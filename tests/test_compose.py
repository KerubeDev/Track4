from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_env(path: Path):
    values = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def test_compose_contract():
    cfg = yaml.safe_load((ROOT / "deploy/docker-compose.yml").read_text())
    services = cfg["services"]
    required = {
        "kafka", "kafka-init", "kafka-probe", "clickhouse", "grafana", "wazuh",
        "qvac", "emulator", "agent", "provision", "seed-fixtures",
    }
    assert required <= set(services)
    assert {"clickhouse-data", "grafana-data", "wazuh-data", "kafka-data"} <= set(cfg["volumes"])


def test_core_health_gates_exist():
    services = yaml.safe_load((ROOT / "deploy/docker-compose.yml").read_text())["services"]
    for name in ("kafka", "clickhouse", "grafana", "wazuh", "qvac", "emulator", "agent", "provision"):
        health = services[name].get("healthcheck")
        assert health and health.get("test") and health.get("interval") and health.get("timeout") and health.get("retries")


def test_host_qvac_is_default_topology():
    services = yaml.safe_load((ROOT / "deploy/docker-compose.yml").read_text())["services"]
    assert services["qvac"].get("profiles") == ["container-qvac"]
    assert "host.docker.internal" in services["agent"]["environment"]["QVAC_URL"]
    assert "host.docker.internal:host-gateway" in services["agent"]["extra_hosts"]
    assert "QVAC_IMAGE" in services["qvac"]["image"]
    assert services["qvac"]["build"]["context"] == "./qvac"


def test_agent_dependency_graph():
    services = yaml.safe_load((ROOT / "deploy/docker-compose.yml").read_text())["services"]
    deps = services["agent"]["depends_on"]
    assert deps["kafka-init"]["condition"] == "service_completed_successfully"
    assert deps["clickhouse"]["condition"] == "service_healthy"
    assert deps["wazuh"]["condition"] == "service_healthy"
    assert "qvac" not in deps  # host runtime is intentionally external to Compose


def test_kafka_is_explicit_kraft_and_topic_is_provisioned():
    services = yaml.safe_load((ROOT / "deploy/docker-compose.yml").read_text())["services"]
    env = services["kafka"]["environment"]
    assert "broker,controller" in env["KAFKA_CFG_PROCESS_ROLES"]
    assert env["KAFKA_CFG_AUTO_CREATE_TOPICS_ENABLE"] == "false"
    init = services["kafka-init"]
    assert init["environment"]["KAFKA_TOPIC"] == "dns.telemetry.v1"
    assert int(init["environment"]["KAFKA_TOPIC_PARTITIONS"]) >= 3
    assert any("init-topics.sh" in str(x) for x in init["entrypoint"])


def test_application_build_contexts_are_repository_root():
    services = yaml.safe_load((ROOT / "deploy/docker-compose.yml").read_text())["services"]
    for name in ("agent", "emulator"):
        assert services[name]["build"]["context"] == ".."
        assert "Dockerfile" in services[name]["build"]["dockerfile"]


def test_safe_environment_template_is_versioned_instead_of_dotenv():
    assert not (ROOT / ".env").exists()
    env = load_env(ROOT / ".env.example")
    assert env["REPLAY_RATE"] == "20"
    assert env["DEMO_SEED"] == "42"
    assert env["CLICKHOUSE_DB"] == "sentinel_dns"
    assert env["QVAC_MODEL"] == "QWEN3_1_7B_INST_Q4"
    assert env["QVAC_URL"].startswith("http://host.docker.internal:")
    assert env["GF_SECURITY_ADMIN_PASSWORD"] == "change-me"


def test_provisioning_is_idempotent_and_checks_operator_surfaces():
    schema = (ROOT / "deploy/clickhouse/schema.sql").read_text()
    script = (ROOT / "deploy/clickhouse/provision-full.sh").read_text()
    for line in schema.splitlines():
        if line.strip().upper().startswith("CREATE TABLE"):
            assert "IF NOT EXISTS" in line.upper()
    assert "ClickHouse" in script
    assert "Grafana" in script
    assert "Wazuh" in script
    assert "idempotent" in script.lower()


def test_no_zookeeper_service():
    services = yaml.safe_load((ROOT / "deploy/docker-compose.yml").read_text())["services"]
    assert not [name for name in services if "zoo" in name.lower()]
