#!/usr/bin/env python3
"""
Tests for Docker Compose configuration and provision idempotency
Issue #15 (S2-T5) — Sentinel-DNS Track4

Validates:
  V1 — Compose YAML is valid and contains all required services.
  V2 — All required services have healthchecks (health gate).
  V3 — .env defaults match acceptance criteria (REPLAY_RATE=x20, DEMO_SEED=42).
  V4 — Default stack is always-on (no profile gate for core services).
  V5 — Provision script is idempotent (schema uses IF NOT EXISTS).
  V6 — Kafka is configured in KRaft mode (no Zookeeper dependency).
  V7 — Service dependency graph is correct (depends_on chains).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, Set

import pytest
import yaml

# ---------------------------------------------------------------------------
# Ensure the project root is on the path
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def compose_config() -> Dict[str, Any]:
    """Load docker-compose.yml as a parsed dict."""
    compose_path = PROJECT_ROOT / "deploy" / "docker-compose.yml"
    with open(compose_path, "r") as f:
        return yaml.safe_load(f)


@pytest.fixture
def env_config() -> Dict[str, str]:
    """Load .env file as a dict."""
    env_path = PROJECT_ROOT / ".env"
    config: Dict[str, str] = {}
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                config[key.strip()] = value.strip()
    return config


@pytest.fixture
def schema_sql() -> str:
    """Load ClickHouse schema.sql."""
    schema_path = PROJECT_ROOT / "deploy" / "clickhouse" / "schema.sql"
    return schema_path.read_text()


@pytest.fixture
def provision_script() -> str:
    """Load provision-full.sh."""
    script_path = PROJECT_ROOT / "deploy" / "clickhouse" / "provision-full.sh"
    return script_path.read_text()


@pytest.fixture
def provision_sh() -> str:
    """Load original provision.sh."""
    script_path = PROJECT_ROOT / "deploy" / "clickhouse" / "provision.sh"
    return script_path.read_text()


# ===========================================================================
# V1: Compose YAML structure
# ===========================================================================

class TestComposeStructure:
    """V1: Compose YAML is valid and contains all required services."""

    REQUIRED_SERVICES = {
        "kafka",
        "kafka-init",
        "kafka-probe",
        "clickhouse",
        "grafana",
        "wazuh",
        "qvac",
        "emulator",
        "agent",
        "provision",
        "seed-fixtures",
    }

    def test_compose_loads(self, compose_config: Dict[str, Any]) -> None:
        """docker-compose.yml parses as valid YAML."""
        assert "services" in compose_config, "Missing 'services' key"

    def test_all_services_present(self, compose_config: Dict[str, Any]) -> None:
        """All required services are defined."""
        services = set(compose_config["services"].keys())
        missing = self.REQUIRED_SERVICES - services
        assert not missing, f"Missing services: {missing}"

    def test_volumes_defined(self, compose_config: Dict[str, Any]) -> None:
        """Named volumes are declared."""
        assert "volumes" in compose_config, "Missing 'volumes' key"
        volumes = compose_config["volumes"]
        assert "clickhouse-data" in volumes
        assert "grafana-data" in volumes
        assert "wazuh-data" in volumes
        assert "kafka-data" in volumes


# ===========================================================================
# V2: Healthchecks on all required services
# ===========================================================================

class TestHealthchecks:
    """V2: All core services have healthchecks for the health gate."""

    SERVICES_WITHOUT_HEALTHCHECK = {"seed-fixtures", "kafka-init", "kafka-probe"}

    def test_core_services_have_healthchecks(self, compose_config: Dict[str, Any]) -> None:
        """Core infrastructure services must have healthchecks."""
        services = compose_config["services"]
        core_services = {
            name for name in services if name not in self.SERVICES_WITHOUT_HEALTHCHECK
        }

        for name in core_services:
            svc = services[name]
            assert "healthcheck" in svc, (
                f"Service '{name}' missing healthcheck"
            )
            hc = svc["healthcheck"]
            assert "test" in hc, f"Service '{name}' healthcheck missing 'test'"
            assert "interval" in hc, f"Service '{name}' healthcheck missing 'interval'"
            assert "timeout" in hc, f"Service '{name}' healthcheck missing 'timeout'"
            assert "retries" in hc, f"Service '{name}' healthcheck missing 'retries'"

    def test_kafka_healthcheck_uses_kafka_tools(self, compose_config: Dict[str, Any]) -> None:
        """Kafka healthcheck should use kafka-topics.sh or similar."""
        hc_test = compose_config["services"]["kafka"]["healthcheck"]["test"]
        test_str = " ".join(hc_test) if isinstance(hc_test, list) else str(hc_test)
        assert "kafka" in test_str.lower(), (
            f"Kafka healthcheck should use kafka tooling, got: {test_str}"
        )

    def test_clickhouse_healthcheck_pings(self, compose_config: Dict[str, Any]) -> None:
        """ClickHouse healthcheck should ping the HTTP interface."""
        hc_test = compose_config["services"]["clickhouse"]["healthcheck"]["test"]
        test_str = " ".join(hc_test) if isinstance(hc_test, list) else str(hc_test)
        assert "ping" in test_str.lower() or "8123" in test_str, (
            f"ClickHouse healthcheck should ping, got: {test_str}"
        )

    def test_grafana_healthcheck_uses_api(self, compose_config: Dict[str, Any]) -> None:
        """Grafana healthcheck should use /api/health."""
        hc_test = compose_config["services"]["grafana"]["healthcheck"]["test"]
        test_str = " ".join(hc_test) if isinstance(hc_test, list) else str(hc_test)
        assert "health" in test_str.lower(), (
            f"Grafana healthcheck should use /api/health, got: {test_str}"
        )


# ===========================================================================
# V3: .env defaults match acceptance criteria
# ===========================================================================

class TestEnvDefaults:
    """V3: .env defaults match the acceptance criteria."""

    def test_replay_rate_default(self, env_config: Dict[str, str]) -> None:
        """REPLAY_RATE defaults to 20 (x20)."""
        assert "REPLAY_RATE" in env_config
        assert env_config["REPLAY_RATE"] == "20", (
            f"REPLAY_RATE should be '20', got '{env_config['REPLAY_RATE']}'"
        )

    def test_demo_seed_default(self, env_config: Dict[str, str]) -> None:
        """DEMO_SEED defaults to a fixed value for reproducibility."""
        assert "DEMO_SEED" in env_config
        seed = int(env_config["DEMO_SEED"])
        assert seed == 42, f"DEMO_SEED should be 42, got {seed}"

    def test_clickhouse_db_default(self, env_config: Dict[str, str]) -> None:
        """CLICKHOUSE_DB defaults to sentinel_dns."""
        assert env_config.get("CLICKHOUSE_DB") == "sentinel_dns"

    def test_grafana_credentials(self, env_config: Dict[str, str]) -> None:
        """Grafana admin credentials are set."""
        assert "GF_SECURITY_ADMIN_USER" in env_config
        assert "GF_SECURITY_ADMIN_PASSWORD" in env_config


# ===========================================================================
# V4: Demo profile configuration
# ===========================================================================

class TestDemoProfile:
    """V4: Services start with the default stack; no explicit profile needed."""

    def test_emulator_has_no_profile(self, compose_config: Dict[str, Any]) -> None:
        """Emulator runs on a plain `up` (no profile gate)."""
        emulator = compose_config["services"]["emulator"]
        profiles = emulator.get("profiles", [])
        assert not profiles, (
            f"Emulator should have no profile (always on), got: {profiles}"
        )

    def test_agent_has_no_profile(self, compose_config: Dict[str, Any]) -> None:
        """Agent runs on a plain `up` (no profile gate)."""
        agent = compose_config["services"]["agent"]
        profiles = agent.get("profiles", [])
        assert not profiles, (
            f"Agent should have no profile (always on), got: {profiles}"
        )

    def test_seed_fixtures_has_dev_profile(self, compose_config: Dict[str, Any]) -> None:
        """Seed fixtures must be in the dev profile."""
        seed = compose_config["services"]["seed-fixtures"]
        profiles = seed.get("profiles", [])
        assert "dev" in profiles, (
            f"Seed fixtures missing 'dev' profile, got: {profiles}"
        )

    def test_core_services_have_no_profile(self, compose_config: Dict[str, Any]) -> None:
        """Services that must always start should have no profile."""
        core_services = [
            "kafka", "clickhouse", "grafana", "wazuh", "qvac",
            "provision", "emulator", "agent",
        ]
        for name in core_services:
            svc = compose_config["services"][name]
            profiles = svc.get("profiles", [])
            assert not profiles, (
                f"Service '{name}' should have no profile, got: {profiles}"
            )


# ===========================================================================
# V5: Provision script idempotency
# ===========================================================================

class TestProvisionIdempotency:
    """V5: Provision operations are idempotent."""

    def test_schema_uses_if_not_exists(self, schema_sql: str) -> None:
        """All CREATE TABLE statements use IF NOT EXISTS."""
        lines = [
            line.strip()
            for line in schema_sql.split("\n")
            if line.strip().upper().startswith("CREATE TABLE")
        ]
        for line in lines:
            assert "IF NOT EXISTS" in line.upper(), (
                f"CREATE TABLE missing IF NOT EXISTS: {line}"
            )

    def test_schema_uses_if_not_exists_database(self, schema_sql: str) -> None:
        """CREATE DATABASE uses IF NOT EXISTS."""
        db_lines = [
            line.strip()
            for line in schema_sql.split("\n")
            if line.strip().upper().startswith("CREATE DATABASE")
        ]
        for line in db_lines:
            assert "IF NOT EXISTS" in line.upper(), (
                f"CREATE DATABASE missing IF NOT EXISTS: {line}"
            )

    def test_provision_script_exists(self) -> None:
        """provision-full.sh exists and is executable."""
        script_path = PROJECT_ROOT / "deploy" / "clickhouse" / "provision-full.sh"
        assert script_path.exists(), f"provision-full.sh not found at {script_path}"
        assert os.access(script_path, os.X_OK), "provision-full.sh is not executable"

    def test_provision_checks_all_components(self, provision_script: str) -> None:
        """provision-full.sh checks ClickHouse, Grafana, and Wazuh."""
        assert "ClickHouse" in provision_script
        assert "Grafana" in provision_script
        assert "Wazuh" in provision_script

    def test_provision_mount_points_to_clickhouse_dir(
        self, compose_config: Dict[str, Any]
    ) -> None:
        """Provision must mount ./clickhouse:/scripts so the script resolves."""
        volumes = compose_config["services"]["provision"]["volumes"]
        assert any(
            vol.startswith("./clickhouse:") or vol.startswith("./clickhouse /")
            for vol in volumes
        ), f"Provision should mount ./clickhouse:/scripts, got: {volumes}"

    def test_provision_mount_supported_by_script(self, provision_script: str) -> None:
        """Provision script schema path must resolve under the clickhouse mount."""
        assert "${SCRIPT_DIR}/schema.sql" in provision_script, (
            "SCHEMA_FILE must resolve next to the script (${SCRIPT_DIR}/schema.sql)"
        )

    def test_provision_has_idempotent_message(self, provision_script: str) -> None:
        """provision-full.sh mentions idempotency."""
        assert "idempotent" in provision_script.lower() or "multiple times" in provision_script.lower()


# ===========================================================================
# V6: Kafka KRaft mode
# ===========================================================================

class TestKafkaKRaft:
    """V6: Kafka is configured in KRaft mode (no Zookeeper)."""

    def test_kafka_has_kraft_config(self, compose_config: Dict[str, Any]) -> None:
        """Kafka service should have KRaft-specific environment variables."""
        kafka_env = compose_config["services"]["kafka"]["environment"]
        # KRaft requires process_roles and controller settings
        has_process_roles = any(
            "PROCESS_ROLES" in k.upper() for k in kafka_env
        )
        has_controller = any(
            "CONTROLLER" in k.upper() for k in kafka_env
        )
        assert has_process_roles, "Kafka missing KRaft PROCESS_ROLES config"
        assert has_controller, "Kafka missing KRaft CONTROLLER config"

    def test_no_zookeeper_service(self, compose_config: Dict[str, Any]) -> None:
        """No Zookeeper service should exist."""
        services = set(compose_config["services"].keys())
        zookeeper_names = {s for s in services if "zoo" in s.lower()}
        assert not zookeeper_names, f"Unexpected Zookeeper services: {zookeeper_names}"

    def test_kafka_uses_bitnami_image(self, compose_config: Dict[str, Any]) -> None:
        """Kafka uses the Bitnami KRaft-compatible image."""
        image = compose_config["services"]["kafka"]["image"]
        assert "bitnami" in image.lower() or "kafka" in image.lower(), (
            f"Kafka image should be KRaft-compatible, got: {image}"
        )


# ===========================================================================
# V7: Service dependency graph
# ===========================================================================

class TestServiceDependencies:
    """V7: Service dependency chains are correct."""

    def test_grafana_depends_on_clickhouse(self, compose_config: Dict[str, Any]) -> None:
        """Grafana depends on ClickHouse being healthy."""
        grafana = compose_config["services"]["grafana"]
        deps = grafana.get("depends_on", {})
        assert "clickhouse" in deps, "Grafana should depend on clickhouse"
        assert deps["clickhouse"]["condition"] == "service_healthy"

    def test_provision_depends_on_clickhouse(self, compose_config: Dict[str, Any]) -> None:
        """Provision depends on ClickHouse being healthy."""
        provision = compose_config["services"]["provision"]
        deps = provision.get("depends_on", {})
        assert "clickhouse" in deps, "Provision should depend on clickhouse"
        assert deps["clickhouse"]["condition"] == "service_healthy"

    def test_emulator_depends_on_kafka(self, compose_config: Dict[str, Any]) -> None:
        """Emulator depends on Kafka being healthy."""
        emulator = compose_config["services"]["emulator"]
        deps = emulator.get("depends_on", {})
        assert "kafka" in deps, "Emulator should depend on kafka"

    def test_agent_depends_on_kafka_and_qvac(self, compose_config: Dict[str, Any]) -> None:
        """Agent depends on Kafka and QVAC being healthy."""
        agent = compose_config["services"]["agent"]
        deps = agent.get("depends_on", {})
        assert "kafka" in deps, "Agent should depend on kafka"
        assert "qvac" in deps, "Agent should depend on qvac"
        assert "clickhouse" in deps, "Agent should depend on clickhouse"


# ===========================================================================
# V8: Kafka topic provisioning (issue #7)
# ===========================================================================

class TestKafkaTopicProvisioning:
    """V8: dns.telemetry.v1 is created explicitly with the accepted layout."""

    def test_kafka_init_mounts_topic_script(self, compose_config):
        """kafka-init mounts ./kafka:/scripts so init-topics.sh resolves."""
        volumes = compose_config["services"]["kafka-init"]["volumes"]
        assert any(
            vol.startswith("./kafka:") or vol.startswith("./kafka /")
            for vol in volumes
        ), f"kafka-init should mount ./kafka:/scripts, got: {volumes}"

    def test_kafka_init_runs_topic_script(self, compose_config):
        entrypoint = compose_config["services"]["kafka-init"]["entrypoint"]
        assert any(
            "init-topics.sh" in str(part) for part in entrypoint
        ), f"kafka-init should run init-topics.sh, got: {entrypoint}"

    def test_kafka_init_depends_on_kafka_healthy(self, compose_config):
        deps = compose_config["services"]["kafka-init"].get("depends_on", {})
        assert "kafka" in deps, "kafka-init should depend on kafka"
        assert deps["kafka"]["condition"] == "service_healthy"

    def test_kafka_init_has_explicit_partitions_and_retention(self, compose_config):
        env = compose_config["services"]["kafka-init"]["environment"]
        assert int(env["KAFKA_TOPIC_PARTITIONS"]) >= 3
        retention_default = env["KAFKA_TOPIC_RETENTION_MS"]
        assert "3600000" in retention_default or int(env["KAFKA_TOPIC_RETENTION_MS"]) <= 3_600_000

    @pytest.fixture
    def init_script(self) -> str:
        script_path = PROJECT_ROOT / "deploy" / "kafka" / "init-topics.sh"
        return script_path.read_text()

    def test_init_script_creates_topic_explicitly(self, init_script: str):
        assert "--create" in init_script
        assert "--if-not-exists" in init_script
        assert "--replication-factor 1" in init_script

    def test_init_script_sets_partitions_and_retention(self, init_script: str):
        assert "--partitions" in init_script
        assert "retention.ms" in init_script
        assert "cleanup.policy=delete" in init_script

    def test_init_script_is_executable(self):
        script_path = PROJECT_ROOT / "deploy" / "kafka" / "init-topics.sh"
        assert script_path.exists()
        assert os.access(script_path, os.X_OK)

    def test_kafka_probe_runs_health_module(self, compose_config):
        command = compose_config["services"]["kafka-probe"]["command"]
        cmd_str = " ".join(command)
        assert "app.common.kafka_health" in cmd_str
        assert "dns.telemetry.v1" in cmd_str

    def test_kafka_probe_depends_on_kafka_init(self, compose_config):
        deps = compose_config["services"]["kafka-probe"].get("depends_on", {})
        assert "kafka-init" in deps, "kafka-probe should depend on kafka-init"
        assert deps["kafka-init"]["condition"] == "service_completed_successfully"


# ===========================================================================
# V9: Compose build contexts
# ===========================================================================

class TestBuildContexts:
    """V8: Python services have correct build contexts."""

    PYTHON_SERVICES = ["qvac", "emulator", "agent"]

    def test_build_context_is_project_root(self, compose_config: Dict[str, Any]) -> None:
        """Python services build from the project root."""
        for name in self.PYTHON_SERVICES:
            svc = compose_config["services"][name]
            build = svc.get("build", {})
            context = build.get("context", "")
            assert context == "..", (
                f"Service '{name}' build context should be '..', got: '{context}'"
            )

    def test_build_dockerfile(self, compose_config: Dict[str, Any]) -> None:
        """Python services use the shared Dockerfile."""
        for name in self.PYTHON_SERVICES:
            svc = compose_config["services"][name]
            build = svc.get("build", {})
            dockerfile = build.get("dockerfile", "")
            assert "Dockerfile" in dockerfile, (
                f"Service '{name}' Dockerfile should reference Dockerfile, got: '{dockerfile}'"
            )
