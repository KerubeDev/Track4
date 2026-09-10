# Demo video script — Sentinel-DNS

Target: ≤ 5 minutes, in Spanish (mandated by the rules), no credentials required, reproducible from the
delivered repo.

> The narration lines below stay in Spanish because the rules require the demo video to be in Spanish.
> All other documentation in this repository is in English.

## Structure

| Block | Time | On screen | Narration (Spanish) |
|---|---|---|---|
| 1. Problem | 0:00–0:40 | Ovnicom logo + slide: "Regulated clients, DNS telemetry, zero network egress" | "Nuestros clientes están regulados: su tráfico DNS no puede salir a una IA en la nube. La inteligencia debe vivir donde está el resolver: local." |
| 2. Architecture | 0:40–1:30 | Diagram: emulator → Kafka → Sentinel-DNS (rules + local QVAC) → Wazuh + ClickHouse/Grafana | "Leemos el stream sin tocar producción; un filtro de reglas rápido separa lo sospechoso; QVAC razona localmente el veredicto; las alertas van a Wazuh y el QoE a Grafana." |
| 3. Live demo | 1:30–3:00 | Terminal: event stream being classified + alerts in the Wazuh dashboard | "Ahora arrancamos el pipeline con el guion de ataque inyectado. Vemos dominios DGA y beaconing detectados en tiempo real; la alerta llega a Wazuh como incidente con veredicto y confianza." |
| 4. QoE | 3:00–4:15 | Grafana dashboard: per-site score degrading (red) + culprit breakdown | "Un sitio se degrada: sube la latencia y el NXDOMAIN. El score baja, pasa a 'Malo', y el desglose muestra qué le quita puntos. Comparación entre sitios." |
| 5. Privacy guarantee + close | 4:15–5:00 | `ip link set eth0 down` (or equivalent) and everything keeps running | "Modelo precargado del registry QVAC, red cortada: la inferencia y el dashboard siguen vivos. Local, interpretable, integrado al SIEM. Gracias." |

## Production notes

- Entire demo inference runs **offline**: preload the model before recording and cut the network in block 5.
- In block 4, say explicitly that the dnstap layer (rcode/latency/zones) is **synthesized by the emulator**,
  because the challenge dataset is a BIND9 log without those fields (honest provenance).
- Keep audio in Spanish; ~30 seconds per key idea.
- The published repo (Track4) must reproduce this demo exactly: `docker compose up` + model preload and
  dataset download scripts.
- Reference duration when recording: 4:45–5:00 to leave margin.