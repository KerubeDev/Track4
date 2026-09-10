"""Offline evaluation harness for the Sentinel-DNS detection chain.

Ticket S1-T6 (issue #10). Scores a recorded emulator run against ground
truth that is carried **only** in the emulator output.

Design notes
------------
- The evaluation unit is a single query.
- ``ground_truth`` is read from the recorded run (emulator output /
  recorded metadata). The agent never sees it: the copy of each event that
  reaches the deterministic filter and QVAC is stripped of ``ground_truth``
  (``agent_view``), while the scoring side keeps a separate label copy.
- A query that is not escalated by the deterministic filter is predicted
  ``benign`` (no QVAC call, no alert). An escalated query is predicted by
  the QVAC verdict (one of ``CLASS_ORDER``).
- Precision/recall/F1 are computed one-vs-rest for every class and
  macro-averaged over the four attack classes (plus an all-class macro).
- The filter elimination rate is the share of queries that never reached
  QVAC, reported overall and restricted to ground-truth-benign queries
  (>= 80 % of benign traffic should never cost a QVAC call).
- Filter-path latency is the wall-clock time of the deterministic filter
  call per query; QVAC-path latency is filter time plus the QVAC inference
  latency (from the verdict) for the escalated subset. p50/p95 use the
  nearest-rank method.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

from app.agent.filter import DeterministicFilter, FilterConfig
from app.agent.qvac_adapter import QVACVerdict
from app.eval.qvac import MockQVAC

CLASS_ORDER = ("benign", "dga", "tunnel", "beaconing", "typosquat", "unverified")
ATTACK_CLASSES = ("dga", "tunnel", "beaconing", "typosquat")
REPORT_SCHEMA = "sentinel-dns.eval.report.v1"

Clock = Callable[[], float]


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def percentile(values: Sequence[float], pct: float) -> float:
    """Nearest-rank percentile of a sample; ``0.0`` when the sample is empty."""
    sample = sorted(values)
    if not sample:
        return 0.0
    rank = min(len(sample), max(1, int(math.ceil(pct / 100.0 * len(sample)))))
    return float(sample[rank - 1])


def ground_truth_label(event: dict[str, Any]) -> str:
    """The true class of an emulator event: its ``ground_truth.attack``, or
    ``benign`` when the field is absent/null. Unknown labels collapse to
    ``unverified`` so they are never silently scored as benign."""
    gt = event.get("ground_truth")
    label = gt.get("attack", "benign") if isinstance(gt, dict) else "benign"
    return label if label in CLASS_ORDER else "unverified"


def agent_view(event: dict[str, Any]) -> dict[str, Any]:
    """The agent's copy of an event — ground truth removed, and ``ts``
    normalized to the ``timestamp`` field the deterministic filter reads."""
    view = dict(event)
    view.pop("ground_truth", None)
    if "timestamp" not in view and "ts" in view:
        view["timestamp"] = view["ts"]
    return view


def _ts_key(event: dict[str, Any]) -> str:
    return str(event.get("ts", event.get("timestamp", "")))


# ---------------------------------------------------------------------------
# Per-query records and result structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvalRecord:
    ts: str
    client_ip: str
    qname: str
    qtype: str
    rcode: str
    zone_id: str
    pop_id: str
    true_label: str
    escalated: bool
    verdict: str
    predicted: str
    filter_latency_ms: float
    qvac_latency_ms: float | None = None


@dataclass(frozen=True)
class ClassMetrics:
    label: str
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float
    support: int


@dataclass(frozen=True)
class EliminationStats:
    total: int
    escalated: int
    eliminated: int
    overall_rate: float
    benign_total: int
    benign_escalated: int
    benign_elimination_rate: float


@dataclass(frozen=True)
class LatencyStats:
    n: int
    p50_ms: float
    p95_ms: float
    max_ms: float


@dataclass(frozen=True)
class MacroStats:
    classes: tuple[str, ...]
    precision: float
    recall: float
    f1: float


@dataclass(frozen=True)
class GroupSummary:
    label: str
    total: int
    classes: dict[str, ClassMetrics]
    macro: MacroStats
    elimination: EliminationStats


@dataclass(frozen=True)
class EvaluationReport:
    total_queries: int
    labels: tuple[str, ...]
    matrix: tuple[tuple[int, ...], ...]
    classes: dict[str, ClassMetrics]
    macro: MacroStats
    macro_all: MacroStats
    accuracy: float
    elimination: EliminationStats
    latency: dict[str, LatencyStats]
    by_zone: dict[str, GroupSummary]
    by_pop: dict[str, GroupSummary]
    records: tuple[EvalRecord, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": REPORT_SCHEMA,
            "total_queries": self.total_queries,
            "labels": list(self.labels),
            "confusion_matrix": [list(row) for row in self.matrix],
            "classes": {label: _metrics_dict(self.classes[label]) for label in self.labels},
            "macro": _macro_dict(self.macro),
            "macro_all_classes": _macro_dict(self.macro_all),
            "accuracy": self.accuracy,
            "elimination": _elimination_dict(self.elimination),
            "latency_ms": {name: _latency_dict(stats) for name, stats in self.latency.items()},
            "by_zone": {k: _group_dict(v) for k, v in sorted(self.by_zone.items())},
            "by_pop": {k: _group_dict(v) for k, v in sorted(self.by_pop.items())},
            "summary": self.summary_text(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def summary_text(self) -> str:
        lines = [
            f"Sentinel-DNS evaluation report ({REPORT_SCHEMA})",
            f"Queries: {self.total_queries} | QVAC calls: {self.elimination.escalated} "
            f"| eliminated before QVAC: {self.elimination.eliminated}",
            f"Benign never reaching QVAC: {self.elimination.benign_elimination_rate:.1%} "
            f"({self.elimination.benign_total - self.elimination.benign_escalated} of "
            f"{self.elimination.benign_total} benign queries)",
            f"Accuracy: {self.accuracy:.1%}",
            f"Macro over {len(self.macro.classes)} attack classes — "
            f"precision {self.macro.precision:.1%}, recall {self.macro.recall:.1%}, "
            f"F1 {self.macro.f1:.1%}",
            "Per class:",
        ]
        for label in self.labels:
            m = self.classes[label]
            lines.append(
                f"  {label:<10} p={m.precision:.1%} r={m.recall:.1%} f1={m.f1:.1%} "
                f"(tp={m.tp} fp={m.fp} fn={m.fn} tn={m.tn})"
            )
        lat = self.latency
        lines.append(
            f"Latency (ms): filter_path p50={lat['filter_path'].p50_ms:.1f} "
            f"p95={lat['filter_path'].p95_ms:.1f} | qvac_path p50={lat['qvac_path'].p50_ms:.1f} "
            f"p95={lat['qvac_path'].p95_ms:.1f}"
        )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Metric computation
# ---------------------------------------------------------------------------


def _metrics_dict(m: ClassMetrics) -> dict[str, Any]:
    return {
        "tp": m.tp, "fp": m.fp, "fn": m.fn, "tn": m.tn,
        "precision": m.precision, "recall": m.recall, "f1": m.f1, "support": m.support,
    }


def _macro_dict(m: MacroStats) -> dict[str, Any]:
    return {"classes": list(m.classes), "precision": m.precision, "recall": m.recall, "f1": m.f1}


def _elimination_dict(e: EliminationStats) -> dict[str, Any]:
    return {
        "total": e.total, "escalated": e.escalated, "eliminated": e.eliminated,
        "overall_rate": e.overall_rate, "benign_total": e.benign_total,
        "benign_escalated": e.benign_escalated, "benign_elimination_rate": e.benign_elimination_rate,
    }


def _latency_dict(s: LatencyStats) -> dict[str, Any]:
    return {"n": s.n, "p50_ms": s.p50_ms, "p95_ms": s.p95_ms, "max_ms": s.max_ms}


def _group_dict(g: GroupSummary) -> dict[str, Any]:
    return {
        "total": g.total,
        "classes": {label: _metrics_dict(g.classes[label]) for label in g.classes},
        "macro": _macro_dict(g.macro),
        "elimination": _elimination_dict(g.elimination),
    }


def _confusion_matrix(records: Sequence[EvalRecord], labels: Sequence[str]) -> tuple[tuple[int, ...], ...]:
    index = {label: i for i, label in enumerate(labels)}
    n = len(labels)
    matrix = [[0] * n for _ in range(n)]
    for record in records:
        row = index.get(record.true_label, index["unverified"])
        col = index.get(record.predicted, index["unverified"])
        matrix[row][col] += 1
    return tuple(tuple(row) for row in matrix)


def _class_metrics(matrix: tuple[tuple[int, ...], ...], index: int) -> ClassMetrics:
    n = len(matrix)
    tp = matrix[index][index]
    fp = sum(matrix[i][index] for i in range(n) if i != index)
    fn = sum(matrix[index][j] for j in range(n) if j != index)
    tn = sum(matrix[i][j] for i in range(n) for j in range(n) if i != index and j != index)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    support = tp + fn
    # the label is filled by the caller
    return ClassMetrics("", tp, fp, fn, tn, precision, recall, f1, support)


def _macro(metrics: Sequence[ClassMetrics]) -> MacroStats:
    if not metrics:
        return MacroStats((), 0.0, 0.0, 0.0)
    labels = tuple(m.label for m in metrics)
    return MacroStats(
        labels,
        sum(m.precision for m in metrics) / len(metrics),
        sum(m.recall for m in metrics) / len(metrics),
        sum(m.f1 for m in metrics) / len(metrics),
    )


def _elimination(records: Sequence[EvalRecord]) -> EliminationStats:
    total = len(records)
    escalated = sum(1 for r in records if r.escalated)
    benign = [r for r in records if r.true_label == "benign"]
    benign_total = len(benign)
    benign_escalated = sum(1 for r in benign if r.escalated)
    return EliminationStats(
        total=total,
        escalated=escalated,
        eliminated=total - escalated,
        overall_rate=(total - escalated) / total if total else 0.0,
        benign_total=benign_total,
        benign_escalated=benign_escalated,
        benign_elimination_rate=(benign_total - benign_escalated) / benign_total if benign_total else 0.0,
    )


def _latency_stats(values: Sequence[float]) -> LatencyStats:
    return LatencyStats(
        n=len(values),
        p50_ms=round(percentile(values, 50.0), 3),
        p95_ms=round(percentile(values, 95.0), 3),
        max_ms=round(max(values), 3) if values else 0.0,
    )


def _latency_by_path(records: Sequence[EvalRecord]) -> dict[str, LatencyStats]:
    filter_times = [r.filter_latency_ms for r in records]
    qvac_times = [r.filter_latency_ms + (r.qvac_latency_ms or 0.0) for r in records if r.escalated]
    return {"filter_path": _latency_stats(filter_times), "qvac_path": _latency_stats(qvac_times)}


def _group_summary(label: str, records: Sequence[EvalRecord], labels: Sequence[str]) -> GroupSummary:
    matrix = _confusion_matrix(records, labels)
    classes = {}
    for i, name in enumerate(labels):
        class_name = name
        m = _class_metrics(matrix, i)
        classes[class_name] = ClassMetrics(class_name, m.tp, m.fp, m.fn, m.tn, m.precision, m.recall, m.f1, m.support)
    attack_metrics = [classes[name] for name in labels if name in ATTACK_CLASSES]
    return GroupSummary(
        label=label,
        total=len(records),
        classes=classes,
        macro=_macro(attack_metrics),
        elimination=_elimination(records),
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def evaluate(
    events: Iterable[dict[str, Any]],
    *,
    filter: DeterministicFilter | None = None,
    qvac: Any = None,
    clock: Clock | None = None,
    labels: Sequence[str] = CLASS_ORDER,
) -> EvaluationReport:
    """Score a recorded run (iterable of emulator event dicts) end to end.

    ``filter`` is a :class:`DeterministicFilter`, ``qvac`` anything exposing
    ``infer(qname, signal_evidence, context) -> verdict`` where the verdict
    has ``verdict`` and ``latency_ms`` (a ``QVACVerdict`` or a dict). ``clock``
    is injected for deterministic latency measurement in tests.
    """
    filter_ = filter or DeterministicFilter(FilterConfig.from_env())
    qvac_ = qvac or MockQVAC()
    clock_ = clock or time.monotonic

    records: list[EvalRecord] = []
    events = sorted(events, key=_ts_key)
    true_labels = [ground_truth_label(event) for event in events]

    for event, true_label in zip(events, true_labels):
        view = agent_view(event)
        start = clock_()
        evidence = filter_.process(view)
        filter_ms = (clock_() - start) * 1000.0

        if evidence is None:
            records.append(EvalRecord(
                ts=str(event.get("ts", "")), client_ip=str(event.get("client_ip", "")),
                qname=str(event.get("qname", "")), qtype=str(event.get("qtype", "")),
                rcode=str(event.get("rcode", "")), zone_id=str(event.get("zone_id", "")),
                pop_id=str(event.get("pop_id", "")), true_label=true_label,
                escalated=False, verdict="benign", predicted="benign",
                filter_latency_ms=filter_ms,
            ))
            continue

        result = qvac_.infer(evidence["qname"], evidence["signals"], {"client_ip": evidence["client_ip"]})
        verdict = _verdict_name(result)
        qvac_ms = _verdict_latency(result)
        predicted = verdict if verdict in labels else "unverified"
        records.append(EvalRecord(
            ts=str(event.get("ts", "")), client_ip=str(event.get("client_ip", "")),
            qname=str(event.get("qname", "")), qtype=str(event.get("qtype", "")),
            rcode=str(event.get("rcode", "")), zone_id=str(event.get("zone_id", "")),
            pop_id=str(event.get("pop_id", "")), true_label=true_label,
            escalated=True, verdict=verdict, predicted=predicted,
            filter_latency_ms=filter_ms, qvac_latency_ms=qvac_ms,
        ))

    labels = tuple(labels)
    matrix = _confusion_matrix(records, labels)
    classes: dict[str, ClassMetrics] = {}
    for i, name in enumerate(labels):
        m = _class_metrics(matrix, i)
        classes[name] = ClassMetrics(name, m.tp, m.fp, m.fn, m.tn, m.precision, m.recall, m.f1, m.support)

    attack_metrics = [classes[name] for name in labels if name in ATTACK_CLASSES]
    all_metrics = [classes[name] for name in labels]
    diagonal = sum(matrix[i][i] for i in range(len(labels)))
    accuracy = diagonal / len(records) if records else 0.0

    by_zone: dict[str, list[EvalRecord]] = {}
    by_pop: dict[str, list[EvalRecord]] = {}
    for record in records:
        by_zone.setdefault(record.zone_id, []).append(record)
        by_pop.setdefault(record.pop_id, []).append(record)

    return EvaluationReport(
        total_queries=len(records),
        labels=labels,
        matrix=matrix,
        classes=classes,
        macro=_macro(attack_metrics),
        macro_all=_macro(all_metrics),
        accuracy=accuracy,
        elimination=_elimination(records),
        latency=_latency_by_path(records),
        by_zone={key: _group_summary(key, group, labels) for key, group in by_zone.items()},
        by_pop={key: _group_summary(key, group, labels) for key, group in by_pop.items()},
        records=tuple(records),
    )


def _verdict_name(result: Any) -> str:
    if isinstance(result, QVACVerdict):
        return result.verdict
    if isinstance(result, dict):
        return str(result.get("verdict", "unverified"))
    return str(getattr(result, "verdict", "unverified"))


def _verdict_latency(result: Any) -> float:
    if isinstance(result, QVACVerdict):
        return float(result.latency_ms)
    if isinstance(result, dict):
        return float(result.get("latency_ms", result.get("latency", 0.0)) or 0.0)
    return float(getattr(result, "latency_ms", 0.0) or 0.0)


def load_run(path: str) -> list[dict[str, Any]]:
    """Load a recorded run (JSON-lines of TelemetryEvent dicts)."""
    events: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events