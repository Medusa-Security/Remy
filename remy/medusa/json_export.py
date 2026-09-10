"""JSON serialization for a Medusa report (machine-readable / CI artifacts)."""


def report_to_dict(report) -> dict:
    findings = []
    for f in report.findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        findings.append(
            {
                "scanner": f.scanner,
                "severity": sev,
                "cwe": f.cwe,
                "title": f.title,
                "location": f.file,
                "description": f.description,
            }
        )

    root_causes = [
        {
            "failure_id": rc.failure_id,
            "explanation": rc.explanation,
            "chain": [{"kind": s.kind.value, "target": s.target} for s in rc.chain],
        }
        for rc in report.root_causes
    ]

    regression = None
    if report.regression:
        r = report.regression
        regression = {
            "target": r.target,
            "flags": r.flags,
            "latency_regression_pct": r.latency_regression_pct,
            "has_regression": r.has_regression,
        }

    return {
        "run_id": report.run_id,
        "target": report.target,
        "timestamp": report.timestamp.isoformat(),
        "duration_seconds": report.duration_seconds,
        "agents": [r.agent for r in report.agent_results],
        "skipped": [{"agent": a, "reason": b} for a, b in report.skipped],
        "findings": findings,
        "root_causes": root_causes,
        "regression": regression,
    }
