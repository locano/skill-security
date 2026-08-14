#!/usr/bin/env python3
"""Mapea hallazgos de ZAP / Bandit / npm a OWASP Top 10 2021 y API Top 10 2023.

Uso:
    python3 map-owasp.py [output_dir]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

OUT_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("security-reports")

WEB = [
    ("A01:2021", "Broken Access Control", {22, 284, 285, 352, 425, 639, 862, 863}),
    ("A02:2021", "Cryptographic Failures", {259, 310, 319, 326, 327, 328, 330, 331, 523, 780}),
    ("A03:2021", "Injection", {77, 78, 79, 88, 89, 90, 91, 94, 95, 98, 643, 917}),
    ("A04:2021", "Insecure Design", {209, 256, 501, 522, 841}),
    ("A05:2021", "Security Misconfiguration", {16, 611, 942, 1004}),
    ("A06:2021", "Vulnerable and Outdated Components", set()),
    ("A07:2021", "Identification and Authentication Failures", {287, 306, 307, 384, 521, 613, 620, 640}),
    ("A08:2021", "Software and Data Integrity Failures", {345, 353, 426, 494, 502, 829, 830}),
    ("A09:2021", "Security Logging and Monitoring Failures", {117, 223, 532, 778}),
    ("A10:2021", "Server-Side Request Forgery", {918}),
]

API = [
    ("API1:2023", "Broken Object Level Authorization", {284, 285, 639}),
    ("API2:2023", "Broken Authentication", {287, 306, 307, 384, 521}),
    ("API3:2023", "Broken Object Property Level Authorization", {213, 215, 359}),
    ("API4:2023", "Unrestricted Resource Consumption", {400, 770, 920}),
    ("API5:2023", "Broken Function Level Authorization", {285, 862, 863}),
    ("API6:2023", "Unrestricted Access to Sensitive Business Flows", set()),
    ("API7:2023", "Server Side Request Forgery", {918}),
    ("API8:2023", "Security Misconfiguration", {16, 209, 611, 942}),
    ("API9:2023", "Improper Inventory Management", set()),
    ("API10:2023", "Unsafe Consumption of APIs", {502, 829}),
]


def load(name):
    p = OUT_DIR / name
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def cwe_int(value):
    if value is None or value == "" or value == "-1":
        return None
    try:
        return int(str(value).replace("CWE-", "").strip())
    except ValueError:
        return None


def zap_findings(*docs):
    out = []
    for doc in docs:
        if not doc:
            continue
        for site in doc.get("site", []):
            for alert in site.get("alerts", []):
                cwe = cwe_int(alert.get("cweid"))
                out.append(
                    {
                        "source": "zap",
                        "name": alert.get("name", ""),
                        "cwe": cwe,
                        "risk": (alert.get("riskdesc") or "").split(" ")[0],
                    }
                )
    return out


def bandit_findings(doc):
    out = []
    if not doc:
        return out
    for r in doc.get("results", []):
        cwe = None
        raw = r.get("issue_cwe")
        if isinstance(raw, dict):
            cwe = cwe_int(raw.get("id"))
        else:
            cwe = cwe_int(raw)
        out.append(
            {
                "source": "bandit",
                "name": r.get("issue_text", r.get("test_id", "")),
                "cwe": cwe,
                "risk": r.get("issue_severity", ""),
            }
        )
    return out


def classify(items, catalog, extra_hits=None):
    extra_hits = extra_hits or {}
    rows = []
    for oid, name, cwes in catalog:
        matched = [f for f in items if f.get("cwe") in cwes]
        if extra_hits.get(oid):
            matched.extend(extra_hits[oid])
        if matched:
            status = "hit"
        else:
            status = "clear"
        rows.append(
            {
                "id": oid,
                "name": name,
                "status": status,
                "findings": matched[:20],
            }
        )
    return rows


def main():
    inventory = load("inventory.json") or {}
    kinds = set(inventory.get("kinds") or [])
    zap = load("zap-dast-report.json")
    zap_web = load("zap-dast-web.json")
    zap_api = load("zap-dast-api.json")
    bandit = load("bandit-report.json")
    npm = load("npm-audit-report.json")
    pip = load("pip-audit-report.json")
    review = load("owasp-review.json")

    findings = zap_findings(zap, zap_web, zap_api) + bandit_findings(bandit)

    extra_web = {}
    extra_api = {}
    if npm and npm.get("vulnerabilities"):
        extra_web["A06:2021"] = [
            {"source": "npm-audit", "name": f"{len(npm['vulnerabilities'])} vulnerabilidades npm", "cwe": None}
        ]
        extra_api["API10:2023"] = extra_web["A06:2021"]
    if pip:
        deps = pip.get("dependencies", pip if isinstance(pip, list) else [])
        n = 0
        for dep in deps:
            n += len(dep.get("vulns", []) if isinstance(dep, dict) else [])
        if n:
            extra_web.setdefault("A06:2021", []).append(
                {"source": "pip-audit", "name": f"{n} vulnerabilidades pip", "cwe": None}
            )

    web_rows = classify(findings, WEB, extra_web)
    api_rows = classify(findings, API, extra_api)

    only_serverless = kinds == {"serverless"}
    if only_serverless:
        for row in web_rows:
            if row["status"] == "clear":
                row["status"] = "n/a"
    if kinds == {"web"}:
        for row in api_rows:
            if row["status"] == "clear":
                row["status"] = "n/a"

    if isinstance(review, dict):
        by_id = {i.get("id"): i for i in review.get("items", []) if isinstance(i, dict)}
        for row in web_rows + api_rows:
            rev = by_id.get(row["id"])
            if not rev:
                continue
            row["review"] = {
                "status": rev.get("status", ""),
                "evidence": rev.get("evidence", ""),
            }
            if rev.get("status") == "fail" and row["status"] == "clear":
                row["status"] = "hit"

    summary = {
        "web": web_rows,
        "api": api_rows,
        "kinds": list(kinds),
        "notes": [
            "hit = hallazgo de herramienta o revisión fail.",
            "clear = sin evidencia automática (no es un pass formal).",
            "n/a = no aplica al tipo de proyecto detectado.",
            "API6/API9 y varios ítems requieren revisión de código (owasp-review.json).",
        ],
    }
    path = OUT_DIR / "owasp-summary.json"
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"[map-owasp] {path}")


if __name__ == "__main__":
    main()
