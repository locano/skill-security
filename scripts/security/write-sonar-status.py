#!/usr/bin/env python3
"""Escribe security-reports/sonar-status.json (incluye login).

Uso:
    python3 write-sonar-status.py <output_dir> <status> <reason> [url] [project_key]
"""

import json
import sys
from datetime import date
from pathlib import Path

out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("security-reports")
status = sys.argv[2] if len(sys.argv) > 2 else "unknown"
reason = sys.argv[3] if len(sys.argv) > 3 else ""
url = sys.argv[4] if len(sys.argv) > 4 else ""
project_key = sys.argv[5] if len(sys.argv) > 5 else ""

out_dir.mkdir(parents=True, exist_ok=True)
admin_file = out_dir / ".sonar-admin"
if admin_file.is_file() and admin_file.stat().st_size:
    password = admin_file.read_text(encoding="utf-8").strip()
else:
    password = f"Security_Scan_{date.today().year}!"

dashboard = f"{url}/dashboard?id={project_key}" if url and project_key else url
payload = {
    "url": url,
    "dashboard_url": dashboard,
    "status": status,
    "reason": reason,
    "project_key": project_key,
    "login": "admin",
    "password": password,
    "password_file": str(admin_file),
}
path = out_dir / "sonar-status.json"
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print(
    f"[sonar-status] {status} {dashboard or url or '(sin URL)'}\n"
    f"  Usuario: admin\n"
    f"  Password: {password}\n"
    f"  Archivo: {admin_file}",
    file=sys.stderr,
)
