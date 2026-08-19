#!/usr/bin/env python3
"""Escribe security-reports/sonar-status.json (incluye login).

Uso:
    python3 write-sonar-status.py <output_dir> <status> <reason> [url] [project_key]
"""

import json
import os
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

# El contenedor de SonarQube es uno por máquina, pero .sonar-admin vive dentro
# de cada proyecto. Si este repo todavía no lo tiene, la password real puede
# estar en el store global que escribió otro proyecto.
port = url.rsplit(":", 1)[-1].rstrip("/") if url else "9000"
if not port.isdigit():
    port = "9000"
global_file = (
    Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    / "skill-security" / f"sonar-admin-{port}"
)


def read_pass(path):
    try:
        if path.is_file() and path.stat().st_size:
            return path.read_text(encoding="utf-8").strip()
    except OSError:
        pass
    return ""


password = read_pass(admin_file) or read_pass(global_file) \
    or f"Security_Scan_{date.today().year}!"
password_file = str(admin_file if read_pass(admin_file) else
                    (global_file if read_pass(global_file) else admin_file))

dashboard = f"{url}/dashboard?id={project_key}" if url and project_key else url
payload = {
    "url": url,
    "dashboard_url": dashboard,
    "status": status,
    "reason": reason,
    "project_key": project_key,
    "login": "admin",
    "password": password,
    "password_file": password_file,
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
