#!/usr/bin/env python3
"""collect-inventory.py — Detecta stack y tipo de proyecto en el cwd.

Uso:
    python3 collect-inventory.py [output_dir]

Escribe inventory.json. No valida “orden de carpetas”; solo describe qué hay.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

OUT_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("security-reports")
ROOT = Path(".").resolve()
SKIP = {".git", "node_modules", ".venv", "venv", "dist", "build", "security-reports", ".scannerwork"}

OPENAPI_NAMES = {
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "swagger.json",
    "swagger.yaml",
    "swagger.yml",
}


def walk_files(max_files: int = 8000):
    n = 0
    for p in ROOT.rglob("*"):
        if n >= max_files:
            break
        if any(part in SKIP for part in p.parts):
            continue
        if p.is_file():
            n += 1
            yield p


def count_suffix(files, *suffixes):
    s = {x.lower() for x in suffixes}
    return sum(1 for f in files if f.suffix.lower() in s)


def main():
    files = list(walk_files())
    names = {f.name.lower() for f in files}
    rel_dirs = {p.parent.relative_to(ROOT).as_posix() for p in files}

    top_dirs = sorted(
        {
            p.relative_to(ROOT).parts[0]
            for p in ROOT.iterdir()
            if p.is_dir() and p.name not in SKIP and not p.name.startswith(".")
        }
    )

    has_pkg = (ROOT / "package.json").is_file()
    pkg_text = ""
    if has_pkg:
        try:
            pkg_text = (ROOT / "package.json").read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            pkg_text = ""

    openapi = []
    for f in files:
        if f.name.lower() in OPENAPI_NAMES:
            openapi.append(str(f.relative_to(ROOT)))

    serverless_markers = []
    for marker in (
        "serverless.yml",
        "serverless.yaml",
        "template.yaml",
        "template.yml",
        "samconfig.toml",
        "sst.config.ts",
        "sst.config.js",
        "cdk.json",
    ):
        if (ROOT / marker).is_file() or marker in names:
            serverless_markers.append(marker)

    py_count = count_suffix(files, ".py")
    ts_count = count_suffix(files, ".ts", ".tsx")
    js_count = count_suffix(files, ".js", ".jsx")
    html_count = count_suffix(files, ".html")

    folder_hints = {
        "api": any(d in top_dirs or d.startswith("api") for d in top_dirs)
        or any(part in {"api", "backend", "server"} for d in rel_dirs for part in d.split("/")),
        "web": any(d in {"web", "frontend", "client", "app", "ui"} for d in top_dirs),
        "functions": any(d in {"functions", "lambdas", "handlers"} for d in top_dirs),
    }

    kinds = []
    if serverless_markers or folder_hints["functions"]:
        kinds.append("serverless")
    if openapi or folder_hints["api"] or "fastapi" in pkg_text or "express" in pkg_text:
        kinds.append("api")
    web_libs = any(x in pkg_text for x in ("react", "vue", "next", "nuxt", "angular", "svelte"))
    if folder_hints["web"] or web_libs or (html_count > 0 and not serverless_markers):
        kinds.append("web")
    if not kinds:
        kinds.append("code")

    stacks = []
    if has_pkg:
        stacks.append("node")
    if py_count:
        stacks.append("python")
    if ts_count:
        stacks.append("typescript")
    if (ROOT / "go.mod").is_file():
        stacks.append("go")
    if (ROOT / "pom.xml").is_file() or (ROOT / "build.gradle").is_file():
        stacks.append("java")

    out = {
        "root": str(ROOT),
        "kinds": kinds,
        "stacks": stacks,
        "top_dirs": top_dirs,
        "counts": {
            "python": py_count,
            "javascript": js_count,
            "typescript": ts_count,
            "html": html_count,
        },
        "package_json": has_pkg,
        "openapi": openapi,
        "serverless_markers": serverless_markers,
        "folder_hints": folder_hints,
        "dast_applies": False,
        "notes": [
            "Inventario descriptivo: no valida el orden de carpetas del proyecto.",
            "SAST cubre toda la carpeta. DAST solo si hay URL HTTP.",
        ],
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / "inventory.json"
    path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"[collect-inventory] {path} kinds={kinds} stacks={stacks}")


if __name__ == "__main__":
    main()
