#!/usr/bin/env bash
# run-sast-sca.sh — Ejecuta SAST (Bandit) y SCA (npm audit / pip-audit) locales,
# sin dependencias de Docker. Detecta automáticamente qué aplica según el repo.
#
# Uso:
#   ./run-sast-sca.sh <output_dir>

set -euo pipefail

OUTPUT_DIR="${1:-security-reports}"
mkdir -p "${OUTPUT_DIR}"

log() { echo "[run-sast-sca] $*" >&2; }

# --- Bandit (SAST Python) ---
if find . -name "*.py" -not -path "*/node_modules/*" -not -path "*/.venv*/*" | grep -q .; then
  log "Python detectado — ejecutando Bandit..."
  if ! command -v bandit >/dev/null 2>&1; then
    log "Bandit no instalado, instalando en venv temporal..."
    python3 -m venv /tmp/.bandit-venv 2>/dev/null || true
    # shellcheck disable=SC1091
    source /tmp/.bandit-venv/bin/activate
    pip install -q bandit
  fi
  bandit -r . -f json -o "${OUTPUT_DIR}/bandit-report.json" \
    -x "*/node_modules/*,*/.venv*/*,*/test/*,*/tests/*" || true
  log "Bandit -> ${OUTPUT_DIR}/bandit-report.json"
else
  log "Sin archivos Python, se omite Bandit."
fi

# --- pip-audit (SCA Python) ---
if [ -f "requirements.txt" ] || [ -f "Pipfile" ] || [ -f "pyproject.toml" ]; then
  log "Dependencias Python detectadas — ejecutando pip-audit..."
  if ! command -v pip-audit >/dev/null 2>&1; then
    pip install -q pip-audit 2>/dev/null || true
  fi
  if [ -f "requirements.txt" ]; then
    pip-audit -r requirements.txt -f json -o "${OUTPUT_DIR}/pip-audit-report.json" || true
  else
    pip-audit -f json -o "${OUTPUT_DIR}/pip-audit-report.json" || true
  fi
  log "pip-audit -> ${OUTPUT_DIR}/pip-audit-report.json"
fi

# --- npm audit (SCA Node) ---
if [ -f "package.json" ]; then
  log "package.json detectado — ejecutando npm audit..."
  npm audit --json > "${OUTPUT_DIR}/npm-audit-report.json" 2>/dev/null || true
  log "npm audit -> ${OUTPUT_DIR}/npm-audit-report.json"
fi

log "Listo."
