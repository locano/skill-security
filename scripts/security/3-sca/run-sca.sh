#!/usr/bin/env bash
# run-sca.sh — SCA: dependencias de terceros con CVE conocido.
#
# No mira tu código: mira lo que instalaste. pip-audit para Python y
# npm audit para Node. Cada uno corre solo si hay manifiesto.
#
# Uso: ./run-sca.sh [output_dir]
# Salida: <output_dir>/pip-audit-report.json, <output_dir>/npm-audit-report.json
#
# Requiere: python3 (pip-audit se instala si falta), npm para la parte Node.

set -uo pipefail

OUTPUT_DIR="${1:-security-reports}"
mkdir -p "${OUTPUT_DIR}"

log() { echo "[run-sca] $*" >&2; }
RAN=0

# --- Python ---
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
  log "-> ${OUTPUT_DIR}/pip-audit-report.json"
  RAN=1
fi

# --- Node ---
# Cada gestor emite un JSON distinto: npm usa {"vulnerabilities": {paquete}},
# pnpm usa {"advisories": {id}}. Se elige por el lockfile presente; usar el
# comando equivocado devuelve un informe vacío que parece "sin hallazgos".
if [ -f "package.json" ]; then
  if [ -f "pnpm-lock.yaml" ] && command -v pnpm >/dev/null 2>&1; then
    log "pnpm-lock.yaml detectado — ejecutando pnpm audit..."
    pnpm audit --json > "${OUTPUT_DIR}/npm-audit-report.json" \
      2>"${OUTPUT_DIR}/pnpm-audit.err" || true
  elif [ -f "yarn.lock" ] && command -v yarn >/dev/null 2>&1; then
    log "yarn.lock detectado — ejecutando yarn npm audit..."
    yarn npm audit --json > "${OUTPUT_DIR}/npm-audit-report.json" \
      2>"${OUTPUT_DIR}/yarn-audit.err" || true
  else
    log "Ejecutando npm audit..."
    npm audit --json > "${OUTPUT_DIR}/npm-audit-report.json" 2>/dev/null || true
  fi

  # Un archivo sin detalle ni totales suele ser un audit que falló en silencio.
  if ! python3 - "${OUTPUT_DIR}/npm-audit-report.json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
tot = sum(v for v in ((d.get("metadata") or {}).get("vulnerabilities") or {}).values()
          if isinstance(v, int))
sys.exit(0 if (d.get("vulnerabilities") or d.get("advisories") or tot) else 1)
PY
  then
    log "AVISO: el audit no devolvió datos. Revisá que las dependencias estén instaladas."
  fi
  log "-> ${OUTPUT_DIR}/npm-audit-report.json"
  RAN=1
fi

[ "$RAN" -eq 0 ] && log "Sin manifiestos de dependencias: nada que auditar."
exit 0
