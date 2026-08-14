#!/usr/bin/env bash
# check-prereqs.sh — Valida herramientas, Docker y descarga las imágenes
# necesarias. Escribe security-reports/prereqs.json para el reporte y el
# orquestador. Sin Docker NO aborta el scan completo: SAST/SCA local sigue.
#
# Uso:
#   ./check-prereqs.sh [output_dir] [--with-zap]
#
# Códigos de salida:
#   0  Docker listo (SonarQube posible; ZAP si --with-zap)
#   2  Docker ausente o daemon caído — continuar solo con Bandit/SCA
#   1  Falta python3 (no se puede generar el reporte)

set -euo pipefail

OUTPUT_DIR="security-reports"
WITH_ZAP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --with-zap) WITH_ZAP=1 ;;
    --output-dir)
      OUTPUT_DIR="${2:?Falta valor de --output-dir}"
      shift
      ;;
    *) OUTPUT_DIR="$1" ;;
  esac
  shift
done

mkdir -p "${OUTPUT_DIR}"

log() { echo "[check-prereqs] $*" >&2; }

SONAR_IMAGE="${SONAR_DOCKER_IMAGE:-sonarqube:community}"
SCANNER_IMAGE="${SONAR_SCANNER_IMAGE:-sonarsource/sonar-scanner-cli}"
ZAP_IMAGE="${ZAP_DOCKER_IMAGE:-zaproxy/zap-stable}"

PYTHON3_OK=false
PYYAML_OK=false
CURL_OK=false
JQ_OK=false
DOCKER_STATUS="missing"
SONAR_IMAGE_STATUS="skipped"
SCANNER_IMAGE_STATUS="skipped"
ZAP_IMAGE_STATUS="skipped"
SONAR_READY=false
ZAP_READY=false
NOTES=()

note() { NOTES+=("$1"); }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
write_sonar_status() {
  python3 "${SCRIPT_DIR}/write-sonar-status.py" "${OUTPUT_DIR}" "$1" "$2" "http://localhost:9000" "" || true
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

ensure_image() {
  local image="$1"
  if docker image inspect "$image" >/dev/null 2>&1; then
    log "Imagen ya local: ${image}"
    echo "pulled"
    return 0
  fi
  log "Descargando ${image} (puede tardar, ~1GB)..."
  if docker pull "$image" >&2; then
    echo "pulled"
    return 0
  fi
  log "ERROR: no se pudo descargar ${image}."
  echo "missing"
  return 1
}

if has_cmd python3; then
  PYTHON3_OK=true
else
  log "ERROR: python3 no está instalado. Es obligatorio para generar el reporte."
  note "Falta python3 — no se puede generar el HTML."
  echo "{\"docker\":\"missing\",\"python3\":false,\"error\":\"python3 required\"}" > "${OUTPUT_DIR}/prereqs.json"
  exit 1
fi

if python3 -c "import yaml" >/dev/null 2>&1; then
  PYYAML_OK=true
else
  log "PyYAML no está instalado. Intentando pip install pyyaml..."
  if python3 -m pip install -q pyyaml >/dev/null 2>&1; then
    PYYAML_OK=true
    note "PyYAML se instaló automáticamente."
  else
    log "AVISO: instalá PyYAML con: pip install pyyaml"
    note "Falta PyYAML (pip install pyyaml). El HTML no se podrá generar."
  fi
fi

if has_cmd curl; then CURL_OK=true; else note "Falta curl — se omite SonarQube."; fi
if has_cmd jq; then JQ_OK=true; else note "Falta jq — se omite SonarQube."; fi

if ! has_cmd docker; then
  DOCKER_STATUS="missing"
  log "Docker no está instalado. SonarQube y ZAP se omiten."
  log "Instalá Docker Desktop: https://docs.docker.com/get-docker/"
  note "Docker no instalado. SAST/SCA local (Bandit, npm/pip audit) sí corren. SonarQube y ZAP omitidos."
  write_sonar_status images_missing "Docker no instalado. URL prevista: http://localhost:9000"
else
  if docker info >/dev/null 2>&1; then
    DOCKER_STATUS="ok"
    log "Docker daemon OK."
  else
    DOCKER_STATUS="down"
    log "Docker está instalado pero el daemon no responde."
    log "En macOS: open -a Docker   — esperá a que arranque y reintentá."
    note "Docker daemon caído. En macOS: open -a Docker. SonarQube y ZAP omitidos."
    write_sonar_status images_missing "Docker daemon caído. URL prevista: http://localhost:9000"
  fi
fi

if [ "$DOCKER_STATUS" = "ok" ]; then
  SONAR_IMAGE_STATUS="$(ensure_image "$SONAR_IMAGE" || true)"
  SCANNER_IMAGE_STATUS="$(ensure_image "$SCANNER_IMAGE" || true)"
  if [ "$WITH_ZAP" -eq 1 ]; then
    ZAP_IMAGE_STATUS="$(ensure_image "$ZAP_IMAGE" || true)"
  else
    ZAP_IMAGE_STATUS="skipped"
    note "ZAP no se descargó: no hay URL de DAST."
  fi

  if [ "$SONAR_IMAGE_STATUS" = "pulled" ] && [ "$SCANNER_IMAGE_STATUS" = "pulled" ] && [ "$CURL_OK" = true ] && [ "$JQ_OK" = true ]; then
    SONAR_READY=true
    note "SonarQube listo. El primer arranque del servidor tarda 1–2 min. URL: http://localhost:9000"
  else
    note "SonarQube no está listo (imagen, curl o jq faltante). URL prevista: http://localhost:9000"
    write_sonar_status images_missing "Imagen, curl o jq faltante. URL prevista: http://localhost:9000"
  fi

  if [ "$WITH_ZAP" -eq 1 ] && [ "$ZAP_IMAGE_STATUS" = "pulled" ]; then
    ZAP_READY=true
  fi
fi

# Serializar notes a JSON vía python3 (ya confirmado).
export PYTHON3_OK PYYAML_OK CURL_OK JQ_OK DOCKER_STATUS
export SONAR_IMAGE_STATUS SCANNER_IMAGE_STATUS ZAP_IMAGE_STATUS
export SONAR_READY ZAP_READY OUTPUT_DIR
NOTES_JSON="$(printf '%s\n' "${NOTES[@]+"${NOTES[@]}"}" | python3 -c 'import json,sys; print(json.dumps([l.rstrip("\n") for l in sys.stdin if l.strip()]))')"
export NOTES_JSON

python3 - <<'PY'
import json, os
from pathlib import Path

def b(v):
    return str(v).lower() in ("true", "1", "yes")

out = {
    "docker": os.environ["DOCKER_STATUS"],
    "python3": b(os.environ["PYTHON3_OK"]),
    "pyyaml": b(os.environ["PYYAML_OK"]),
    "curl": b(os.environ["CURL_OK"]),
    "jq": b(os.environ["JQ_OK"]),
    "images": {
        "sonarqube:community": os.environ["SONAR_IMAGE_STATUS"],
        "sonarsource/sonar-scanner-cli": os.environ["SCANNER_IMAGE_STATUS"],
        "zaproxy/zap-stable": os.environ["ZAP_IMAGE_STATUS"],
    },
    "sonar_ready": b(os.environ["SONAR_READY"]),
    "zap_ready": b(os.environ["ZAP_READY"]),
    "notes": json.loads(os.environ.get("NOTES_JSON") or "[]"),
}
path = Path(os.environ["OUTPUT_DIR"]) / "prereqs.json"
path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
print(f"[check-prereqs] escrito {path}")
PY

if [ "$DOCKER_STATUS" = "ok" ]; then
  exit 0
fi
exit 2
