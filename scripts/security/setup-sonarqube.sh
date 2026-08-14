#!/usr/bin/env bash
# setup-sonarqube.sh — Levanta SonarQube Community en Docker (modo local) y
# crea/reutiliza un proyecto + token vía API REST.
#
# Uso:
#   ./setup-sonarqube.sh <project_key> <project_name> [port]
#
# Variables de entorno:
#   SECURITY_OUTPUT_DIR   directorio para .sonar-admin (default: security-reports)
#   SONAR_ADMIN_PASSWORD  password admin a setear en el primer arranque
#   SONAR_DOCKER_IMAGE    imagen (default: sonarqube:community)
#
# Salida (stdout):
#   SONAR_URL=...
#   TOKEN=...
# Requiere: docker, curl, jq

set -euo pipefail

PROJECT_KEY="${1:?Uso: setup-sonarqube.sh <project_key> <project_name> [port]}"
PROJECT_NAME="${2:?Falta project_name}"
PORT="${3:-9000}"
CONTAINER_NAME="sonarqube-security-scan"
SONAR_URL="http://localhost:${PORT}"
IMAGE="${SONAR_DOCKER_IMAGE:-sonarqube:community}"
OUTPUT_DIR="${SECURITY_OUTPUT_DIR:-security-reports}"
DEFAULT_ADMIN_PASS="admin"
NEW_ADMIN_PASS="${SONAR_ADMIN_PASSWORD:-Security_Scan_$(date +%Y)!}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "[setup-sonarqube] $*" >&2; }

write_status() {
  python3 "${SCRIPT_DIR}/write-sonar-status.py" "${OUTPUT_DIR}" "$1" "$2" "${SONAR_URL}" "${PROJECT_KEY}" || true
}

if ! command -v docker >/dev/null 2>&1; then
  log "ERROR: Docker no está instalado."
  write_status images_missing "Docker no está instalado."
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  log "ERROR: el daemon de Docker no está corriendo. En macOS: open -a Docker"
  write_status images_missing "Docker daemon caído. En macOS: open -a Docker"
  exit 1
fi
if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
  log "ERROR: se necesitan curl y jq."
  write_status images_missing "Faltan curl o jq."
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
ADMIN_FILE="${OUTPUT_DIR}/.sonar-admin"
OLD_FLAG="/tmp/.sonar_pw_changed_${PORT}"
if [ ! -f "$ADMIN_FILE" ] && [ -f "$OLD_FLAG" ] && [ -s "$OLD_FLAG" ]; then
  cp "$OLD_FLAG" "$ADMIN_FILE"
  log "Migrada password admin desde ${OLD_FLAG}."
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "Descargando ${IMAGE}..."
  docker pull "$IMAGE" >&2
fi

if ! docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  log "Levantando SonarQube en puerto ${PORT}..."
  docker run -d --name "${CONTAINER_NAME}" \
    -p "${PORT}:9000" \
    -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
    "${IMAGE}"
else
  if [ "$(docker inspect -f '{{.State.Running}}' "${CONTAINER_NAME}")" != "true" ]; then
    log "Contenedor existente detenido, iniciando..."
    docker start "${CONTAINER_NAME}"
  else
    log "Contenedor ${CONTAINER_NAME} ya está corriendo."
  fi
fi

log "Esperando a que SonarQube esté disponible (puede tardar 1-2 min)..."
for i in $(seq 1 60); do
  STATUS=$(curl -s "${SONAR_URL}/api/system/status" | jq -r '.status // "DOWN"' 2>/dev/null || echo "DOWN")
  if [ "$STATUS" = "UP" ]; then
    log "SonarQube UP."
    break
  fi
  sleep 5
  if [ "$i" -eq 60 ]; then
    log "ERROR: SonarQube no respondió después de 5 minutos."
    write_status down "Timeout esperando UP. URL prevista: ${SONAR_URL}"
    exit 1
  fi
done
log "Dashboard: ${SONAR_URL}/dashboard?id=${PROJECT_KEY}"

AUTH=""
if [ -f "$ADMIN_FILE" ] && [ -s "$ADMIN_FILE" ]; then
  NEW_ADMIN_PASS="$(cat "$ADMIN_FILE")"
  if curl -s -u "admin:${NEW_ADMIN_PASS}" "${SONAR_URL}/api/authentication/validate" | jq -e '.valid == true' >/dev/null 2>&1; then
    AUTH="admin:${NEW_ADMIN_PASS}"
  fi
fi

if [ -z "$AUTH" ]; then
  if curl -s -u "admin:${DEFAULT_ADMIN_PASS}" "${SONAR_URL}/api/authentication/validate" | jq -e '.valid == true' >/dev/null 2>&1; then
    log "Cambiando password por defecto y guardándola en ${ADMIN_FILE}..."
    curl -s -u "admin:${DEFAULT_ADMIN_PASS}" -X POST "${SONAR_URL}/api/users/change_password" \
      -d "login=admin&previousPassword=${DEFAULT_ADMIN_PASS}&password=${NEW_ADMIN_PASS}" >/dev/null
    printf '%s\n' "$NEW_ADMIN_PASS" > "$ADMIN_FILE"
    chmod 600 "$ADMIN_FILE" 2>/dev/null || true
    AUTH="admin:${NEW_ADMIN_PASS}"
  else
    log "ERROR: no se pudo autenticar como admin. Borrá el contenedor ${CONTAINER_NAME} y reintentá, o definí SONAR_ADMIN_PASSWORD."
    exit 1
  fi
fi

EXISTS=$(curl -s -u "${AUTH}" "${SONAR_URL}/api/projects/search?projects=${PROJECT_KEY}" | jq -r '.components | length')
if [ "$EXISTS" = "0" ]; then
  log "Creando proyecto ${PROJECT_KEY}..."
  curl -s -u "${AUTH}" -X POST "${SONAR_URL}/api/projects/create" \
    --data-urlencode "project=${PROJECT_KEY}" \
    --data-urlencode "name=${PROJECT_NAME}" >/dev/null
fi

curl -s -u "${AUTH}" -X POST "${SONAR_URL}/api/user_tokens/revoke" \
  -d "name=security-scan-token" >/dev/null 2>&1 || true
TOKEN=$(curl -s -u "${AUTH}" -X POST "${SONAR_URL}/api/user_tokens/generate" \
  -d "name=security-scan-token" | jq -r '.token // empty')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  log "ERROR: no se pudo generar el token de análisis."
  exit 1
fi

write_status up "SonarQube UP. Dashboard: ${SONAR_URL}/dashboard?id=${PROJECT_KEY}"
log "────────────────────────────────────────"
log "SonarQube: ${SONAR_URL}/dashboard?id=${PROJECT_KEY}"
log "Usuario:   admin"
log "Password:  ${NEW_ADMIN_PASS}"
log "Archivo:   ${ADMIN_FILE}"
log "────────────────────────────────────────"
echo "SONAR_URL=${SONAR_URL}"
echo "TOKEN=${TOKEN}"
echo "SONAR_LOGIN=admin"
echo "SONAR_PASSWORD=${NEW_ADMIN_PASS}"
