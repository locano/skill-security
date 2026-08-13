#!/usr/bin/env bash
# setup-sonarqube.sh — Levanta SonarQube Community en Docker (modo local) y
# crea/reutiliza un proyecto + token vía API REST.
#
# Uso:
#   ./setup-sonarqube.sh <project_key> <project_name> [port]
#
# Salida (stdout, última línea): TOKEN=<sonar_token>
# Requiere: docker, curl, jq

set -euo pipefail

PROJECT_KEY="${1:?Uso: setup-sonarqube.sh <project_key> <project_name> [port]}"
PROJECT_NAME="${2:?Falta project_name}"
PORT="${3:-9000}"
CONTAINER_NAME="sonarqube-security-scan"
SONAR_URL="http://localhost:${PORT}"
DEFAULT_ADMIN_PASS="admin"
NEW_ADMIN_PASS="${SONAR_ADMIN_PASSWORD:-Security_Scan_$(date +%Y)!}"

log() { echo "[setup-sonarqube] $*" >&2; }

# 1. Levantar contenedor si no existe
if ! docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  log "Descargando y levantando SonarQube en puerto ${PORT}..."
  docker run -d --name "${CONTAINER_NAME}" \
    -p "${PORT}:9000" \
    -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
    sonarqube:community
else
  if [ "$(docker inspect -f '{{.State.Running}}' ${CONTAINER_NAME})" != "true" ]; then
    log "Contenedor existente detenido, iniciando..."
    docker start "${CONTAINER_NAME}"
  else
    log "Contenedor ${CONTAINER_NAME} ya está corriendo."
  fi
fi

# 2. Esperar health check
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
    exit 1
  fi
done

# 3. Cambiar password por defecto si es la primera vez
CHANGED_FLAG="/tmp/.sonar_pw_changed_${PORT}"
AUTH="admin:${DEFAULT_ADMIN_PASS}"
if [ ! -f "$CHANGED_FLAG" ]; then
  if curl -s -u "${AUTH}" "${SONAR_URL}/api/authentication/validate" | jq -e '.valid == true' >/dev/null 2>&1; then
    log "Cambiando password por defecto..."
    curl -s -u "${AUTH}" -X POST "${SONAR_URL}/api/users/change_password" \
      -d "login=admin&previousPassword=${DEFAULT_ADMIN_PASS}&password=${NEW_ADMIN_PASS}" >/dev/null
    touch "$CHANGED_FLAG"
    echo "$NEW_ADMIN_PASS" > "$CHANGED_FLAG"
  fi
fi
if [ -f "$CHANGED_FLAG" ] && [ -s "$CHANGED_FLAG" ]; then
  NEW_ADMIN_PASS=$(cat "$CHANGED_FLAG")
fi
AUTH="admin:${NEW_ADMIN_PASS}"

# 4. Crear proyecto si no existe
EXISTS=$(curl -s -u "${AUTH}" "${SONAR_URL}/api/projects/search?projects=${PROJECT_KEY}" | jq -r '.components | length')
if [ "$EXISTS" = "0" ]; then
  log "Creando proyecto ${PROJECT_KEY}..."
  curl -s -u "${AUTH}" -X POST "${SONAR_URL}/api/projects/create" \
    -d "project=${PROJECT_KEY}&name=${PROJECT_NAME}" >/dev/null
fi

# 5. Generar token (revoca uno previo con el mismo nombre para evitar acumulación)
TOKEN_NAME="scan-$(date +%s)"
curl -s -u "${AUTH}" -X POST "${SONAR_URL}/api/user_tokens/revoke" \
  -d "name=security-scan-token" >/dev/null 2>&1 || true
TOKEN=$(curl -s -u "${AUTH}" -X POST "${SONAR_URL}/api/user_tokens/generate" \
  -d "name=security-scan-token" | jq -r '.token')

log "Proyecto listo: ${SONAR_URL}/dashboard?id=${PROJECT_KEY}"
log "Admin password: ${NEW_ADMIN_PASS} (guardada en ${CHANGED_FLAG})"
echo "SONAR_URL=${SONAR_URL}"
echo "TOKEN=${TOKEN}"
