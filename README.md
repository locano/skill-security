# /skill-security-scan

Skill de [Claude Code](https://claude.com/claude-code) que analiza **cualquier
repo** (web, API, serverless o mixto): SAST de toda la carpeta, DAST solo si
hay una URL HTTP, checklist OWASP Top 10 / API Top 10, y un HTML final.

**Página explicativa:** `index.html`.

## Qué cubre

| Tipo | SAST (Sonar + Bandit/SCA) | DAST (ZAP) | OWASP |
|---|---|---|---|
| Web | Toda la carpeta | Si hay `--web-url` | Top 10 2021 |
| API | Toda la carpeta | `--api-url` y/o OpenAPI | API Top 10 2023 |
| Web + API | Un Sonar sobre el cwd | Las dos URLs, opcionales | Ambas listas |
| Serverless | El código es código | Solo si hay URL HTTP (gateway / `sam local`) | SAST + revisión de handlers |

Sin URL el scan **es válido**. ZAP se omite; no es un fallo. No se valida el
“orden de carpetas” del proyecto destino.

SonarQube (si Docker está): `http://localhost:9000/dashboard?id=<project-key>`
— esa URL se informa **aunque el scan falle**.

Login (también lo imprime el scan y el HTML):

- Usuario: `admin`
- Password: la de `security-reports/.sonar-admin`, o si el archivo no existe: `Security_Scan_2026!` (el año actual).
- Si Sonar nunca cambió la clave: `admin` / `admin`.

## Instalación

```bash
git clone git@github.com:<tu-org>/skill-security.git ~/skill-security
```

En Claude Code:

```
/plugin marketplace add ~/skill-security
/plugin install lc2tech@skill-security
```

En cualquier repo: `/skill-security-scan` o “corre un security scan”. El
agente pregunta el nombre y URLs opcionales, y **avisa cada fase** (no se
queda callado 15 minutos).

> El nombre completo del comando es `/lc2tech:skill-security-scan`
> (namespace del plugin + skill). El alias corto `/skill-security-scan` se
> registra solo si ningún otro plugin instalado ya reclama ese nombre; si
> eso pasa, usá la forma completa.

A mano, desde la raíz del repo a analizar:

```bash
bash ~/skill-security/scripts/security/run-scan.sh \
  --project-name "Mi app" \
  --web-url http://localhost:3000 \
  --api-url http://localhost:8000
```

El primer run con Docker baja imágenes (~1GB c/u). Sonar tarda 1–2 min en levantar.

Si hay poco disco (menos de 5 GB), el scan corre **1 por 1** (SAST → Sonar → ZAP)
para que no fallen todos juntos. También:

```bash
bash ~/skill-security/scripts/security/run-scan.sh --project-name "Mi app" --only sast
bash ~/skill-security/scripts/security/run-scan.sh --project-name "Mi app" --only sonar
bash ~/skill-security/scripts/security/run-scan.sh --project-name "Mi app" --only zap --web-url http://localhost:3000
```

Detalle: [scripts/security/README.md](scripts/security/README.md).

## Estructura

Los scripts están agrupados por tipo de análisis, y el número es el orden en
que corren:

```
.claude-plugin/plugin.json
skills/skill-security-scan/SKILL.md      instrucciones del agente (fases + URL Sonar)
scripts/security/
  run-scan.sh                            orquestador CLI con banners [1/6]…[6/6]
  1-preflight/                           ¿qué es este repo y qué se puede correr?
    collect-inventory.py                 web / api / serverless / OpenAPI
    check-prereqs.sh                     Docker, imágenes, espacio en disco
  2-sast/                                análisis estático: se lee el código
    run-bandit.sh                        patrones inseguros en Python
    setup-sonarqube.sh                   levanta el contenedor y crea el proyecto
    run-sonarqube.sh                     corre el scanner y exporta los issues
    write-sonar-status.py                sonar-status.json (URL siempre)
  3-sca/                                 dependencias de terceros con CVE
    run-sca.sh                           pip-audit + npm audit
  4-dast/                                análisis dinámico: se ataca la app viva
    run-zap.sh                           --web/--api/--openapi o URL única
  5-report/                              correlación y entregable
    map-owasp.py                         Top 10 web + API
    generate-report-template.py          HTML: web para revisar, Cmd+P para PDF
security-reports/security.config.example.yml
index.html
```

## Guardrails

- No `npm audit fix` sin preguntar.
- No ZAP active a producción.
- No commit de `security-reports/` sin pedido explícito.

## Licencia

Uso interno / libre para el equipo.
