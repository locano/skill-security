# /security-scan

Skill de [Claude Code](https://claude.com/claude-code) que corre un análisis de seguridad completo
(SAST + DAST + SCA + OWASP API Security Top 10) directo en tu repositorio, sin plataformas externas
que configurar.

**Página explicativa:** `index.html` — pensada para GitHub Pages, cubre qué es, qué analiza y por qué
nació de un caso real. Instrucciones para publicarla abajo.

## Instalación en tu repo

```bash
git clone https://github.com/locano/skill-security.git
cp -r skill-security/.claude/agents/security-scan.md tu-repo/.claude/agents/
cp -r skill-security/scripts/security tu-repo/scripts/
cp skill-security/security-reports/security.config.example.yml tu-repo/security-reports/
chmod +x tu-repo/scripts/security/*.sh
```

Después, en Claude Code dentro de tu repo:

```
corre un security scan
```

Detalle técnico completo en [scripts/security/README.md](scripts/security/README.md).

## Estructura

```
.claude/agents/security-scan.md          skill (instrucciones para Claude Code)
scripts/security/
  setup-sonarqube.sh                     Docker + SonarQube + token vía API REST
  run-zap.sh                             Docker + ZAP baseline/active scan
  run-sast-sca.sh                        Bandit + pip-audit + npm audit, sin Docker
  generate-report-template.py            genera el HTML final desde JSON + config
  README.md                              quickstart técnico
security-reports/security.config.example.yml   plantilla de config por repo
index.html                               página explicativa (GitHub Pages)
```

## Publicar la página en GitHub Pages

1. Configuración del repo → Pages → Source: `Deploy from a branch` → rama `main`, carpeta `/ (root)`.
2. La página queda en `https://locano.github.io/skill-security/`.

## Por qué existe

Nació de una auditoría de seguridad real (SonarQube, Bandit, OWASP ZAP, npm audit) sobre el API del
CRM en LC2TECH, que encontró y cerró vulnerabilidades críticas: `eval()` sin
sandboxing (CWE-78), S3 sin `ExpectedBucketOwner` (CWE-284), y dependencias npm con RCE conocidos.
El mismo flujo que generó ese reporte es el que empaqueta este skill.

## Guardrails

El skill nunca corre sin preguntar:

- `npm audit fix` — modifica `package-lock.json`.
- Un active scan de ZAP contra una URL — siempre confirma target y ambiente.
- Un `git commit` de los reportes generados.

## Licencia

Uso interno / libre para compartir dentro del equipo. Ajustá esta sección si vas a abrir el repo
públicamente con una licencia formal (MIT, Apache-2.0, etc.).
