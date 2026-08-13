# Security Scan — SAST + SCA + DAST reutilizable

Skill de Claude Code para correr un análisis de seguridad completo en
cualquier repositorio. Portable: copia esta carpeta + `.claude/agents/security-scan.md`
+ `security-reports/security.config.example.yml` a otro repo y ya funciona ahí.

## Uso rápido

1. Abre Claude Code en la raíz del repo.
2. Pide: **"corre un security scan"** o **"/security-scan"**.
3. Claude te preguntará: nombre del proyecto, si quieres branding custom, y
   la URL target si vas a correr DAST (ZAP). Nunca asume esos datos.
4. Al final tendrás `security-reports/security-report-completo.html`.

## Requisitos

| Herramienta | Para qué | Obligatorio |
|---|---|---|
| `python3` + `pyyaml` | Generar el reporte | Sí |
| `bandit` | SAST Python | Se instala solo si falta |
| `pip-audit` | SCA Python | Se instala solo si falta |
| `npm` | SCA Node | Solo si hay `package.json` |
| `docker` | SonarQube + ZAP | Solo si quieres esos scans |
| `jq`, `curl` | Scripts de setup | Sí, para SonarQube/ZAP |

Sin Docker igual obtienes Bandit + npm/pip audit — es el 80% del valor sin
fricción de infraestructura.

## Qué NO hace automático (por diseño, requiere tu confirmación)

- **No corre `npm audit fix` sin preguntar** — modifica `package-lock.json`.
- **No lanza un ZAP active scan sin que confirmes la URL y el ambiente** —
  un active scan envía payloads de ataque reales.
- **No commitea `security-reports/` sin preguntar.**

## Archivos

```
.claude/agents/security-scan.md              skill (instrucciones para Claude)
scripts/security/
  setup-sonarqube.sh                          Docker + SonarQube + token
  run-zap.sh                                  Docker + ZAP baseline/active
  run-sast-sca.sh                             Bandit + pip-audit + npm audit (sin Docker)
  generate-report-template.py                 Genera el HTML final desde los JSON + config
security-reports/
  security.config.example.yml                 plantilla — copiar a security.config.yml
  security.config.yml                         config real del repo (gitignored)
```

## Reevaluar después de aplicar fixes

Corre el mismo comando de nuevo — el reporte se regenera con el estado
actual del código. No hace falta borrar nada del directorio primero.
