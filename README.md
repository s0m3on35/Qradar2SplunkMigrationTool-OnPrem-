# QRadar to Splunk Migration Toolkit

Herramienta portable para convertir reglas exportadas desde QRadar en una app de Splunk con `savedsearches.conf`, `correlationsearches.conf`, lookups, metadata, reporte JSON y log de migracion.

## Requisitos

- Python 3.8 o superior.
- `PyYAML` es opcional. Si no esta instalado, el script puede leer mappings YAML simples del tipo `campo_qradar: campo_splunk`.

Instalacion opcional:

```powershell
python -m pip install --user -r requirements.txt
```

## Uso rapido

Windows:

```bat
run_portable.bat
```

Ejecucion directa:

```powershell
python convert.py `
  --input-csv samples\qradar_rules.csv `
  --xml samples\qradar_rules_export.xml `
  --outdir output `
  --app My_SIEM_Migration `
  --default-index main `
  --field-map mappings\field_map.yaml `
  --building-blocks mappings\building_blocks.csv `
  --reference-sets mappings\reference_sets.csv `
  --backup --log-level INFO
```

Validacion sin generar la app:

```powershell
python convert.py `
  --input-csv samples\qradar_rules.csv `
  --outdir output `
  --dry-run --strict --fail-on-warn
```

Uso con perfil de entorno:

```powershell
python convert.py `
  --profile migration_profile.sample.yaml `
  --outdir output `
  --backup --package --log-level INFO
```

Preflight antes de generar nada:

```powershell
python convert.py `
  --profile migration_profile.sample.yaml `
  --outdir preflight `
  --preflight
```

Validacion opcional contra Splunk on-premise:

```powershell
python convert.py `
  --profile migration_profile.sample.yaml `
  --outdir output `
  --validate-splunk `
  --splunk-url https://splunk-search-head.local:8089 `
  --splunk-username admin `
  --splunk-password "change-me" `
  --splunk-no-verify-ssl
```

Export basico desde QRadar API:

```powershell
python convert.py `
  --profile migration_profile.sample.yaml `
  --outdir qradar_inventory `
  --qradar-export `
  --qradar-token "SEC_TOKEN" `
  --qradar-no-verify-ssl
```

Validacion profunda contra Splunk con ejecucion de muestra:

```powershell
python convert.py `
  --profile migration_profile.sample.yaml `
  --outdir output `
  --validate-splunk `
  --splunk-execute-sample `
  --sample-earliest "-24h" `
  --sample-latest now
```

Auditoria de mappings y tracker sin generar app:

```powershell
python convert.py `
  --profile migration_profile.sample.yaml `
  --outdir audit `
  --audit-only --log-level INFO
```

Estado de revision:

```powershell
python convert.py `
  --profile migration_profile.sample.yaml `
  --review-state reviews.sample.yaml `
  --outdir output
```

Instalacion segura con busquedas deshabilitadas:

```powershell
python convert.py `
  --profile migration_profile.sample.yaml `
  --outdir output `
  --disable-searches --package
```

## Entradas

- CSV de reglas con columnas `name,aql,enabled,cron,notable,severity,description,throttle_window,risk_score,throttle_keys`.
- XML exportado con nodos `rule`.
- `mappings/field_map.yaml` para mapear campos QRadar a campos Splunk.
- `mappings/building_blocks.csv` para expandir building blocks QRadar.
- `mappings/reference_sets.csv` para declarar lookups equivalentes a reference sets.

Si una fila CSV contiene AQL con comas sin entrecomillar, el script intenta reconstruirla y emite un warning. Lo recomendable para produccion es entrecomillar cualquier AQL que contenga comas.

## Salidas

- `output/app/local/savedsearches.conf`
- `output/app/local/correlationsearches.conf`
- `output/app/local/macros.conf`
- `output/app/local/props.conf`
- `output/app/local/transforms.conf`
- `output/app/default/app.conf`
- `output/app/metadata/local.meta`
- `output/app/metadata/default.meta`
- `output/report.json`
- `output/compatibility_report.json`
- `output/compatibility_report.html`
- `output/executive_summary.md`
- `output/readiness_report.md`
- `output/manifest.json`
- `output/preflight_report.json` cuando se usa `--preflight`
- `output/mapping_audit.json`
- `output/mapping_audit.csv`
- `output/migration_tracker.xlsx`
- `output/qradar_inventory.json` cuando se usa `--qradar-export`
- `output/packages/<app>.tgz`
- `output/migration.log`

## Controles de robustez

- Escritura atomica de ficheros.
- `--dry-run` real para validar sin escribir app ni reporte.
- `--strict` para fallar ante errores criticos.
- `--fail-on-warn` para devolver error si hay warnings.
- `--backup` para preservar configuraciones previas antes de sobrescribir.
- Hash SHA-256 de cada salida en `report.json`.
- Normalizacion de severidad, cron, throttling y nombres de stanza.
- Perfil de entorno con entradas, mappings, app Splunk, indice por defecto y parametros REST.
- Reporte de compatibilidad por regla: estado, confianza, campos sin mapear, dependencias e incidencias.
- Validacion REST opcional contra Splunk on-premise usando `/services/search/parser`.
- Linter interno de app Splunk para estructura, stanzas, lookups y busquedas incompletas.
- Resumen ejecutivo Markdown para seguimiento de migracion.
- Empaquetado `.tgz` instalable en Splunk on-premise con `--package`.
- Auditoria de mappings con campos usados, campos sin mapear, reglas afectadas y acciones pendientes.
- Excel de seguimiento `migration_tracker.xlsx` con pestanas de resumen, reglas, campos, dependencias y acciones.
- Export basico desde QRadar API: reglas, building blocks, reference sets, log sources, log source types y custom properties.
- Validacion Splunk ampliada: parser SPL, inventario de indexes/sourcetypes, deteccion de referencias faltantes y ejecucion sample opcional.
- Estado de revision persistente con `--review-state` para owner, aprobacion, descarte, notas y trazabilidad humana.
- Preflight operativo con `--preflight` para validar rutas, permisos, perfil, credenciales requeridas y parametros peligrosos.
- Readiness report con blockers/warnings antes de instalar.
- Manifest final con hashes de inputs/outputs y parametros sanitizados.
- Modo seguro `--disable-searches` para instalar sin activar alertas en produccion.
