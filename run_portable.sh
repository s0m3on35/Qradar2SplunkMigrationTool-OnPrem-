#!/usr/bin/env bash
set -e
python convert.py   --input-csv samples/qradar_rules.csv   --xml samples/qradar_rules_export.xml   --outdir output   --app My_SIEM_Migration   --default-index main   --field-map mappings/field_map.yaml   --building-blocks mappings/building_blocks.csv   --reference-sets mappings/reference_sets.csv   --backup --log-level INFO
echo "Listo. Revisa la carpeta 'output/'."
