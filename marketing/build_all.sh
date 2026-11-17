#!/usr/bin/env bash
# Génère tous les visuels (toutes les langues du manifeste) d'une appli :
#   build_all.sh <dépôt de l appli> [--no-side] [--out-dir <dossier>]
# Les captures pleine résolution doivent déjà exister (voir capture.sh).
set -euo pipefail
[ $# -ge 1 ] || { echo "usage : build_all.sh <depot de l appli> [--no-side] [--out-dir <dossier>]" >&2; exit 2; }
ici="$(cd "$(dirname "$0")" && pwd)"
depot="$1"; shift
python3 "$ici/generate.py" --app-dir "$depot" "$@"
