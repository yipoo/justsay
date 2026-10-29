#!/bin/sh
set -eu
source_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output_root=${1:?Usage: build.sh /absolute/output/directory}
case "$output_root" in
  /*) ;;
  *) echo 'Output directory must be absolute' >&2; exit 1 ;;
esac
mkdir -p "$output_root"
package_root=$(mktemp -d)
trap 'rm -rf "$package_root"' EXIT
mkdir "$package_root/generator"
cp -R "$source_root/cert-generator/." "$package_root/generator/"
uv pip install --target "$package_root/generator/python" \
  --python-platform x86_64-manylinux_2_28 --python-version 3.10 \
  --only-binary cryptography --only-binary cffi \
  -r "$source_root/cert-generator/requirements.txt"
cp -R "$source_root/fc-domain-manager" "$package_root/manager"
npm ci --prefix "$package_root/manager" --ignore-scripts --no-audit --no-fund
python3 - "$package_root" "$output_root" <<'PY'
from pathlib import Path
import sys
import zipfile
root, output = map(Path, sys.argv[1:])
for source, name in [('generator', 'cert-generator.zip'), ('manager', 'cert-domain-manager.zip')]:
    with zipfile.ZipFile(output / name, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for file in (root / source).rglob('*'):
            if file.is_file() and '__pycache__' not in file.parts:
                archive.write(file, file.relative_to(root / source))
    print(output / name)
PY
