#!/bin/bash
set -eu
python - <<'PYCODE'
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
root = Path("/etc/letsencrypt/live") / os.environ["DEVS_DOMAIN"]
key = serialization.load_pem_private_key((root / "privkey.pem").read_bytes(), password=None)
path = root / "privkey.pkcs1.pem"
path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
path.chmod(0o600)
PYCODE
