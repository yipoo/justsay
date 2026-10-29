"""Encrypt existing local Certbot state for this repository's first run.

The output contains private material and must only be stored in GitHub Secrets.
"""
import os
from pathlib import Path
import shutil
import sys
import tempfile

import manage


def main():
    source = Path(sys.argv[1]).expanduser().resolve()
    output = Path(os.environ["STATE_ARCHIVE"]).expanduser().resolve()
    repository = Path(__file__).resolve().parents[2]
    if output.is_relative_to(repository):
        raise RuntimeError("Store encrypted state outside the public repository")
    if not (source / "live" / manage.DOMAIN / "privkey.pem").exists():
        raise RuntimeError("Source does not contain the JustSay certificate")
    with tempfile.TemporaryDirectory(prefix="justsay-acme-bootstrap-") as temp:
        manage.STATE = Path(temp)
        target = manage.STATE / "config"
        shutil.copytree(source, target, symlinks=True)
        for other in (target / "renewal").glob("*.conf"):
            if other.name != f"{manage.DOMAIN}.conf":
                raise RuntimeError("Use Certbot state dedicated to JustSay")
        runner = "/tmp/justsay-acme-state"
        for conf in (target / "renewal").glob("*.conf"):
            text = conf.read_text().replace(str(source), f"{runner}/config")
            text = text.replace(str(source.parent / "work"), f"{runner}/work")
            text = text.replace(str(source.parent / "logs"), f"{runner}/logs")
            conf.write_text(text)
        manage.crypt_state(True)
        output.chmod(0o600)


if __name__ == "__main__":
    main()
