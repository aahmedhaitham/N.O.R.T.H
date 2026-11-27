"""Download one reviewed, pinned public EVTX dataset file and record its provenance."""
import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import quote
from urllib.request import urlopen

DATASET = "sbousseaden/EVTX-ATTACK-SAMPLES"
HOST = "https://raw.githubusercontent.com/"
LIMIT = 128 * 1024 * 1024


def fetch(url):
    response = urlopen(url, timeout=25)
    if not response.geturl().startswith(HOST):
        response.close()
        raise ValueError("The dataset redirected outside its reviewed host.")
    return response


def download(commit, member, directory):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Use a full Git commit ID.")
    member = PurePosixPath(member)
    if (member.is_absolute() or ".." in member.parts or member.suffix.lower() != ".evtx"
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", member.name)):
        raise ValueError("Choose a relative EVTX path with a standard filename.")
    base = f"{HOST}{DATASET}/{commit}/"
    license_url = base + "LICENSE.GPL"
    with fetch(license_url) as response:
        license_text = response.read(100_001)
    if len(license_text) > 100_000 or b"GNU GENERAL PUBLIC LICENSE" not in license_text or b"Version 3" not in license_text:
        raise ValueError("The pinned dataset license could not be verified.")
    url = base + quote(member.as_posix(), safe="/")
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / member.name
    manifest = output.with_suffix(output.suffix + ".provenance.json")
    if output.exists() or manifest.exists():
        raise ValueError("The dataset or its provenance record already exists.")
    digest = hashlib.sha256()
    length = 0
    with tempfile.TemporaryFile() as staging, fetch(url) as response:
        header = response.read(8)
        if header != b"ElfFile\x00":
            raise ValueError("The download is not recognizable as EVTX.")
        staging.write(header)
        digest.update(header)
        length += len(header)
        while data := response.read(128 * 1024):
            length += len(data)
            if length > LIMIT:
                raise ValueError("The EVTX download exceeds 128 MiB.")
            staging.write(data)
            digest.update(data)
        result = {"source": url, "repository": DATASET, "commit": commit, "license": "GPL-3.0",
                  "license_source": license_url, "sha256": digest.hexdigest(), "bytes": length}
        with manifest.open("x", encoding="utf-8") as file:
            json.dump(result, file, indent=2)
            file.write("\n")
        staging.seek(0)
        try:
            with output.open("xb") as file:
                while data := staging.read(128 * 1024):
                    file.write(data)
        except OSError:
            manifest.unlink()
            raise
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("commit")
    parser.add_argument("path")
    parser.add_argument("--directory", type=Path, default=Path(".north-launcher/datasets"))
    args = parser.parse_args()
    try:
        print(json.dumps(download(args.commit, args.path, args.directory), indent=2))
    except (OSError, ValueError) as error:
        parser.exit(2, "NORTH could not download the reviewed dataset: " + str(error) + "\n")


if __name__ == "__main__":
    main()
