"""Fetch the public datasets SPECIMEN is evaluated on (reports/features only).

    python scripts/download_data.py --dest $SPECIMEN_DATA [--only avast,ember,malbehavd]

Datasets (no binaries are downloaded - ever):

* ``avast``     Avast-CTU Public CAPEv2 Dataset, *reduced* reports (593 MB zip,
                48,976 CAPE behaviour reports + labels, MIT).
* ``ember``     EMBER 2018 v2 raw static features (JSON lines). Only a prefix of
                the 1.7 GB tar.bz2 is fetched by default (``--ember-mb``); the
                loader stream-decodes whatever prefix is present.
* ``malbehavd`` MalbehavD-V1 Cuckoo API-call sequences, 1,285 benign +
                1,285 malicious (MIT).

SHA-256 of every file is written to ``<dest>/SHA256SUMS`` after download and
verified on the next run (``--verify``).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _download import download, sha256_file  # noqa: E402

AVAST_URL = ("https://drive.usercontent.google.com/download?"
             "id=1xujiSqV0sUv4GinS2xq8XFRpZLvvs1um&export=download&confirm=t")
AVAST_SIZE = 592_988_050
EMBER_URL = "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
MALBEHAVD = "https://raw.githubusercontent.com/mpasco/MalbehavD-V1/main/"
# pinned hashes of fully-downloaded files (prefix downloads are hashed locally)
KNOWN = {
    "malbehavd/MalBehavD-V1-dataset.csv": None,
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dest", type=Path, default=Path(os.environ.get("SPECIMEN_DATA", "data")))
    ap.add_argument("--only", default="malbehavd,avast,ember")
    ap.add_argument("--ember-mb", type=int, default=120, help="MB prefix of the EMBER tar.bz2 to fetch")
    ap.add_argument("--avast-mb", type=int, default=0, help="0 = full reduced archive; >0 = prefix only")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--verify", action="store_true", help="only verify SHA256SUMS")
    a = ap.parse_args(argv)
    dest: Path = a.dest
    sums = dest / "SHA256SUMS"
    if a.verify:
        bad = 0
        for line in sums.read_text().splitlines():
            h, rel = line.split(maxsplit=1)
            ok = sha256_file(dest / rel) == h
            bad += not ok
            print(("OK  " if ok else "BAD ") + rel)
        return 1 if bad else 0
    only = set(a.only.split(","))
    files: list[Path] = []
    if "malbehavd" in only:
        for f in ("MalBehavD-V1-dataset.csv", "README.md", "license"):
            files.append(download(MALBEHAVD + f, dest / "malbehavd" / f, workers=1))
    if "avast" in only:
        mb = a.avast_mb * 1024 * 1024 if a.avast_mb else None
        files.append(download(AVAST_URL, dest / "avast_cape" / "Public_Avast_CTU_CAPEv2_Dataset_Small.zip",
                              max_bytes=mb, workers=a.workers))
    if "ember" in only:
        files.append(download(EMBER_URL, dest / "ember" / "ember_dataset_2018_2.tar.bz2",
                              max_bytes=a.ember_mb * 1024 * 1024, workers=a.workers))
    lines = {}
    if sums.exists():
        for line in sums.read_text().splitlines():
            h, rel = line.split(maxsplit=1)
            lines[rel] = h
    for f in files:
        rel = f.relative_to(dest).as_posix()
        lines[rel] = sha256_file(f)
    sums.write_text("".join(f"{h}  {r}\n" for r, h in sorted(lines.items())))
    print(f"wrote {sums}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
