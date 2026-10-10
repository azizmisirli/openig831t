#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Plan or explicitly fetch the fixed, hash-pinned optional source cache.

Import and default invocation perform no network access or filesystem writes.
This tool does not build, apply patches, install software, or access hardware.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

MAX_BYTES = 2 * 1024 * 1024


def selected_sources(manifest: dict, group: str) -> list[dict]:
    """Return only the source records in the checked-in manifest."""
    projects = {"linux": {"Linux"}, "libusb": {"libusb"}, "all": {"Linux", "libusb"}}
    selected = [s for s in manifest["sources"] if s["project"] in projects[group]]
    for source in selected:
        path = Path(source["cache_path"])
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("unsafe cache path")
        if not source["url"].startswith("https://raw.githubusercontent.com/"):
            raise ValueError("unapproved source host")
        if not 0 < source["size"] <= MAX_BYTES or len(source["sha256"]) != 64:
            raise ValueError("invalid pinned source metadata")
    return selected


def verify_bytes(data: bytes, source: dict) -> None:
    if len(data) != source["size"] or hashlib.sha256(data).hexdigest() != source["sha256"]:
        raise ValueError("source size or SHA256 mismatch: " + source["cache_path"])


def cache_path(root: Path, source: dict) -> Path:
    target = root / source["cache_path"]
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError("cache path escapes the selected directory")
    return target


def fetch_one(root: Path, source: dict) -> str:
    target = cache_path(root, source)
    if target.exists():
        verify_bytes(target.read_bytes(), source)
        return "REUSED_VERIFIED"
    request = urllib.request.Request(source["url"], headers={"User-Agent": "OpenIG831T-source-fetch/0.1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(MAX_BYTES + 1)
    verify_bytes(data, source)
    target.parent.mkdir(parents=True, exist_ok=True)
    # Recheck after directory creation; exclusive creation never overwrites a file.
    target = cache_path(root, source)
    with target.open("xb") as stream:
        stream.write(data)
    return "FETCHED_VERIFIED"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--execute-fetch", action="store_true", help="explicitly allow the listed HTTPS downloads")
    modes.add_argument("--verify-cache", action="store_true", help="check existing files without network access")
    parser.add_argument("--group", choices=("all", "linux", "libusb"), default="all")
    parser.add_argument("--cache-dir", type=Path, default=Path(__file__).resolve().parents[2] / ".cache/upstream")
    args = parser.parse_args(argv)
    manifest = json.loads(Path(__file__).with_name("upstream.json").read_text())
    records = selected_sources(manifest, args.group)
    try:
        for source in records:
            status = "PLAN_ONLY"
            if args.execute_fetch:
                status = fetch_one(args.cache_dir, source)
            elif args.verify_cache:
                verify_bytes(cache_path(args.cache_dir, source).read_bytes(), source)
                status = "CACHE_VERIFIED"
            print(json.dumps({"status": status, "source": source["url"], "cache_path": source["cache_path"], "sha256": source["sha256"]}))
    except (OSError, ValueError) as error:
        parser.exit(1, f"Source verification failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
