#!/usr/bin/env python3
"""Collect exact symbol maps from pinned local PHP Apache Docker images."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from poc import parse_elf_symbol_offsets  # noqa: E402


def run(*argv: str) -> str:
    completed = subprocess.run(
        argv,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def collect(tag: str) -> tuple[str, dict[str, object]]:
    image = f"php:{tag}"
    run("docker", "pull", image)

    inspect = json.loads(run("docker", "image", "inspect", image))[0]
    if inspect.get("Architecture") != "amd64" or inspect.get("Os") != "linux":
        raise RuntimeError(f"{image} is not a linux/amd64 image")
    digests = inspect.get("RepoDigests") or []
    digest = next((value for value in digests if value.startswith("php@")), "")
    if not digest:
        raise RuntimeError(f"{image} has no immutable php@sha256 RepoDigest")

    version = run("docker", "run", "--rm", image, "php", "-r", "echo PHP_VERSION;")
    codename = run(
        "docker",
        "run",
        "--rm",
        image,
        "sh",
        "-c",
        ". /etc/os-release; "
        "if [ -n \"$VERSION_CODENAME\" ]; then printf %s \"$VERSION_CODENAME\"; "
        "else printf %s \"$VERSION\" | sed -n 's/.*(\\([^)]*\\)).*/\\1/p'; fi",
    )
    if not codename:
        raise RuntimeError(f"cannot determine distribution codename from {image}")
    apache_output = run("docker", "run", "--rm", image, "apache2", "-v")
    match = re.search(r"^Server version:\s*(.+)$", apache_output, re.MULTILINE)
    if not match:
        raise RuntimeError(f"cannot parse Apache version from {image}")

    libphp_path = run(
        "docker",
        "run",
        "--rm",
        image,
        "sh",
        "-c",
        "grep -RhsE '^[[:space:]]*LoadModule[[:space:]]+php[^[:space:]]*_module[[:space:]]+' "
        "/etc/apache2 2>/dev/null | awk 'NR == 1 { print $3 }'",
    )
    if not libphp_path.startswith("/"):
        raise RuntimeError(f"cannot discover absolute libphp module path from {image}")

    container = f"php2shell-map-{uuid.uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory(prefix="php2shell-map-") as directory:
        local_libphp = Path(directory) / "libphp.so"
        try:
            run("docker", "create", "--name", container, image)
            run("docker", "cp", f"{container}:{libphp_path}", str(local_libphp))
            libphp_sha256, symbols = parse_elf_symbol_offsets(local_libphp)
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )

    build_id = f"official-php-{version}-apache-{codename}-amd64"
    return build_id, {
        "php_header": f"PHP/{version}",
        "server_header": match.group(1),
        "image_digest": digest.removeprefix("php@"),
        "libphp_path": libphp_path,
        "libphp_sha256": libphp_sha256,
        "symbols": {
            "zif_system": f"0x{symbols['zif_system']:x}",
            "zval_ptr_dtor": f"0x{symbols['zval_ptr_dtor']:x}",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tags", nargs="+", help="official tags such as 8.4.26-apache")
    parser.add_argument(
        "--profiles-file",
        type=Path,
        default=ROOT / "profiles.json",
        help="registry to read and optionally update",
    )
    parser.add_argument("--write", action="store_true", help="merge into the registry")
    parser.add_argument(
        "--replace",
        action="store_true",
        help="replace an existing build only when its exact metadata changed",
    )
    args = parser.parse_args()

    registry = json.loads(args.profiles_file.read_text(encoding="utf-8"))
    builds = registry.get("builds")
    if registry.get("schema_version") != 1 or not isinstance(builds, dict):
        raise RuntimeError("unsupported profile registry")

    collected: dict[str, dict[str, object]] = {}
    for tag in args.tags:
        build_id, mapping = collect(tag)
        existing = builds.get(build_id)
        if existing is not None and existing != mapping and not args.replace:
            raise RuntimeError(
                f"{build_id} already exists with different metadata; use --replace"
            )
        collected[build_id] = mapping
        if args.write:
            builds[build_id] = mapping

    if args.write:
        args.profiles_file.write_text(
            json.dumps(registry, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        print(f"updated {args.profiles_file} with {len(collected)} build(s)")
    else:
        print(json.dumps(collected, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
