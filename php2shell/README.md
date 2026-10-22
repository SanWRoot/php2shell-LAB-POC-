# php2shell

Reproducible HTTP proof of concept for the PHP request-state vulnerabilities
tracked as CVE-2026-109618 and CVE-2026-109619. The verified chain leaks the
Zend MM heap base, leaks the loaded `libphp` base, and executes a short command
through `zif_system`.

The default command writes a random proof file into a web-readable application
directory, fetches it over HTTP, and succeeds only when the response contains
`uid=`. No helper PHP file is installed on the target.

![Verified WordPress proof](docs/screenshots/wordpress-proof.png)

The screenshot above was rendered from the retained
[`docs/evidence/wordpress-proof.txt`](docs/evidence/wordpress-proof.txt) output
of a clean build of `lab/8.4.26/wordpress`.

## Quick start

Requirements:

- Docker with Compose support;
- Python 3.11 or newer, using only the standard library;
- an x86-64 host with enough memory for a 140 MiB request body;
- loopback access to the selected lab port.

```bash
git clone https://github.com/dimasma0305/php2shell.git
cd php2shell

docker compose -f lab/8.4.26/wordpress/compose.yaml up -d --build
./poc.py --url http://127.0.0.1:18173/
```

On Windows, use `python poc.py --url http://127.0.0.1:18173/`.

A successful run ends with output similar to:

```text
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The PoC prints `REMOTE_PROOF_REMAINS` with the random proof path so it can be
removed after the run.

## Labs

Every fixture under `lab/` has a retained successful `PROOF: uid=...` run.
Negative compatibility experiments and uncalibrated applications are not
shipped as labs.

### WordPress

This is the main end-to-end fixture. It uses the exact affected PHP image,
WordPress commit `fc9832bef919c2a08541248db23af90d14ffb082`, and a deterministic
MariaDB seed.

```bash
docker compose -f lab/8.4.26/wordpress/compose.yaml up -d --build
./poc.py --url http://127.0.0.1:18173/
docker compose -f lab/8.4.26/wordpress/compose.yaml down -v
```

The PHP files are converted to the CRLF representation used during layout
calibration. This is part of the fixture because PHP parser allocations affect
the application heap shape.

### MediaWiki

The MediaWiki fixture uses the bundled, directly reachable Scribunto constants
file and writes proof under the default writable `images/` directory. A full
MediaWiki installation or database is not required for this route.

```bash
docker build -t php2shell-mediawiki lab/8.4.26/mediawiki
docker run --rm -d --name php2shell-mediawiki \
  -p 127.0.0.1:18081:80 php2shell-mediawiki
./poc.py --url http://127.0.0.1:18081/
```

The verified run is retained in
[`docs/evidence/mediawiki-proof.txt`](docs/evidence/mediawiki-proof.txt).

### DokuWiki

This fixture copies unmodified DokuWiki `2026-07-14c` application files from
the pinned official image onto the affected PHP runtime. It materializes the
official image's storage layout during the build, so no volume or setup wizard
is required.

```bash
docker build -t php2shell-dokuwiki lab/8.4.26/dokuwiki
docker run --rm -d --name php2shell-dokuwiki \
  -p 127.0.0.1:18083:80 php2shell-dokuwiki
./poc.py --url http://127.0.0.1:18083/
```

Two clean-container reproductions are retained in
[`docs/evidence/dokuwiki-proof.txt`](docs/evidence/dokuwiki-proof.txt) and
[`docs/evidence/dokuwiki-proof-run2.txt`](docs/evidence/dokuwiki-proof-run2.txt).

### Joomla

This fixture copies the Joomla `6.1.4` tree from the pinned official image,
adds the PHP extensions required by its installer, and serves the ordinary
installer route from the affected PHP runtime. It does not install a helper
endpoint or a proof reader.

```bash
docker build -t php2shell-joomla lab/8.4.26/joomla
docker run --rm -d --name php2shell-joomla \
  -p 127.0.0.1:18086:80 php2shell-joomla
./poc.py --url http://127.0.0.1:18086/
```

Two clean-container reproductions are retained in
[`docs/evidence/joomla-proof.txt`](docs/evidence/joomla-proof.txt) and
[`docs/evidence/joomla-proof-run2.txt`](docs/evidence/joomla-proof-run2.txt).

The current upstream DokuWiki and Joomla images use fixed PHP releases. These
fixtures intentionally combine their pinned application files with the exact
affected `php:8.4.26-apache` image; they do not claim that a current default
deployment of either application remains vulnerable.

### Bare PHP/Apache

The smallest fixture has a plain PHP endpoint with no `session_start()` and no
framework:

```bash
docker build -t php2shell-php-apache lab/8.4.26/php-apache
docker run --rm -d --name php2shell-php-apache \
  -p 127.0.0.1:18082:80 php2shell-php-apache
./poc.py --url http://127.0.0.1:18082/
```

The verified run is retained in
[`docs/evidence/php-apache-proof.txt`](docs/evidence/php-apache-proof.txt).

## Exploitation prerequisites

The included profile is deliberately narrow. All of these properties are part
of the verified environment:

- official `php:8.4.26-apache` image digest
  `sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a`;
- Debian Trixie x86-64 `libphp.so` SHA-256
  `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c`;
- Apache prefork with `mod_php`, preserving one producer/consumer pair on one
  keep-alive connection;
- stock PHP limits, including `memory_limit=128M`, `post_max_size=8M`, and
  enabled Session upload progress;
- chunked request bodies reaching Apache without proxy or WAF normalization;
- a tested application route whose allocations preserve the calibrated heap
  layout;
- a writable, web-readable output path for automatic HTTP proof.

PHP version alone is insufficient. Distribution patches, compiler flags,
loaded modules, SAPI, application source, configuration strings, and proxy
behavior can change the required layout. Unknown or ambiguous fingerprints
fail closed.

PHP 8.4.27 and PHP 8.5.12 contain the vendor fixes and are negative controls,
not supported targets.

## Profile registry

[`profiles.json`](profiles.json) separates:

1. exact binary identity and exported ELF symbol offsets;
2. heap-layout constants;
3. runtime configuration and its HTTP fingerprint.

Useful inspection commands:

```bash
./poc.py --list-builds
./poc.py --list-profiles
./poc.py --inspect-libphp /path/to/libphp.so
./poc.py --url http://127.0.0.1:18173/ --check-profile
```

`--inspect-libphp` maps binary symbols but does not infer a heap layout. A new
build is usable only after its SAPI, configuration, and application route have
been reproduced and calibrated independently.

### Candidate symbol maps

The registry also contains exact `libphp.so` identities and symbol offsets for
collected official Apache builds:

- PHP 7.0.33, 7.1.33, 7.2.34, 7.3.33, and 7.4.33 EOL final releases;
- PHP 8.2.34;
- PHP 8.3.35;
- PHP 8.4.26;
- PHP 8.5.11.

Only PHP 8.4.26 currently has calibrated heap layouts. A build entry with zero
profiles is a symbol map, not an exploitability claim. The normal `auto` mode
continues to reject it.

For an isolated lab with a known compatible layout but an unknown exact
`libphp.so`, apply one candidate explicitly:

```bash
./poc.py --url http://127.0.0.1:18086/ \
  --profile-id official-php-8.4.26-apache-trixie-stock-preapp \
  --build-id official-php-8.4.26-apache-trixie-amd64
```

Or try the recorded official symbol maps in sequence and stop at the first
self-verified proof:

```bash
python scripts/try_builds.py \
  --url http://127.0.0.1:18086/ \
  --profile-id official-php-8.4.26-apache-trixie-stock-preapp \
  --all-builds --retries 3
```

A verified batch run is retained in
[`docs/evidence/candidate-build-proof.txt`](docs/evidence/candidate-build-proof.txt).

Wrong symbol or layout candidates normally terminate an Apache worker. The
batch helper is bounded and explicit for this reason; it is not part of the
default URL-only path.

To collect another official `linux/amd64` Apache image without committing the
binary itself:

```bash
python scripts/collect_official_builds.py 8.4.25-apache --write
```

The collector pins the image digest, discovers and copies the loaded `libphp`
module from a temporary container, hashes it, extracts `zif_system` and the
logical zval destructor, merges the mapping, and removes the temporary binary
and container. PHP 7 exports that destructor as `_zval_ptr_dtor`; the registry
normalizes it under `zval_ptr_dtor`.

## Repository layout

```text
.
├── poc.py
├── profiles.json
├── README.md
├── scripts/
│   ├── collect_official_builds.py
│   └── try_builds.py
├── docs/
│   ├── evidence/
│   └── screenshots/
└── lab/
    └── 8.4.26/
        ├── php-apache/Dockerfile
        ├── wordpress/
        │   ├── Dockerfile
        │   ├── compose.yaml
        │   └── src/
        ├── mediawiki/Dockerfile
        ├── dokuwiki/Dockerfile
        └── joomla/Dockerfile
```

## References

- [PHP security release, 21 October 2026](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CVE-2026-109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Upstream PHP 8.5.11 to 8.5.12 diff](https://github.com/php/php-src/compare/php-8.5.11...php-8.5.12)
- [Calif: PHP use-after-free research](https://calif.io/research/php-uaf)
- [Calif: php2shell](https://calif.io/php2shell/)

Use the PoC only against systems you own or are explicitly authorized to test.
