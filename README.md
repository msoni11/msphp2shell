# msphp2shell

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)


A free, **read-only** checker that tells you whether your server is exposed to
**PHP2Shell** (CVE-2026-109618 and CVE-2026-109619), and what to do next.

PHP2Shell is a pair of critical flaws in the PHP runtime itself, disclosed on
21 October 2026. An attacker can run code on a web server with nothing more than
crafted HTTP requests, with no login and often before your application code
even runs. It affects PHP 5.4 through 8.5, under PHP-FPM, mod_php, CGI,
LiteSpeed and FrankenPHP alike. Exploitation in the wild has been reported.

**Fixed upstream in:** PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35.
PHP 5.x, 7.x, 8.0 and 8.1 get no upstream fix.

## What this tool does

- Finds every PHP build on the host: system PHP, PHP-FPM, CGI, mod_php,
  LiteSpeed `lsphp`, cPanel EA-PHP, CloudLinux alt-php, Plesk, Remi, aaPanel,
  Homebrew and custom builds, plus binaries of running PHP processes.
- Compares each version with the fixed releases.
- Detects **vendor back-ports** (for example, Ubuntu and AlmaLinux patch the
  bug without changing the version number) by reading RPM and Debian changelogs.
- Flags PHP services that were updated on disk but **never restarted**.
- Detects mod_php, the highest-risk setup.
- Checks the advisory's interim mitigations (`session.upload_progress.enabled`,
  `post_max_size`, FPM pool overrides).
- Optionally reviews web roots, error logs and Docker containers.
- Prints a clear verdict and next steps for your distro or control panel.

## What it does NOT do

It never sends exploit traffic, never tries to trigger the bug, and changes
nothing on your system. Read the script before running it; it is one file.

## Quick start (servers with SSH)

Download just the script:

```bash
curl -fsSLO https://raw.githubusercontent.com/msoni11/msphp2shell/main/php2shell-check.sh
less php2shell-check.sh            # review it first
chmod +x php2shell-check.sh
sudo ./php2shell-check.sh
```

Or clone the repository:

```bash
git clone https://github.com/msoni11/msphp2shell.git
cd msphp2shell
sudo ./php2shell-check.sh
```

Recommended full run:

```bash
sudo ./php2shell-check.sh --scan-dir /var/www --docker
```

| Option | Purpose |
| --- | --- |
| `--scan-dir DIR` | List per-directory PHP settings and PHP files changed since 15 Oct 2026 (repeatable) |
| `--docker` | Check PHP inside running containers |
| `--no-logs` | Skip the error-log review |
| `--no-color` | Plain output for logs and CI |

**Exit codes** (useful for Ansible, cron or CI): `0` patched, `1` at risk,
`2` needs manual review, `3` no PHP found.

Fleet example: `for h in $(cat hosts); do ssh "$h" 'sudo bash -s -- --no-color' < php2shell-check.sh > "$h.txt"; done`

## Shared hosting (no SSH)

Use [`php2shell-check.php`](https://github.com/msoni11/msphp2shell/blob/main/php2shell-check.php)
(download it from the repo, or [raw](https://raw.githubusercontent.com/msoni11/msphp2shell/main/php2shell-check.php)):

1. Open it and change `ACCESS_KEY` to a long random string.
2. Upload it under a hard-to-guess name.
3. Visit `https://your-site/<file>.php?key=<your key>`.
4. **Delete it afterwards.**

Without the right key the file returns a 404. It cannot see vendor back-ports,
so if it says "at risk", ask your host whether they have patched PHP for both CVEs.

## Reading the results

| Verdict | Meaning | Action |
| --- | --- | --- |
| `[OK] patched upstream release` | Version includes the fix | None |
| `[OK] vendor back-port found` | Your distro patched an older version number | None |
| `[RISK] older than the fixed release` | Vulnerable | Update and restart |
| `[RISK] end-of-life branch` | 5.x / 7.x / 8.0 / 8.1, no upstream fix | Move to a supported branch, or confirm a vendor back-port |
| `[RISK] binary was replaced on disk` | Update installed, service still running the old code | Restart PHP-FPM / Apache |
| `[WARN] session.upload_progress.enabled = On` | One confirmed attack path is open | Turn it off in `php.ini` or the FPM pool |

## Next steps if you are at risk

1. **Update PHP** through your OS or control panel; the script prints the command.
2. **Restart** every PHP service (`php*-fpm`, `apache2`/`httpd`, `lsws`).
3. **Until patched**, apply the advisory's mitigations:
   `session.upload_progress.enabled = 0` (in `php.ini` or the FPM pool,
   not `ini_set()` or `.user.ini`), remove invalid per-directory PHP settings
   that raise warnings, keep `post_max_size` low, and move off mod_php. A WAF
   helps but does not replace patching.
4. **Check for compromise**, since attacks began before patches shipped:
   unknown PHP files, cron jobs, or processes running as the web user. If you
   find any, rotate database passwords and API keys, and consider rebuilding.
5. **Re-run** the script to confirm.

## Found a wrong result?

Distro back-ports vary a lot. If the script says "at risk" on a patched server (or the
reverse), please [open a "Wrong result" issue](https://github.com/msoni11/msphp2shell/issues/new?template=wrong-result.md)
with your OS and PHP package details. Pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Need help?

If you need help reading the results or fixing an at-risk server, email
[ms@taketwotechnologies.com](mailto:ms@taketwotechnologies.com).

## Limitations

- Version and changelog checks cannot see every vendor back-port. If a build is
  flagged but your vendor's advisory says it is fixed, trust the vendor.
- The log and file reviews are signals, not proof of compromise or of safety.
- PHP inside containers is checked by version only; rebuild images from patched bases.

## References

- PHP security advisory: https://www.php.net/archive/2026.php#2026-10-21-5
- CVE-2026-109618: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- CVE-2026-109619: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- AlmaLinux guidance and mitigations: https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/

## License

[MIT](LICENSE). Provided as-is, with no warranty. This is not an official PHP project.
Security issues with this tool: see [SECURITY.md](SECURITY.md).
