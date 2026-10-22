# Changelog

## 1.1.0 - 2026-10-22
- Mitigation checks follow the full PHP advisory: `memory_limit = -1`, `post_max_size`
  above 32M, `upload_max_filesize` not below `post_max_size`, and `fatal_error_backtraces`
  on PHP 8.5. Gaps are warnings only for builds that are still at risk.
- Next steps list every advisory mitigation and say they only reduce exposure.
- End-of-life wording mentions PHP's source-only back-ports for 7.4, 8.0 and 8.1.
- Log review window starts 17 Oct 2026, the first reported exploitation attempt.
- Note that Remi had no updates on release day.

## 1.0.1 - 2026-10-22
- Fix: the server scanner crashed on bash 3.2 (macOS, older distros); it no longer
  needs associative arrays and handles empty lists under `set -u`.
- Fix: at-risk Docker containers now count toward the verdict and exit code, and a host
  with PHP only in containers no longer reports "No PHP was found".
- Fix: the list of recently changed PHP files now works with BSD/macOS `find`.
- Homebrew update hint in the next steps.

## 1.0.0 - 2026-10-22
- First release.
- Server scanner: finds all PHP builds, checks versions against 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35,
  detects RPM and Debian back-ports, stale (not restarted) PHP processes, mod_php,
  interim mitigations, optional web-root, log and Docker review.
- Shared-hosting checker (`php2shell-check.php`) protected by an access key.
