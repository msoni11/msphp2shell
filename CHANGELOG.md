# Changelog

## 1.0.0 - 2026-10-22
- First release.
- Server scanner: finds all PHP builds, checks versions against 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35,
  detects RPM and Debian back-ports, stale (not restarted) PHP processes, mod_php,
  interim mitigations, optional web-root, log and Docker review.
- Shared-hosting checker (`php2shell-check.php`) protected by an access key.
