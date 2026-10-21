# Contributing

Contributions are welcome, especially new PHP install locations and distro back-port detection.

- Keep the scanner read-only: no exploit attempts, no system changes.
- `php2shell-check.sh` must pass `shellcheck -S warning`.
- `php2shell-check.php` must stay compatible with PHP 5.4+ (old servers are the ones at risk).
- When PHP ships new fixed releases, update `FIXED_*` in the `.sh` file and `$fixed` in the `.php` file,
  and add a CHANGELOG entry.
- If you report a wrong result, include your OS, PHP package name and version, and the script output.
