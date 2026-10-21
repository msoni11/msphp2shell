#!/usr/bin/env bash
# =============================================================================
# php2shell-check.sh
# Read-only exposure checker for PHP2Shell (CVE-2026-109618, CVE-2026-109619)
#
# What it does:
#   - Finds every PHP build on the host (CLI, PHP-FPM, CGI, mod_php, LiteSpeed,
#     cPanel EA-PHP, CloudLinux alt-php, Plesk, Remi, aaPanel, custom builds)
#   - Compares each version with the upstream fixed releases
#   - Looks for distro back-port evidence (RPM / Debian changelogs)
#   - Detects running PHP processes still using an old (replaced) binary
#   - Checks the interim mitigations from the PHP advisory
#   - Optionally reviews web roots, logs, and Docker containers
#   - Prints clear next steps
#
# What it does NOT do:
#   - It never sends exploit traffic and never tries to trigger the bug.
#   - It changes nothing on the system.
#
# Project:  https://github.com/msoni11/msphp2shell
# Issues:   https://github.com/msoni11/msphp2shell/issues
#
# References:
#   https://www.php.net/archive/2026.php#2026-10-21-5
#   https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
#   https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
#
# License: MIT (see LICENSE)
# =============================================================================

set -u

TOOL_VERSION="1.0.1"
CVE_RE='CVE-2026-10961[89]'

# Upstream fixed releases (PHP advisory, 2026-10-21)
FIXED_82="8.2.35"
FIXED_83="8.3.36"
FIXED_84="8.4.27"
FIXED_85="8.5.12"

# Files modified on/after this date in web roots are listed for review
REVIEW_SINCE="2026-10-15"

SCAN_DIRS=()
CHECK_DOCKER=0
CHECK_LOGS=1
USE_COLOR=1

# ---------------------------------------------------------------- arguments --
usage() {
  cat <<EOF
php2shell-check.sh v${TOOL_VERSION}  (https://github.com/msoni11/msphp2shell)
Read-only checker for PHP2Shell (CVE-2026-109618, CVE-2026-109619).

Usage: sudo ./php2shell-check.sh [options]

Options:
  --scan-dir DIR   Review a web root (repeatable): per-directory PHP settings
                   (.htaccess / .user.ini) and PHP files changed since ${REVIEW_SINCE}
  --docker         Also check PHP inside running Docker containers
  --no-logs        Skip the error-log review
  --no-color       Plain output (for logs / CI)
  -h, --help       Show this help

Exit codes: 0 = no at-risk PHP found, 1 = at-risk PHP found,
            2 = could not decide for some builds, 3 = no PHP found
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --scan-dir) shift; [ $# -gt 0 ] || { echo "--scan-dir needs a path" >&2; exit 64; }
                SCAN_DIRS+=("$1") ;;
    --docker)   CHECK_DOCKER=1 ;;
    --no-logs)  CHECK_LOGS=0 ;;
    --no-color) USE_COLOR=0 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 64 ;;
  esac
  shift
done

[ -t 1 ] || USE_COLOR=0
if [ "$USE_COLOR" -eq 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLU=$'\033[34m'
  BLD=$'\033[1m'; RST=$'\033[0m'
else
  RED=""; GRN=""; YEL=""; BLU=""; BLD=""; RST=""
fi

say()     { printf '%s\n' "$*"; }
header()  { printf '\n%s== %s ==%s\n' "$BLD" "$*" "$RST"; }
ok()      { printf '  %s[OK]%s %s\n' "$GRN" "$RST" "$*"; }
warn()    { printf '  %s[WARN]%s %s\n' "$YEL" "$RST" "$*"; }
bad()     { printf '  %s[RISK]%s %s\n' "$RED" "$RST" "$*"; }
info()    { printf '  %s[INFO]%s %s\n' "$BLU" "$RST" "$*"; }

run_to() {  # run with a timeout when available
  if command -v timeout >/dev/null 2>&1; then timeout 15 "$@"; else "$@"; fi
}

# Returns 0 if version $1 >= $2
ver_ge() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# ------------------------------------------------------- version decisions --
# Prints: FIXED | VULNERABLE | EOL | NEWER | UNKNOWN
classify_version() {
  local v="$1" mm
  mm="$(printf '%s' "$v" | cut -d. -f1,2)"
  case "$mm" in
    8.2) ver_ge "$v" "$FIXED_82" && echo FIXED || echo VULNERABLE ;;
    8.3) ver_ge "$v" "$FIXED_83" && echo FIXED || echo VULNERABLE ;;
    8.4) ver_ge "$v" "$FIXED_84" && echo FIXED || echo VULNERABLE ;;
    8.5) ver_ge "$v" "$FIXED_85" && echo FIXED || echo VULNERABLE ;;
    8.0|8.1|7.*|5.*) echo EOL ;;
    *)
      if [ -n "$v" ] && ver_ge "$v" "8.6.0"; then echo NEWER; else echo UNKNOWN; fi ;;
  esac
}

# Prints the version of a PHP binary or a mod_php shared object
php_version_of() {
  local f="$1" out
  case "$f" in
    *.so)
      out="$(grep -aoE 'X-Powered-By: PHP/[0-9]+\.[0-9]+\.[0-9]+' "$f" 2>/dev/null | head -n1)"
      printf '%s' "${out##*/}" ;;
    *)
      out="$(run_to "$f" -v 2>/dev/null | head -n1)"
      printf '%s' "$out" | grep -oE '^PHP [0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' ;;
  esac
}

php_sapi_of() {
  local f="$1"
  case "$f" in
    *.so) echo "apache2handler (mod_php)"; return ;;
  esac
  run_to "$f" -v 2>/dev/null | head -n1 | grep -oE '\((cli|fpm-fcgi|cgi-fcgi|litespeed|embed|phpdbg)\)' | tr -d '()' || true
}

# Prints where back-port evidence was found and returns 0, or returns 1
backport_evidence() {
  local f="$1" pkg doc
  if command -v rpm >/dev/null 2>&1; then
    pkg="$(rpm -qf "$f" 2>/dev/null | head -n1)"
    if [ -n "$pkg" ] && ! printf '%s' "$pkg" | grep -q 'not owned'; then
      if rpm -q --changelog "$pkg" 2>/dev/null | grep -Eq "$CVE_RE"; then
        echo "rpm changelog of $pkg"; return 0
      fi
    fi
  fi
  if command -v dpkg >/dev/null 2>&1; then
    pkg="$(dpkg -S "$f" 2>/dev/null | head -n1 | cut -d: -f1)"
    if [ -n "$pkg" ]; then
      for doc in "/usr/share/doc/$pkg/changelog.Debian.gz" \
                 "/usr/share/doc/${pkg%-*}-common/changelog.Debian.gz"; do
        if [ -r "$doc" ] && zgrep -Eq "$CVE_RE" "$doc" 2>/dev/null; then
          echo "Debian changelog of $pkg"; return 0
        fi
      done
    fi
  fi
  return 1
}

# Value of an ini setting as PHP itself reports it (CLI / FPM only)
ini_value() {
  local f="$1" key="$2"
  run_to "$f" -i 2>/dev/null | awk -F' => ' -v k="$key" '$1==k {print $3; exit}'
}

# --------------------------------------------------------------- discovery --
# Plain newline-separated lists instead of associative arrays, so the script
# also runs on bash 3.2 (macOS, old CentOS).
SEEN_LIST=$'\n'
TARGETS=()

in_list()  { case "$1" in *$'\n'"$2"$'\n'*) return 0 ;; esac; return 1; }

add_target() {
  local p="$1" real
  [ -e "$p" ] || return 0
  real="$(readlink -f "$p" 2>/dev/null || printf '%s' "$p")"
  [ -f "$real" ] || return 0
  case "$real" in *.so) ;; *) [ -x "$real" ] || return 0 ;; esac
  case "$(basename "$real")" in
    php-config*|phpize*|phpdbg*|php*.ini) return 0 ;;
  esac
  if ! in_list "$SEEN_LIST" "$real"; then
    SEEN_LIST="$SEEN_LIST$real"$'\n'
    TARGETS+=("$real")
  fi
}

discover() {
  local p
  shopt -s nullglob
  for p in php php-cgi php-fpm lsphp; do
    command -v "$p" >/dev/null 2>&1 && add_target "$(command -v "$p")"
  done
  for p in \
    /usr/bin/php /usr/bin/php[0-9]* /usr/bin/php-cgi* /usr/sbin/php-fpm* \
    /usr/local/bin/php /usr/local/bin/php-cgi /usr/local/sbin/php-fpm \
    /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm \
    /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
    /opt/alt/php*/usr/bin/php /opt/alt/php*/usr/sbin/php-fpm \
    /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm \
    /usr/local/lsws/lsphp*/bin/php /usr/local/lsws/lsphp*/bin/lsphp \
    /www/server/php/*/bin/php /www/server/php/*/sbin/php-fpm \
    /usr/local/php*/bin/php /usr/local/php*/sbin/php-fpm \
    /opt/homebrew/opt/php*/bin/php /usr/local/opt/php*/bin/php \
    /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so \
    /usr/lib/httpd/modules/libphp*.so /etc/httpd/modules/libphp*.so \
    /usr/local/apache*/modules/libphp*.so /usr/local/apache/modules/libphp*.so ; do
    add_target "$p"
  done
  shopt -u nullglob
}

# ------------------------------------------------------------------- start --
say "${BLD}php2shell-check v${TOOL_VERSION}${RST} - read-only check for CVE-2026-109618 / CVE-2026-109619"
say "Host: $(hostname 2>/dev/null)  |  $(date -u '+%Y-%m-%d %H:%M UTC')"
[ "$(id -u)" -eq 0 ] || say "${YEL}Tip: run with sudo for complete results (process, config and log checks).${RST}"

OS_ID=""; OS_LIKE=""
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  OS_ID="$(. /etc/os-release; echo "${ID:-}")"
  # shellcheck disable=SC1091
  OS_LIKE="$(. /etc/os-release; echo "${ID_LIKE:-}")"
fi

discover

COUNT_RISK=0; COUNT_UNKNOWN=0; COUNT_OK=0
MODPHP_FOUND=0; STALE_PROCS=0; UPLOAD_PROGRESS_ON=0
DOCKER_FOUND=0; DOCKER_RISK=0

# --------------------------------------------------------- 1. PHP builds ----
header "1. PHP builds on this host"
if [ "${#TARGETS[@]}" -eq 0 ]; then
  info "No PHP binaries found in common locations."
fi

for f in ${TARGETS[@]+"${TARGETS[@]}"}; do
  v="$(php_version_of "$f")"
  sapi="$(php_sapi_of "$f")"
  [ -n "$v" ] || { warn "$f - could not read version"; COUNT_UNKNOWN=$((COUNT_UNKNOWN+1)); continue; }
  status="$(classify_version "$v")"
  label="$f  (PHP $v${sapi:+, $sapi})"
  case "$sapi" in *mod_php*) MODPHP_FOUND=1 ;; esac

  case "$status" in
    FIXED)
      ok "$label - patched upstream release"; COUNT_OK=$((COUNT_OK+1)) ;;
    NEWER)
      ok "$label - newer than the fixed releases"; COUNT_OK=$((COUNT_OK+1)) ;;
    VULNERABLE|EOL)
      if ev="$(backport_evidence "$f")"; then
        ok "$label - vendor back-port found ($ev)"; COUNT_OK=$((COUNT_OK+1))
      elif [ "$status" = "EOL" ]; then
        bad "$label - end-of-life branch, no upstream fix exists; no vendor back-port found"
        COUNT_RISK=$((COUNT_RISK+1))
      else
        bad "$label - older than the fixed release for $(printf '%s' "$v" | cut -d. -f1,2); no vendor back-port found"
        COUNT_RISK=$((COUNT_RISK+1))
      fi ;;
    *)
      warn "$label - version not recognised, check manually"; COUNT_UNKNOWN=$((COUNT_UNKNOWN+1)) ;;
  esac
done

# --------------------------------------------- 2. What is serving traffic ---
header "2. Running PHP processes and web server"
if [ -d /proc ]; then
  EXE_SEEN=$'\n'; exe_count=0
  for pid in $(pgrep -f 'php|lsphp' 2>/dev/null); do
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" || continue
    case "$exe" in *php*) ;; *) continue ;; esac
    in_list "$EXE_SEEN" "$exe" && continue
    EXE_SEEN="$EXE_SEEN$exe"$'\n'; exe_count=$((exe_count+1))
    case "$exe" in
      *" (deleted)")
        bad "Process $pid runs a PHP binary that was replaced on disk: ${exe% (deleted)}"
        bad "  -> the update is installed but this service was NOT restarted"
        STALE_PROCS=1 ;;
      *)
        if ! in_list "$SEEN_LIST" "$exe"; then
          rv="$(php_version_of "$exe")"
          info "Running: $exe (PHP ${rv:-?}) - not in common paths, status: $(classify_version "${rv:-0}")"
        else
          info "Running: $exe"
        fi ;;
    esac
  done
  [ "$exe_count" -gt 0 ] || info "No running PHP processes visible (run with sudo to see all)."
fi

for ctl in apache2ctl apachectl httpd; do
  if command -v "$ctl" >/dev/null 2>&1; then
    mods="$(run_to "$ctl" -M 2>/dev/null)"
    if printf '%s' "$mods" | grep -Eqi 'php[0-9]*_module'; then
      MODPHP_FOUND=1
      bad "Apache loads mod_php ($ctl -M). PHP rates this the highest-risk setup."
    else
      info "Apache found ($ctl); mod_php not loaded."
    fi
    break
  fi
done

# ------------------------------------------------------ 3. Mitigations ------
header "3. Interim mitigations (from the PHP advisory)"
for f in ${TARGETS[@]+"${TARGETS[@]}"}; do
  case "$f" in *.so|*cgi*|*lsphp*) continue ;; esac
  up="$(ini_value "$f" session.upload_progress.enabled)"
  [ -n "$up" ] || continue
  ml="$(ini_value "$f" memory_limit)"
  pm="$(ini_value "$f" post_max_size)"
  case "$up" in
    On|on|1) UPLOAD_PROGRESS_ON=1
       warn "$f: session.upload_progress.enabled = On (advisory: turn Off)" ;;
    *) ok   "$f: session.upload_progress.enabled = Off" ;;
  esac
  info "$f: memory_limit = ${ml:-?}, post_max_size = ${pm:-?}"
done

shopt -s nullglob
POOL_FILES=( /etc/php-fpm.d/*.conf /etc/php/*/fpm/pool.d/*.conf \
             /etc/opt/remi/php*/php-fpm.d/*.conf /opt/remi/php*/root/etc/php-fpm.d/*.conf \
             /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf \
             /opt/plesk/php/*/etc/php-fpm.d/*.conf /usr/local/etc/php-fpm.d/*.conf \
             /www/server/php/*/etc/php-fpm.conf )
shopt -u nullglob
for pf in ${POOL_FILES[@]+"${POOL_FILES[@]}"}; do
  hits="$(grep -nE '^[[:space:]]*php_(admin_)?(value|flag)\[(session\.upload_progress\.enabled|memory_limit|post_max_size)\]' "$pf" 2>/dev/null)"
  [ -n "$hits" ] && info "FPM pool override in $pf:" && printf '%s\n' "$hits" | sed 's/^/        /'
done

# ---------------------------------------------------- 4. Web root review ----
if [ "${#SCAN_DIRS[@]}" -gt 0 ]; then
  header "4. Web root review"
  for d in "${SCAN_DIRS[@]}"; do
    [ -d "$d" ] || { warn "$d is not a directory"; continue; }
    info "Per-directory PHP settings in $d (invalid ones that raise warnings are an attack path):"
    find "$d" -xdev \( -name .htaccess -o -name .user.ini \) -type f 2>/dev/null \
      | while read -r h; do
          case "$(basename "$h")" in
            .htaccess) grep -qE '^[[:space:]]*php_(admin_)?(value|flag)' "$h" 2>/dev/null && printf '        %s\n' "$h" ;;
            .user.ini) [ -s "$h" ] && printf '        %s\n' "$h" ;;
          esac
        done | head -n 50
    n="$(find "$d" -xdev -type f -name '*.php' -newermt "$REVIEW_SINCE" 2>/dev/null | wc -l)"
    if [ "$n" -gt 0 ]; then
      warn "$n PHP file(s) in $d changed since $REVIEW_SINCE. Confirm they are your own deploys:"
      if find /dev/null -printf '' >/dev/null 2>&1; then
        find "$d" -xdev -type f -name '*.php' -newermt "$REVIEW_SINCE" -printf '        %TY-%Tm-%Td %TH:%TM  %u  %p\n' 2>/dev/null \
          | sort -r | head -n 25
      else  # BSD / macOS find
        find "$d" -xdev -type f -name '*.php' -newermt "$REVIEW_SINCE" \
          -exec stat -f '        %Sm  %Su  %N' -t '%Y-%m-%d %H:%M' {} + 2>/dev/null \
          | sort -r | head -n 25
      fi
    else
      ok "No PHP files in $d changed since $REVIEW_SINCE."
    fi
  done
fi

# --------------------------------------------------------- 5. Log review ----
if [ "$CHECK_LOGS" -eq 1 ]; then
  header "5. Error-log review (signal only, not proof)"
  shopt -s nullglob
  LOGS=( /var/log/php*fpm*.log /var/log/php-fpm/*.log /var/log/apache2/error.log \
         /var/log/httpd/error_log /var/log/nginx/error.log /usr/local/apache/logs/error_log \
         /usr/local/lsws/logs/error.log /www/wwwlogs/*.error.log )
  shopt -u nullglob
  found_logs=0
  for lf in ${LOGS[@]+"${LOGS[@]}"}; do
    [ -r "$lf" ] || continue
    found_logs=1
    c="$(grep -c 'Allowed memory size of' "$lf" 2>/dev/null || true)"
    s="$(grep -cE 'child [0-9]+ exited on signal (11|6)|SIGSEGV|Segmentation fault' "$lf" 2>/dev/null || true)"
    if [ "${c:-0}" -gt 0 ] || [ "${s:-0}" -gt 0 ]; then
      warn "$lf: ${c:-0} out-of-memory fatals, ${s:-0} worker crashes"
    else
      ok "$lf: no out-of-memory fatals or worker crashes"
    fi
  done
  [ "$found_logs" -eq 1 ] || info "No readable logs in common locations."
  info "The exploit path involves memory exhaustion and worker crashes. Bursts of these,"
  info "especially from upload (POST) requests since 20 Oct 2026, are worth investigating."
fi

# ------------------------------------------------------------- 6. Docker ----
if [ "$CHECK_DOCKER" -eq 1 ]; then
  header "6. Docker containers"
  if command -v docker >/dev/null 2>&1; then
    while read -r cid cname; do
      [ -n "$cid" ] || continue
      line="$(docker exec "$cid" sh -c 'php -v 2>/dev/null || php-fpm -v 2>/dev/null' 2>/dev/null | head -n1)"
      cv="$(printf '%s' "$line" | grep -oE '^PHP [0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}')"
      [ -n "$cv" ] || continue
      DOCKER_FOUND=$((DOCKER_FOUND+1))
      case "$(classify_version "$cv")" in
        FIXED|NEWER) ok   "$cname: PHP $cv" ;;
        *)           bad  "$cname: PHP $cv - rebuild from a patched base image and redeploy"
                     DOCKER_RISK=$((DOCKER_RISK+1)) ;;
      esac
    done < <(docker ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    [ "$DOCKER_FOUND" -gt 0 ] || info "No running containers with PHP found (or no access to docker)."
  else
    info "docker not found."
  fi
fi

# ------------------------------------------------------------ Summary -------
header "Result"
if [ "${#TARGETS[@]}" -eq 0 ] && [ "$DOCKER_FOUND" -eq 0 ]; then
  say "  No PHP was found. If PHP runs in containers, re-run with --docker."
  exit 3
fi

AT_RISK=0
{ [ "$COUNT_RISK" -gt 0 ] || [ "$STALE_PROCS" -eq 1 ] || [ "$DOCKER_RISK" -gt 0 ]; } && AT_RISK=1

if [ "$AT_RISK" -eq 1 ]; then
  msg="${COUNT_RISK} PHP build(s) need updating"
  [ "$STALE_PROCS" -eq 1 ] && msg="$msg; some services need a restart"
  [ "$DOCKER_RISK" -gt 0 ] && msg="$msg; ${DOCKER_RISK} container(s) need rebuilding"
  say "  ${RED}${BLD}AT RISK${RST}: $msg."
elif [ "$COUNT_UNKNOWN" -gt 0 ]; then
  say "  ${YEL}${BLD}NEEDS REVIEW${RST}: ${COUNT_UNKNOWN} build(s) could not be classified."
else
  say "  ${GRN}${BLD}PATCHED${RST}: every PHP build found has the fix."
  [ "${#TARGETS[@]}" -gt 0 ] || say "  (Only container PHP was found on this host.)"
fi

header "Next steps"
if [ "$COUNT_RISK" -gt 0 ]; then
  say "  1. Update PHP now. Upstream fixed releases: ${FIXED_85}, ${FIXED_84}, ${FIXED_83}, ${FIXED_82}."
  say "     PHP 5.x, 7.x, 8.0 and 8.1 get no upstream fix: move to a supported branch"
  say "     unless your OS vendor ships a back-port."
  if   [ -d /usr/local/cpanel ];  then say "     cPanel:      sudo dnf upgrade 'ea-php*'   (or yum)"; fi
  if   [ -d /opt/alt ];           then say "     CloudLinux:  sudo dnf upgrade 'alt-php*'  (or yum)"; fi
  if   [ -d /usr/local/psa ];     then say "     Plesk:       Tools & Settings > Updates, then confirm the PHP versions"; fi
  if   [ -d /www/server/panel ];  then say "     aaPanel:     update PHP from the App Store, then re-run this check"; fi
  case " $OS_ID $OS_LIKE " in
    *" debian "*|*" ubuntu "*) say "     Debian/Ubuntu: sudo apt update && sudo apt install --only-upgrade 'php*' 'libapache2-mod-php*'" ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" almalinux "*|*" rocky "*)
                               say "     RHEL family:   sudo dnf upgrade --refresh 'php*'   (Remi SCL: 'php8*-php*')" ;;
    *" alpine "*)              say "     Alpine:        apk update && apk upgrade" ;;
  esac
  if command -v brew >/dev/null 2>&1; then say "     Homebrew:      brew update && brew upgrade php"; fi
  say "     If your distro has not shipped a fix yet, apply step 3 now and watch its security feed."
fi
if [ "$AT_RISK" -eq 1 ]; then
  [ "$DOCKER_RISK" -gt 0 ] && say "  -  Containers: rebuild images from a patched php base image and redeploy."
  say "  2. Restart every PHP service so the new binary is loaded, e.g.:"
  say "       sudo systemctl restart 'php*-fpm.service'    and/or    sudo systemctl restart apache2 (or httpd)"
  say "  3. Until patched, apply the advisory's mitigations:"
  say "       - session.upload_progress.enabled = 0 in php.ini or the FPM pool (not ini_set/.user.ini)"
  say "       - remove invalid per-directory PHP settings (.htaccess / PHP_VALUE) that raise warnings"
  say "       - keep post_max_size low (8M without uploads, 32M with) and limit request size at the proxy"
  say "       - put a WAF in front if you can (e.g. Cloudflare ships managed rules); it does not replace patching"
  [ "$MODPHP_FOUND" -eq 1 ] && say "       - move off mod_php to PHP-FPM; mod_php is the most exposed setup"
  say "  4. Exploitation has been reported in the wild. Check for compromise:"
  say "       re-run with --scan-dir <webroot>, look for unknown PHP files, cron jobs and processes"
  say "       running as the web user, and treat secrets on an exposed server (DB passwords, API keys)"
  say "       as possibly leaked if you find anything."
  say "  5. Re-run this script to confirm."
else
  [ "$UPLOAD_PROGRESS_ON" -eq 1 ] && \
    say "  - Optional hardening: PHP suggests keeping session.upload_progress.enabled = 0 if you don't use it."
  say "  - Since exploitation was reported before patches were out, a quick --scan-dir review is still wise."
fi
say ""
say "Limits: version and changelog checks cannot see every vendor back-port. If a build is flagged"
say "but your vendor says it is patched, trust the vendor advisory and re-check later."
say "Wrong result? Report it: https://github.com/msoni11/msphp2shell/issues"

if [ "$AT_RISK" -eq 1 ]; then exit 1
elif [ "$COUNT_UNKNOWN" -gt 0 ]; then exit 2
else exit 0; fi
