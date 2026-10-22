<?php
/**
 * php2shell-check.php - PHP2Shell (CVE-2026-109618 / CVE-2026-109619) check
 * for shared hosting where you have no SSH access.
 *
 *   1. Change ACCESS_KEY below to a long random string.
 *   2. Upload this file to your site (any name, e.g. check-8f3k2.php).
 *   3. Open  https://your-site/check-8f3k2.php?key=YOUR_KEY
 *   4. DELETE THE FILE when you are done.
 *
 * Read-only. It sends no exploit traffic and changes nothing.
 * Written to run on old PHP (5.4+) too, since those are the most exposed.
 * Project: https://github.com/msoni11/msphp2shell
 * Help:    ms@taketwotechnologies.com
 * License: MIT
 */

define('ACCESS_KEY', 'change-me');

$given = isset($_GET['key']) ? (string) $_GET['key'] : '';
if (ACCESS_KEY === 'change-me' || strlen($given) !== strlen(ACCESS_KEY) || $given !== ACCESS_KEY) {
    header('HTTP/1.1 404 Not Found');
    exit;
}

header('Content-Type: text/plain; charset=utf-8');
header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');

$fixed = array('8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12');
$v     = PHP_VERSION;
$mm    = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
$sapi  = php_sapi_name();

if (isset($fixed[$mm])) {
    $status = version_compare($v, $fixed[$mm], '>=') ? 'PATCHED' : 'AT RISK (by version number - see step 2)';
} elseif (version_compare($v, '8.6.0', '>=')) {
    $status = 'PATCHED';
} else {
    $status = 'AT RISK (end-of-life branch, no official PHP release fixes it)';
}

$upload = ini_get('session.upload_progress.enabled');
$uploadOn = in_array(strtolower((string) $upload), array('1', 'on'), true);

echo "PHP2Shell check (CVE-2026-109618 / CVE-2026-109619)\n";
echo str_repeat('=', 52) . "\n\n";
echo "PHP version   : $v\n";
echo "Server API    : $sapi" . ($sapi === 'apache2handler' ? '  <- mod_php, highest-risk setup' : '') . "\n";
echo "Status        : $status\n\n";

echo "Settings\n";
echo "  session.upload_progress.enabled = " . ($uploadOn ? 'On   <- advisory: turn Off' : 'Off') . "\n";
if (PHP_MAJOR_VERSION == 8 && PHP_MINOR_VERSION == 5) {
    $fb = in_array(strtolower((string) ini_get('fatal_error_backtraces')), array('1', 'on'), true);
    echo "  fatal_error_backtraces          = " . ($fb ? 'On   <- advisory: turn Off' : 'Off') . "\n";
}
echo "  memory_limit                    = " . ini_get('memory_limit') . (ini_get('memory_limit') === '-1' ? '' : '   <- advisory: -1 (ask your host)') . "\n";
echo "  post_max_size                   = " . ini_get('post_max_size') . "\n";
echo "  upload_max_filesize             = " . ini_get('upload_max_filesize') . "\n\n";

echo "What to do\n";
if (strpos($status, 'AT RISK') === 0) {
    echo "  1. In your hosting panel, switch this site to a patched PHP version\n";
    echo "     (fixed releases: 8.5.12, 8.4.27, 8.3.36, 8.2.35 or newer).\n";
    echo "     cPanel: 'MultiPHP Manager' or 'Select PHP Version'. Plesk: 'PHP Settings'.\n";
    echo "  2. Some hosts back-port the fix without changing the version number\n";
    echo "     (e.g. CloudLinux alt-php, distro packages). Ask your host:\n";
    echo "     \"Is PHP on my account patched for CVE-2026-109618 and CVE-2026-109619?\"\n";
    echo "  3. If your panel allows php.ini options, set session.upload_progress.enabled = Off.\n";
    echo "     Do not rely on ini_set() or .user.ini for this; the advisory says they apply too late.\n";
    echo "     On PHP 8.5 also set fatal_error_backtraces = Off. These only reduce exposure;\n";
    echo "     updating is the only complete fix.\n";
    echo "  4. Check for unknown .php files in your site folders and change database and\n";
    echo "     admin passwords if you find anything unexpected.\n";
} else {
    echo "  Your PHP version includes the fix.\n";
    if ($uploadOn) {
        echo "  Optional: turn session.upload_progress.enabled Off if your site does not use it.\n";
    }
}
echo "\nWrong result? https://github.com/msoni11/msphp2shell/issues  |  Need help? ms@taketwotechnologies.com\n";
echo "\n>>> Now DELETE this file from your server. <<<\n";
