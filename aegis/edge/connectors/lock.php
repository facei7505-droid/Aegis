<?php
/*
 * Aegis Щит: origin lock.
 * Accepts only requests that came through Aegis (signed X-Aegis-Auth header), and takes the visitor's
 * real address from X-Real-Ip once the signature checks out. Requests from this server itself and
 * command-line scripts (cron, WP-CLI, Bitrix agents) are always allowed.
 *
 * AEGIS_LOCK: 'enforce' refuses unsigned requests (403), 'report' only marks them, 'off' does nothing.
 * The algorithm is aegis/shield/signing.py; keep the two in step.
 */
if (!defined('AEGIS_SECRET')) { define('AEGIS_SECRET', '{{SECRET}}'); }
if (!defined('AEGIS_LOCK')) { define('AEGIS_LOCK', '{{MODE}}'); }
if (!defined('AEGIS_TRUST_LOCAL')) { define('AEGIS_TRUST_LOCAL', true); }  // this server's own requests pass

if (!function_exists('aegis_canonical_host')) {
    function aegis_canonical_host($host) {
        $host = strtolower(trim((string)$host));
        if ($host !== '' && $host[0] === '[') {
            return substr($host, 0, strpos($host, ']') + 1);
        }
        if (substr_count($host, ':') === 1) {
            $host = substr($host, 0, strrpos($host, ':'));
        }
        return $host;
    }

    function aegis_origin_ok() {
        $value = isset($_SERVER['HTTP_X_AEGIS_AUTH']) ? (string)$_SERVER['HTTP_X_AEGIS_AUTH'] : '';
        $parts = explode('.', $value);
        if (count($parts) !== 3 || $parts[0] !== 'v1' || !ctype_digit($parts[1])) {
            return false;
        }
        $ts = (int)$parts[1];
        if (abs(time() - $ts) > 300) {
            return false;
        }
        $ip = isset($_SERVER['HTTP_X_REAL_IP']) ? (string)$_SERVER['HTTP_X_REAL_IP'] : '';
        $host = aegis_canonical_host(isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '');
        return hash_equals(hash_hmac('sha256', "v1|$ts|$host|$ip", AEGIS_SECRET), $parts[2]);
    }

    function aegis_is_local() {
        if (PHP_SAPI === 'cli') {
            return true;
        }
        $addr = isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '';
        if ($addr === '::1' || strpos($addr, '127.') === 0) {
            return true;
        }
        return isset($_SERVER['SERVER_ADDR']) && $addr === $_SERVER['SERVER_ADDR'];
    }

    function aegis_lock() {
        if (AEGIS_LOCK === 'off' || AEGIS_SECRET === '' || PHP_SAPI === 'cli') {
            return;
        }
        if (aegis_origin_ok()) {
            $ip = (string)$_SERVER['HTTP_X_REAL_IP'];
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $_SERVER['REMOTE_ADDR'] = $ip;
            }
            if (!headers_sent()) {
                header('X-Aegis-Connector: ok');
            }
            return;
        }
        $signed = isset($_SERVER['HTTP_X_AEGIS_AUTH']);
        if (!headers_sent() && $signed) {
            header('X-Aegis-Connector: bad-signature');  // wrong secret or clock: `aegis edge connector --verify`
        }
        if (AEGIS_LOCK !== 'enforce' || (AEGIS_TRUST_LOCAL && aegis_is_local())) {
            return;
        }
        if (!headers_sent()) {
            http_response_code(403);
            header('X-Aegis-Connector: refused');
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store');
        }
        echo '<!doctype html><meta charset="utf-8"><title>403</title>'
            . '<p style="font:16px sans-serif;margin:3em">Доступ к сайту только через защиту. '
            . 'Access goes through the site\'s protection only.</p>';
        exit;
    }
}

aegis_lock();
