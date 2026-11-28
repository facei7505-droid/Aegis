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

    /*
     * Failover: when Aegis is down, the watchdog points DNS straight at this server and first sends a
     * signed X-Aegis-Failover token. Until it runs out (at most a day; the watchdog renews it while
     * Aegis stays down) visitors are let in directly, so the site keeps working without protection.
     */
    function aegis_failover_flag() {
        return rtrim(sys_get_temp_dir(), '/\\') . '/aegis-open-' . substr(hash('sha256', AEGIS_SECRET), 0, 16);
    }

    function aegis_failover() {
        if (isset($_SERVER['HTTP_X_AEGIS_FAILOVER'])) {
            $parts = explode('.', (string)$_SERVER['HTTP_X_AEGIS_FAILOVER']);
            $host = aegis_canonical_host(isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '');
            $ok = count($parts) === 3 && $parts[0] === 'v1' && ctype_digit($parts[1])
                && (int)$parts[1] > time() && (int)$parts[1] <= time() + 86400
                && hash_equals(hash_hmac('sha256', 'failover|' . (int)$parts[1] . '|' . $host, AEGIS_SECRET), $parts[2]);
            if (!headers_sent()) {
                header('X-Aegis-Connector: ' . ($ok ? 'failover-open' : 'bad-signature'));
            }
            if ($ok) {
                @file_put_contents(aegis_failover_flag(), (string)(int)$parts[1], LOCK_EX);
                echo 'failover-open';
                exit;
            }
            return false;
        }
        $flag = aegis_failover_flag();
        return is_file($flag) && (int)@file_get_contents($flag) > time();
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
        if (aegis_failover()) {
            return;  // Aegis is down: the site stays open (without the visitor address from Aegis)
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
