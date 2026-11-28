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
        $host = strtr(trim((string)$host, " \t\n\r\0\x0B"), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
        if ($host !== '' && $host[0] === '[') {
            $end = strpos($host, ']');
            return $end === false ? $host : substr($host, 0, $end + 1);
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
        $method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? (string)$_SERVER['REQUEST_METHOD'] : 'GET');
        $uri = isset($_SERVER['REQUEST_URI']) ? (string)$_SERVER['REQUEST_URI'] : '/';
        // Bound to the request line: a signature that leaks (phpinfo shows headers) opens only that request.
        return hash_equals(hash_hmac('sha256', "v1|$ts|$host|$ip|$method|$uri", AEGIS_SECRET), $parts[2]);
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
     * signed, fresh X-Aegis-Failover token; until it runs out (renewed while Aegis stays down) visitors
     * are let in directly, so the site keeps working without protection. When Aegis is back, a "close"
     * token ends it at once. Tokens only move forward: an old "open" replayed after a "close" is refused.
     * The state file sits next to this one (not in a shared /tmp), is a .php that prints nothing, and is
     * signed, so neither another hosting account nor a visitor can open the site.
     */
    function aegis_failover_file() {
        return __DIR__ . '/.aegis-failover-' . substr(hash('sha256', 'file|' . AEGIS_SECRET), 0, 16) . '.php';
    }

    function aegis_failover_state() {
        $raw = @file_get_contents(aegis_failover_file());
        if (!is_string($raw) || !preg_match('/(\d+)\.(\d+)\.([0-9a-f]{64})\s*$/', $raw, $m)) {
            return array(0, 0);
        }
        if (!hash_equals(hash_hmac('sha256', 'state|' . $m[1] . '|' . $m[2], AEGIS_SECRET), $m[3])) {
            return array(0, 0);
        }
        return array((int)$m[1], (int)$m[2]);  // until, issued
    }

    function aegis_failover() {
        if (isset($_SERVER['HTTP_X_AEGIS_FAILOVER'])) {
            $parts = explode('.', (string)$_SERVER['HTTP_X_AEGIS_FAILOVER']);
            $host = aegis_canonical_host(isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '');
            $answer = 'bad-signature';
            if (count($parts) === 4 && $parts[0] === 'v1' && ctype_digit($parts[1]) && ctype_digit($parts[2])) {
                $until = (int)$parts[1];
                $issued = (int)$parts[2];
                $fresh = abs(time() - $issued) <= 300 && ($until === 0 || ($until > time() && $until <= $issued + 86400));
                $mac = hash_hmac('sha256', "failover|$until|$issued|$host", AEGIS_SECRET);
                if ($fresh && hash_equals($mac, $parts[3])) {
                    list(, $last) = aegis_failover_state();
                    if ($issued <= $last) {
                        $answer = 'failover-stale';
                    } else {
                        $state = '<' . "?php exit; ?" . ">\n$until.$issued." . hash_hmac('sha256', "state|$until|$issued", AEGIS_SECRET);
                        $ok = @file_put_contents(aegis_failover_file(), $state, LOCK_EX) !== false;
                        $answer = !$ok ? 'failover-unwritable' : ($until ? 'failover-open' : 'failover-closed');
                    }
                }
            }
            if (!headers_sent()) {
                header('X-Aegis-Connector: ' . $answer);
            }
            if ($answer !== 'bad-signature') {
                echo $answer;
                exit;
            }
            return false;
        }
        list($until) = aegis_failover_state();
        return $until > time();
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
