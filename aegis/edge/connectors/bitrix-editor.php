<?php
/*
 * Aegis Щит for 1C-Bitrix: editor pass. Include from /bitrix/php_interface/init.php (or /local/php_interface/init.php):
 *     require_once __DIR__ . '/aegis-editor.php';
 * Users who may edit content (administrators, or anyone with write access to the iblock or fileman
 * modules) get a signed cookie; Aegis lets HTML through in the admin editor only when it verifies,
 * so a made-up session parameter relaxes nothing. aegis-lock.php (dbconn.php) defines AEGIS_SECRET.
 */
if (!defined('AEGIS_SECRET')) { define('AEGIS_SECRET', '{{SECRET}}'); }

if (!function_exists('aegis_editor_pass')) {
    function aegis_editor_pass($user_id, $expires) {
        $expires = (int)$expires;
        $user_id = (int)$user_id;
        return "v1.$expires.$user_id." . hash_hmac('sha256', "editor|$expires|$user_id", AEGIS_SECRET);
    }

    function aegis_editor_valid($value, $user_id) {
        $parts = explode('.', (string)$value);
        if (count($parts) !== 4 || $parts[0] !== 'v1' || !ctype_digit($parts[1]) || (int)$parts[2] !== (int)$user_id) {
            return false;
        }
        if ((int)$parts[1] < time() + 3600) {
            return false;
        }
        return hash_equals(aegis_editor_pass($parts[2], $parts[1]), (string)$value);
    }

    function aegis_editor_cookie($value, $expires) {
        if (headers_sent()) {
            return;
        }
        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
        setcookie('aegis_editor', $value, array('expires' => $expires, 'path' => '/', 'secure' => $secure,
                                                 'httponly' => true, 'samesite' => 'Lax'));
        $_COOKIE['aegis_editor'] = $value;
    }

    function aegis_bitrix_editor() {
        global $USER, $APPLICATION;
        if (AEGIS_SECRET === '' || !is_object($USER) || !$USER->IsAuthorized()) {
            return false;
        }
        if ($USER->IsAdmin()) {
            return true;
        }
        return is_object($APPLICATION) && ($APPLICATION->GetGroupRight('iblock') >= 'W'
            || $APPLICATION->GetGroupRight('fileman') >= 'W');
    }

    AddEventHandler('main', 'OnBeforeProlog', function () {
        global $USER;
        if (!aegis_bitrix_editor()) {
            return;
        }
        $have = isset($_COOKIE['aegis_editor']) ? $_COOKIE['aegis_editor'] : '';
        if (!aegis_editor_valid($have, $USER->GetID())) {
            aegis_editor_cookie(aegis_editor_pass($USER->GetID(), time() + 2 * 86400), 0);
        }
    });

    AddEventHandler('main', 'OnAfterUserLogout', function () {
        aegis_editor_cookie('', time() - 3600);
    });
}
