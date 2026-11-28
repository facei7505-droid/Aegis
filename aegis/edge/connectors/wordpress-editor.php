
/*
 * Editor pass: a signed cookie for users who can edit posts. Aegis lets HTML through in the editor
 * only when this pass verifies, so a made-up "wordpress_logged_in_" cookie relaxes nothing.
 */
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
        if ((int)$parts[1] < time() + 3600) {  // renew an hour before it runs out
            return false;
        }
        return hash_equals(aegis_editor_pass($parts[2], $parts[1]), (string)$value);
    }

    function aegis_editor_cookie($value, $expires) {
        if (headers_sent()) {
            return;
        }
        setcookie('aegis_editor', $value, array('expires' => $expires, 'path' => '/', 'secure' => is_ssl(),
                                                 'httponly' => true, 'samesite' => 'Lax'));
        $_COOKIE['aegis_editor'] = $value;
    }

    add_action('set_logged_in_cookie', function ($cookie, $expire, $expiration, $user_id) {
        if (AEGIS_SECRET !== '' && user_can($user_id, 'edit_posts')) {
            aegis_editor_cookie(aegis_editor_pass($user_id, $expiration), $expire);
        }
    }, 10, 4);

    add_action('clear_auth_cookie', function () {
        aegis_editor_cookie('', time() - 3600);
    });

    add_action('init', function () {
        if (AEGIS_SECRET === '' || !is_user_logged_in() || !current_user_can('edit_posts')) {
            return;
        }
        $user_id = get_current_user_id();
        $have = isset($_COOKIE['aegis_editor']) ? $_COOKIE['aegis_editor'] : '';
        if (!aegis_editor_valid($have, $user_id)) {
            aegis_editor_cookie(aegis_editor_pass($user_id, time() + 2 * DAY_IN_SECONDS), 0);
        }
    }, 1);
}
