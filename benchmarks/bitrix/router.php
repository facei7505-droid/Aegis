<?php
// Router for PHP's built-in server standing in for Apache's .htaccess in the Bitrix lab:
// real files are served as they are, everything else goes to Bitrix's /bitrix/urlrewrite.php.
$root = $_SERVER['DOCUMENT_ROOT'];
$path = rawurldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/');
$file = realpath($root . $path);
if ($file !== false && strpos($file, realpath($root)) === 0) {
    if (is_dir($file)) {
        if (is_file($file . '/index.php')) {
            if (substr($path, -1) !== '/') {
                header('Location: ' . $path . '/' . (isset($_SERVER['QUERY_STRING']) && $_SERVER['QUERY_STRING'] !== '' ? '?' . $_SERVER['QUERY_STRING'] : ''), true, 301);
                return true;
            }
            $_SERVER['SCRIPT_NAME'] = rtrim($path, '/') . '/index.php';
            $_SERVER['SCRIPT_FILENAME'] = $file . '/index.php';
            $_SERVER['PHP_SELF'] = $_SERVER['SCRIPT_NAME'];
            chdir($file);
            require $file . '/index.php';
            return true;
        }
    } elseif (is_file($file)) {
        return false;
    }
}
$_SERVER['SCRIPT_NAME'] = '/bitrix/urlrewrite.php';
$_SERVER['SCRIPT_FILENAME'] = $root . '/bitrix/urlrewrite.php';
$_SERVER['PHP_SELF'] = '/bitrix/urlrewrite.php';
chdir($root . '/bitrix');
require $root . '/bitrix/urlrewrite.php';
