<?php

header('Content-Type: text/plain; charset=utf-8');

$KEY = 'p8Sy9Zmwabzu2nxPDld79XyKKKIPNqyT6idFrytLCAJGpQzRQ5eUnG5Iev4p8y9T';

if (!isset($_GET['key']) || !is_string($_GET['key']) || !hash_equals($KEY, $_GET['key'])) {
    http_response_code(403);
    exit("Access denied\n");
}

set_time_limit(0);

$root = __DIR__;

$ok   = 0;
$fail = 0;

function setPerm($path, $mode)
{
    global $ok, $fail;

    if (!file_exists($path) && !is_link($path)) {
        return;
    }

    if (@chmod($path, $mode)) {
        $ok++;
    } else {
        $fail++;
        echo "FAIL " . decoct($mode) . " : $path\n";
    }
}


function unhardenRootFiles($root)
{
    $it = new FilesystemIterator($root, FilesystemIterator::SKIP_DOTS);

    foreach ($it as $item) {

        if ($item->isLink() || !$item->isFile()) {
            continue;
        }

        setPerm($item->getPathname(), 0644);
    }
}

function unhardenTree($path)
{
    if (!is_dir($path)) {
        return;
    }

    setPerm($path, 0755);

    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(
            $path,
            FilesystemIterator::SKIP_DOTS
        ),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($it as $item) {

        if ($item->isLink()) {
            continue;
        }

        if ($item->isDir()) {
            setPerm($item->getPathname(), 0755);
        } else {
            setPerm($item->getPathname(), 0644);
        }
    }
}


/* Возвращаем обычные права файлам в корне WordPress */
unhardenRootFiles($root);


/* Возвращаем обычные права каталогам WordPress */
unhardenTree($root . '/wp-admin');
unhardenTree($root . '/wp-includes');
unhardenTree($root . '/wp-content');
unhardenTree($root . '/filewatch');


/* wp-config и .htaccess снова разрешаем владельцу менять */
$files = [
    $root . '/wp-config.php',
    $root . '/.htaccess',
    $root . '/wp-content/uploads/.htaccess',
];

foreach ($files as $file) {
    if (is_file($file)) {
        setPerm($file, 0644);
    }
}


echo "\n====================\n";
echo "UNHARDEN DONE\n";
echo "SUCCESS: $ok\n";
echo "FAILED:  $fail\n";
echo "directories: 755\n";
echo "filewatch: WRITABLE\n";
echo "root files: 644\n";
echo "files: 644\n";
echo "====================\n";