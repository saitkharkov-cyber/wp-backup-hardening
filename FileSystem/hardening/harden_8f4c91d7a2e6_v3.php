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

function hardenRootFiles($root)
{
    $it = new FilesystemIterator($root, FilesystemIterator::SKIP_DOTS);

    foreach ($it as $item) {
        if ($item->isLink() || !$item->isFile()) {
            continue;
        }

        setPerm($item->getPathname(), 0444);
    }
}

function hardenTree($path)
{
    if (!is_dir($path)) {
        return;
    }

    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(
            $path,
            FilesystemIterator::SKIP_DOTS
        ),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($it as $item) {
        if ($item->isLink()) {
            continue;
        }

        if ($item->isDir()) {
            setPerm($item->getPathname(), 0555);
        } else {
            setPerm($item->getPathname(), 0444);
        }
    }

    setPerm($path, 0555);
}

function writableTree($path)
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

/* Файлы в корне WordPress */
hardenRootFiles($root);

/* WordPress core */
hardenTree($root . '/wp-admin');
hardenTree($root . '/wp-includes');

/*
 * ВЕСЬ wp-content сначала закрываем.
 * Сюда входят plugins, themes, mu-plugins,
 * upgrade, cache и любые неизвестные каталоги.
 */
hardenTree($root . '/wp-content');

/*
 * FileWatch полностью закрываем:
 * каталоги 0555, файлы 0444.
 * Его baseline/state находятся выше web-root,
 * поэтому работа мониторинга не нарушается.
 */
hardenTree($root . '/filewatch');

/*
 * Разрешённые writable-каталоги.
 * Сейчас только uploads.
 */
$writable = [
    $root . '/wp-content/uploads',
];

foreach ($writable as $path) {
    writableTree($path);
}

/*
 * Защитные файлы после открытия uploads
 * снова ставим 0444.
 */
$protectedFiles = [
    $root . '/wp-config.php',
    $root . '/.htaccess',
    $root . '/wp-content/uploads/.htaccess',
];

foreach ($protectedFiles as $file) {
    if (is_file($file)) {
        setPerm($file, 0444);
    }
}

echo "\n====================\n";
echo "HARDEN DONE\n";
echo "SUCCESS: $ok\n";
echo "FAILED:  $fail\n";
echo "wp-content: READ ONLY\n";
echo "uploads: WRITABLE\n";
echo "filewatch: READ ONLY\n";
echo "root files: READ ONLY\n";
echo ".htaccess: PROTECTED\n";
echo "====================\n";
