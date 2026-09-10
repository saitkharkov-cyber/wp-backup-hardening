<?php

set_time_limit(0);
ini_set('memory_limit', '512M');

$root = __DIR__;
$zipName = 'site-backup-' . date('Y-m-d_H-i-s') . '.zip';
$zipPath = $root . DIRECTORY_SEPARATOR . $zipName;

if (!class_exists('ZipArchive')) {
    die('ZipArchive недоступен');
}

$zip = new ZipArchive();

if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    die('Не удалось создать ZIP');
}

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator(
        $root,
        RecursiveDirectoryIterator::SKIP_DOTS
    ),
    RecursiveIteratorIterator::SELF_FIRST
);

$count = 0;

foreach ($iterator as $file) {
    $path = $file->getPathname();

    if ($path === $zipPath || $path === __FILE__) {
        continue;
    }

    $relative = substr($path, strlen($root) + 1);

    if ($file->isDir()) {
        $zip->addEmptyDir($relative);
    } else {
        $zip->addFile($path, $relative);
        $count++;
    }
}

$zip->close();

echo '<pre>';
echo "ГОТОВО\n\n";
echo 'Архив: ' . htmlspecialchars($zipName, ENT_QUOTES, 'UTF-8') . "\n";
echo 'Файлов: ' . $count . "\n";
echo 'Размер ZIP: ' . round(filesize($zipPath) / 1024 / 1024, 2) . " MB\n";
echo "\nВАЖНО: после скачивания удалите ZIP и этот скрипт с сервера.\n";
echo '</pre>';
