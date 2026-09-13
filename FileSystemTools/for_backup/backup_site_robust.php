<?php

set_time_limit(0);
ignore_user_abort(true);
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
        FilesystemIterator::SKIP_DOTS
    ),
    RecursiveIteratorIterator::LEAVES_ONLY,
    RecursiveIteratorIterator::CATCH_GET_CHILD
);

$count = 0;
$skipped = 0;
$totalBytes = 0;
$warnings = array();

foreach ($iterator as $file) {

    try {
        if (!$file instanceof SplFileInfo) {
            continue;
        }

        $path = $file->getPathname();

        // Не архивируем сам скрипт и создаваемый ZIP.
        if ($path === $zipPath || $path === __FILE__) {
            continue;
        }

        // Не включаем старые архивы этого же типа.
        $name = $file->getFilename();
        if (
            strpos($name, 'site-backup-') === 0 &&
            strtolower(substr($name, -4)) === '.zip'
        ) {
            continue;
        }

        // Симлинки пропускаем.
        if ($file->isLink()) {
            continue;
        }

        if (!$file->isFile()) {
            continue;
        }

        $relative = substr($path, strlen($root) + 1);

        // Важно: читаем файл СРАЗУ.
        // addFile() может отложить чтение до ZipArchive::close(),
        // из-за чего временно исчезнувший cache/tmp-файл ломает весь архив.
        $data = @file_get_contents($path);

        if ($data === false) {
            $skipped++;
            $warnings[] = 'Пропущен (не удалось прочитать): ' . $relative;
            continue;
        }

        if (!$zip->addFromString($relative, $data)) {
            $skipped++;
            $warnings[] = 'Не удалось добавить в ZIP: ' . $relative;
            unset($data);
            continue;
        }

        $count++;
        $totalBytes += strlen($data);

        // Сразу освобождаем память от содержимого текущего файла.
        unset($data);

    } catch (Throwable $e) {
        $skipped++;
        $warnings[] = $e->getMessage();
    }
}

$closeOk = $zip->close();

echo '<pre>';

if (!$closeOk || !is_file($zipPath)) {
    echo "ОШИБКА\n\n";
    echo "ZipArchive не смог корректно завершить архив.\n";
    echo "Добавлено файлов: " . $count . "\n";
    echo "Пропущено: " . $skipped . "\n";
    echo '</pre>';
    exit;
}

echo "ГОТОВО\n\n";
echo 'Архив: ' . htmlspecialchars($zipName, ENT_QUOTES, 'UTF-8') . "\n";
echo 'Файлов: ' . $count . "\n";
echo 'Пропущено: ' . $skipped . "\n";
echo 'Исходный объём файлов: ' . round($totalBytes / 1024 / 1024, 2) . " MB\n";
echo 'Размер ZIP: ' . round(filesize($zipPath) / 1024 / 1024, 2) . " MB\n";

if ($warnings) {
    echo "\nПРЕДУПРЕЖДЕНИЯ:\n";

    foreach (array_slice($warnings, 0, 50) as $warning) {
        echo '- ' . htmlspecialchars($warning, ENT_QUOTES, 'UTF-8') . "\n";
    }

    if (count($warnings) > 50) {
        echo '... ещё ' . (count($warnings) - 50) . "\n";
    }
}

echo "\nВАЖНО: после скачивания удалите ZIP и этот скрипт с сервера.\n";
echo '</pre>';
