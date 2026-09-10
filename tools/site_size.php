<?php

set_time_limit(0);

$root = __DIR__;
$self = __FILE__;

function format_bytes($bytes)
{
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;

    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }

    return round($bytes, 2) . ' ' . $units[$i];
}

$totalBytes = 0;
$totalFiles = 0;
$groups = [];

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($root, RecursiveDirectoryIterator::SKIP_DOTS),
    RecursiveIteratorIterator::LEAVES_ONLY
);

foreach ($iterator as $file) {
    if (!$file->isFile()) {
        continue;
    }

    $path = $file->getPathname();

    if ($path === $self) {
        continue;
    }

    $size = $file->getSize();
    $relative = substr($path, strlen($root) + 1);
    $parts = preg_split('~[\\\\/]~', $relative);
    $group = count($parts) > 1 ? $parts[0] : '[root]';

    if (!isset($groups[$group])) {
        $groups[$group] = ['bytes' => 0, 'files' => 0];
    }

    $groups[$group]['bytes'] += $size;
    $groups[$group]['files']++;
    $totalBytes += $size;
    $totalFiles++;
}

uasort($groups, function ($a, $b) {
    return $b['bytes'] <=> $a['bytes'];
});

echo '<pre>';
echo "TOTAL\n";
echo 'Size: ' . format_bytes($totalBytes) . "\n";
echo 'Files: ' . $totalFiles . "\n\n";
echo "TOP-LEVEL\n";

foreach ($groups as $name => $data) {
    echo str_pad($name, 35) . str_pad(format_bytes($data['bytes']), 15) . $data['files'] . " files\n";
}

echo '</pre>';
