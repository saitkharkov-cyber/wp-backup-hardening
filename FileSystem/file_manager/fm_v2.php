<?php
/*
 * Server FM v2 — PHP 7.x / 8.x
 * Place this file in the SITE ROOT if you want "ZIP всего сайта".
 * Delete this file from the server after maintenance.
 */

session_start();
set_time_limit(0);
@ini_set('memory_limit', '1024M');

define('FM_ROOT', realpath(__DIR__));
define('FM_PASSWORD', 'FM-59hMkACNtcLLl4');

header('X-Robots-Tag: noindex, nofollow, noarchive', true);
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

function h($s) {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function starts_with_path($path, $root) {
    $path = str_replace('\\', '/', $path);
    $root = rtrim(str_replace('\\', '/', $root), '/');
    return $path === $root || strpos($path, $root . '/') === 0;
}

function safe_existing_path($rel) {
    $rel = trim((string)$rel);
    if ($rel === '' || $rel === '.') return FM_ROOT;

    $candidate = FM_ROOT . DIRECTORY_SEPARATOR . str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $rel);
    $real = realpath($candidate);

    if ($real === false || !starts_with_path($real, FM_ROOT)) return false;
    return $real;
}

function rel_path($abs) {
    $root = rtrim(str_replace('\\', '/', FM_ROOT), '/');
    $abs = str_replace('\\', '/', $abs);
    if ($abs === $root) return '';
    return ltrim(substr($abs, strlen($root)), '/');
}

function csrf_token() {
    if (empty($_SESSION['fm_csrf'])) {
        $_SESSION['fm_csrf'] = function_exists('random_bytes')
            ? bin2hex(random_bytes(24))
            : sha1(uniqid('', true) . mt_rand());
    }
    return $_SESSION['fm_csrf'];
}

function check_csrf() {
    $sent = isset($_POST['csrf']) ? (string)$_POST['csrf'] : '';
    $good = isset($_SESSION['fm_csrf']) ? (string)$_SESSION['fm_csrf'] : '';
    if ($sent === '' || $good === '' || !hash_equals($good, $sent)) {
        http_response_code(403);
        exit('CSRF check failed.');
    }
}

function fmt_bytes($n) {
    $n = (float)$n;
    $units = array('B','KB','MB','GB','TB');
    $i = 0;
    while ($n >= 1024 && $i < count($units)-1) {
        $n /= 1024;
        $i++;
    }
    return ($i === 0 ? (string)(int)$n : number_format($n, 2, '.', '')) . ' ' . $units[$i];
}

function rrmdir($path, &$count) {
    if (is_link($path) || is_file($path)) {
        if (@unlink($path)) { $count++; return true; }
        return false;
    }

    if (!is_dir($path)) return false;
    $items = @scandir($path);
    if ($items === false) return false;

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $child = $path . DIRECTORY_SEPARATOR . $item;

        if (is_link($child)) {
            if (!@unlink($child)) return false;
            $count++;
        } elseif (is_dir($child)) {
            if (!rrmdir($child, $count)) return false;
        } else {
            if (!@unlink($child)) return false;
            $count++;
        }
    }

    if (@rmdir($path)) { $count++; return true; }
    return false;
}

function zip_add_path($zip, $path, $localName, &$count, $excludeAbs = array()) {
    $real = realpath($path);
    if ($real !== false && in_array($real, $excludeAbs, true)) return true;

    if (is_link($path)) return true;

    if (is_file($path)) {
        if ($zip->addFile($path, str_replace('\\','/',$localName))) {
            $count++;
            return true;
        }
        return false;
    }

    if (!is_dir($path)) return false;

    $localName = rtrim(str_replace('\\','/',$localName), '/') . '/';
    if ($localName !== '/') $zip->addEmptyDir($localName);

    $items = @scandir($path);
    if ($items === false) return false;

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $child = $path . DIRECTORY_SEPARATOR . $item;
        $childLocal = $localName . $item;

        if (!zip_add_path($zip, $child, $childLocal, $count, $excludeAbs)) return false;
    }

    return true;
}

function safe_zip_entry($name) {
    $name = str_replace('\\','/',(string)$name);
    if ($name === '' || substr($name,0,1) === '/') return false;
    if (preg_match('~(^|/)\.\.(/|$)~',$name)) return false;
    if (preg_match('~^[A-Za-z]:/~',$name)) return false;
    return true;
}

function redirect_here($rel, $msg) {
    $url = basename(__FILE__) . '?p=' . rawurlencode($rel);
    if ($msg !== '') $url .= '&m=' . rawurlencode($msg);
    header('Location: ' . $url);
    exit;
}

function site_zip_name() {
    $host = isset($_SERVER['HTTP_HOST']) ? preg_replace('~[^A-Za-z0-9._-]+~','-',$_SERVER['HTTP_HOST']) : basename(FM_ROOT);
    return $host . '-backup-' . date('Y-m-d_H-i-s') . '.zip';
}

/* LOGIN */
if (isset($_GET['logout'])) {
    $_SESSION = array();
    session_destroy();
    header('Location: ' . basename(__FILE__));
    exit;
}

if (empty($_SESSION['fm_auth'])) {
    $loginError = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_password'])) {
        $given = (string)$_POST['login_password'];
        if (hash_equals(FM_PASSWORD, $given)) {
            $_SESSION['fm_auth'] = true;
            csrf_token();
            header('Location: ' . basename(__FILE__));
            exit;
        }
        $loginError = 'Неверный пароль.';
    }
    ?>
    <!doctype html><html lang="ru"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>FM v2</title>
    <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif;background:#f5f5f5;margin:0;padding:40px 20px}
    .box{max-width:420px;margin:auto;background:#fff;border:1px solid #ddd;border-radius:12px;padding:24px}
    input,button{box-sizing:border-box;width:100%;font:inherit;padding:10px;margin-top:10px}
    .err{background:#fee;padding:10px;border-radius:6px}
    .warn{font-size:13px;color:#666;margin-top:16px}
    </style></head><body><div class="box">
    <h2>Server FM v2</h2>
    <?php if ($loginError): ?><div class="err"><?php echo h($loginError); ?></div><?php endif; ?>
    <form method="post">
        <input type="password" name="login_password" placeholder="Пароль" autofocus required>
        <button type="submit">Войти</button>
    </form>
    <div class="warn">После обслуживания удалите <?php echo h(basename(__FILE__)); ?>.</div>
    </div></body></html>
    <?php exit;
}

$rel = isset($_GET['p']) ? trim((string)$_GET['p']) : '';
$current = safe_existing_path($rel);
if ($current === false || !is_dir($current)) {
    $rel = '';
    $current = FM_ROOT;
} else {
    $rel = rel_path($current);
}

$message = isset($_GET['m']) ? (string)$_GET['m'] : '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    check_csrf();
    $action = (string)$_POST['action'];

    if ($action === 'zip_site') {
        if (!class_exists('ZipArchive')) {
            $error = 'ZipArchive недоступен.';
        } else {
            $zipName = site_zip_name();
            $zipPath = FM_ROOT . DIRECTORY_SEPARATOR . $zipName;

            $zip = new ZipArchive();
            $open = $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::EXCL);

            if ($open !== true) {
                $error = 'Не удалось создать ZIP. Код: ' . $open;
            } else {
                $count = 0;

                $exclude = array(
                    realpath(__FILE__),
                    realpath($zipPath)
                );

                // Исключаем все ZIP в корне сайта, чтобы не запаковывать старые бэкапы.
                $rootZips = glob(FM_ROOT . DIRECTORY_SEPARATOR . '*.zip');
                if ($rootZips !== false) {
                    foreach ($rootZips as $z) {
                        $rz = realpath($z);
                        if ($rz !== false) $exclude[] = $rz;
                    }
                }

                $items = @scandir(FM_ROOT);
                $ok = ($items !== false);

                if ($ok) {
                    foreach ($items as $item) {
                        if ($item === '.' || $item === '..') continue;

                        $path = FM_ROOT . DIRECTORY_SEPARATOR . $item;
                        $real = realpath($path);

                        if ($real !== false && in_array($real, $exclude, true)) continue;

                        if (!zip_add_path($zip, $path, $item, $count, $exclude)) {
                            $ok = false;
                            break;
                        }
                    }
                }

                $closed = $zip->close();

                if ($ok && $closed) {
                    redirect_here('', 'Создан архив всего сайта: ' . $zipName . ' (файлов: ' . $count . ')');
                } else {
                    @unlink($zipPath);
                    $error = 'Ошибка при создании архива сайта.';
                }
            }
        }
    } else {
        $targetRel = isset($_POST['target']) ? (string)$_POST['target'] : '';
        $target = safe_existing_path($targetRel);

        if ($target === false) {
            $error = 'Неверный или недоступный путь.';
        } elseif ($target === FM_ROOT && $action === 'delete') {
            $error = 'Корневую папку удалить нельзя.';
        } elseif (realpath(__FILE__) === $target && $action === 'delete') {
            $error = 'Текущий fm_v2.php нельзя удалить этой кнопкой.';
        } elseif ($action === 'delete') {
            $count = 0;
            $name = basename($target);
            if (rrmdir($target, $count)) {
                redirect_here($rel, 'Удалено: ' . $name . ' (объектов: ' . $count . ')');
            } else {
                $error = 'Не удалось полностью удалить: ' . $name;
            }

        } elseif ($action === 'rename') {
            $newName = isset($_POST['new_name']) ? trim((string)$_POST['new_name']) : '';

            if ($newName === '' || $newName === '.' || $newName === '..' ||
                strpos($newName,'/') !== false || strpos($newName,'\\') !== false) {
                $error = 'Недопустимое новое имя.';
            } else {
                $dest = dirname($target) . DIRECTORY_SEPARATOR . $newName;
                if (file_exists($dest)) {
                    $error = 'Файл или папка с таким именем уже существует.';
                } elseif (@rename($target, $dest)) {
                    redirect_here($rel, 'Переименовано: ' . basename($target) . ' → ' . $newName);
                } else {
                    $error = 'Не удалось переименовать.';
                }
            }

        } elseif ($action === 'zip') {
            if (!class_exists('ZipArchive')) {
                $error = 'ZipArchive недоступен.';
            } else {
                $baseName = basename($target);
                $zipPath = dirname($target) . DIRECTORY_SEPARATOR . $baseName . '.zip';

                if (file_exists($zipPath)) {
                    $error = 'Архив уже существует: ' . basename($zipPath);
                } else {
                    $zip = new ZipArchive();
                    $open = $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::EXCL);

                    if ($open !== true) {
                        $error = 'Не удалось создать ZIP. Код: ' . $open;
                    } else {
                        $count = 0;
                        $ok = zip_add_path($zip, $target, $baseName, $count, array(realpath(__FILE__), realpath($zipPath)));
                        $closed = $zip->close();

                        if ($ok && $closed) {
                            redirect_here($rel, 'Создан ZIP: ' . basename($zipPath) . ' (файлов: ' . $count . ')');
                        } else {
                            @unlink($zipPath);
                            $error = 'Ошибка при создании ZIP.';
                        }
                    }
                }
            }

        } elseif ($action === 'unzip') {
            if (!class_exists('ZipArchive')) {
                $error = 'ZipArchive недоступен.';
            } elseif (!is_file($target) || strtolower(pathinfo($target,PATHINFO_EXTENSION)) !== 'zip') {
                $error = 'Распаковывать можно только ZIP-файлы.';
            } else {
                $zip = new ZipArchive();
                $open = $zip->open($target);

                if ($open !== true) {
                    $error = 'Не удалось открыть ZIP. Код: ' . $open;
                } else {
                    $bad = array();

                    for ($i=0; $i<$zip->numFiles; $i++) {
                        $name = $zip->getNameIndex($i);
                        if ($name === false || !safe_zip_entry($name)) {
                            $bad[] = (string)$name;
                            break;
                        }
                    }

                    if (!empty($bad)) {
                        $zip->close();
                        $error = 'Распаковка отменена: небезопасный путь в ZIP.';
                    } else {
                        $count = $zip->numFiles;
                        $ok = $zip->extractTo(dirname($target));
                        $zip->close();

                        if ($ok) {
                            redirect_here($rel, 'ZIP распакован: ' . basename($target) . ' (объектов: ' . $count . ')');
                        } else {
                            $error = 'Не удалось распаковать ZIP.';
                        }
                    }
                }
            }
        } else {
            $error = 'Неизвестное действие.';
        }
    }
}

$entries = array();
$items = @scandir($current);

if ($items !== false) {
    foreach ($items as $name) {
        if ($name === '.' || $name === '..') continue;

        $path = $current . DIRECTORY_SEPARATOR . $name;

        $entries[] = array(
            'name' => $name,
            'path' => $path,
            'rel' => rel_path($path),
            'dir' => is_dir($path) && !is_link($path),
            'link' => is_link($path),
            'size' => is_file($path) ? @filesize($path) : null,
            'time' => @filemtime($path),
        );
    }
}

usort($entries,function($a,$b){
    if ($a['dir'] !== $b['dir']) return $a['dir'] ? -1 : 1;
    return strnatcasecmp($a['name'],$b['name']);
});

$parentRel = '';
if ($current !== FM_ROOT) $parentRel = rel_path(dirname($current));
?>
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Server FM v2</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif;margin:0;background:#f5f5f5;color:#222}
.wrap{max-width:1250px;margin:24px auto;padding:0 16px}
.top,.panel{background:#fff;border:1px solid #ddd;border-radius:10px;padding:14px 16px;margin-bottom:14px}
.top{display:flex;gap:12px;justify-content:space-between;align-items:center;flex-wrap:wrap}
.danger-banner{background:#fff3cd;border:1px solid #ffe69c;border-radius:10px;padding:12px 16px;margin-bottom:14px;font-weight:600}
.msg{background:#e9f8ec;border:1px solid #b7e2c0;padding:10px 14px;border-radius:8px;margin-bottom:14px}
.err{background:#fdeaea;border:1px solid #f0b6b6;padding:10px 14px;border-radius:8px;margin-bottom:14px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #ddd}
th,td{padding:9px 10px;border-bottom:1px solid #eee;text-align:left;vertical-align:middle}
th{background:#fafafa}
tr:hover td{background:#fcfcfc}
a{color:#1769aa;text-decoration:none}
a:hover{text-decoration:underline}
.name{word-break:break-all}
.muted{color:#777;font-size:13px}
.actions{display:flex;gap:6px;flex-wrap:wrap}
button,.btn,input{font:inherit}
button,.btn{border:1px solid #bbb;background:#fff;border-radius:6px;padding:6px 9px;cursor:pointer;text-decoration:none;color:#222}
button:hover,.btn:hover{background:#f3f3f3;text-decoration:none}
.red{border-color:#d88;color:#a00}
.zip{border-color:#8ab;color:#245}
.sitezip{border-color:#6a9;color:#174;background:#eef9f1}
.path{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}
form.inline{display:inline-flex;gap:5px;align-items:center;margin:0}
input.rename{width:150px;padding:5px}
@media(max-width:850px){.hide-sm{display:none} table{font-size:14px}}
</style>
<script>
function confirmDelete(name) {
    return confirm('Удалить "' + name + '" рекурсивно?\n\nЭто действие необратимо.');
}
</script>
</head>
<body>
<div class="wrap">

<div class="danger-banner">
Служебный файловый менеджер. После работы обязательно удалите <?php echo h(basename(__FILE__)); ?>.
</div>

<div class="top">
<div>
<strong>ROOT:</strong> <span class="path"><?php echo h(FM_ROOT); ?></span><br>
<strong>Сейчас:</strong> <span class="path">/<?php echo h($rel); ?></span>
</div>
<div><a class="btn" href="?logout=1">Выйти</a></div>
</div>

<?php if ($message !== ''): ?><div class="msg"><?php echo h($message); ?></div><?php endif; ?>
<?php if ($error !== ''): ?><div class="err"><?php echo h($error); ?></div><?php endif; ?>

<div class="panel">
<?php if ($current === FM_ROOT): ?>
<form method="post" class="inline" onsubmit="return confirm('Создать ZIP всего сайта?\n\nZIP-файлы в корне сайта и сам fm_v2.php будут исключены.');">
<input type="hidden" name="csrf" value="<?php echo h(csrf_token()); ?>">
<input type="hidden" name="action" value="zip_site">
<button class="sitezip" type="submit">ZIP всего сайта</button>
</form>
<span class="muted"> Исключаются: сам fm_v2.php и все *.zip в корне сайта.</span>
<?php else: ?>
<a class="btn" href="?p=<?php echo rawurlencode($parentRel); ?>">← На уровень выше</a>
<?php endif; ?>
</div>

<table>
<thead><tr>
<th>Имя</th>
<th class="hide-sm">Размер</th>
<th class="hide-sm">Изменён</th>
<th>Действия</th>
</tr></thead>
<tbody>

<?php foreach ($entries as $e): ?>
<tr>
<td class="name">
<?php if ($e['dir']): ?>
📁 <a href="?p=<?php echo rawurlencode($e['rel']); ?>"><strong><?php echo h($e['name']); ?></strong></a>
<?php elseif ($e['link']): ?>
🔗 <?php echo h($e['name']); ?>
<?php else: ?>
📄 <?php echo h($e['name']); ?>
<?php endif; ?>
</td>

<td class="hide-sm"><?php echo $e['size'] !== null ? h(fmt_bytes($e['size'])) : '—'; ?></td>
<td class="hide-sm"><?php echo $e['time'] ? h(date('Y-m-d H:i:s',$e['time'])) : '—'; ?></td>

<td><div class="actions">

<?php if (!$e['link']): ?>
<form method="post" class="inline">
<input type="hidden" name="csrf" value="<?php echo h(csrf_token()); ?>">
<input type="hidden" name="action" value="zip">
<input type="hidden" name="target" value="<?php echo h($e['rel']); ?>">
<button class="zip" type="submit">ZIP</button>
</form>
<?php endif; ?>

<?php if (!$e['dir'] && strtolower(pathinfo($e['name'],PATHINFO_EXTENSION)) === 'zip'): ?>
<form method="post" class="inline" onsubmit="return confirm('Распаковать ZIP в текущую папку?');">
<input type="hidden" name="csrf" value="<?php echo h(csrf_token()); ?>">
<input type="hidden" name="action" value="unzip">
<input type="hidden" name="target" value="<?php echo h($e['rel']); ?>">
<button type="submit">Распаковать</button>
</form>
<?php endif; ?>

<form method="post" class="inline">
<input type="hidden" name="csrf" value="<?php echo h(csrf_token()); ?>">
<input type="hidden" name="action" value="rename">
<input type="hidden" name="target" value="<?php echo h($e['rel']); ?>">
<input class="rename" type="text" name="new_name" value="<?php echo h($e['name']); ?>">
<button type="submit">Имя</button>
</form>

<?php if (realpath($e['path']) !== realpath(__FILE__)): ?>
<form method="post" class="inline" onsubmit="return confirmDelete(<?php echo json_encode($e['name']); ?>);">
<input type="hidden" name="csrf" value="<?php echo h(csrf_token()); ?>">
<input type="hidden" name="action" value="delete">
<input type="hidden" name="target" value="<?php echo h($e['rel']); ?>">
<button class="red" type="submit">Удалить</button>
</form>
<?php endif; ?>

</div></td>
</tr>
<?php endforeach; ?>

<?php if (empty($entries)): ?><tr><td colspan="4">Папка пуста.</td></tr><?php endif; ?>
</tbody>
</table>

<div class="panel muted" style="margin-top:14px">
Для архива всего сайта положите fm_v2.php именно в корень WordPress. Скрипт не редактирует PHP и не выполняет shell-команды.
</div>

</div>
</body>
</html>
