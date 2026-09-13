<?php
declare(strict_types=1);

require_once __DIR__ . '/filewatch_config.php';


function fw_starts_with(string $haystack, string $needle): bool
{
    if ($needle === '') {
        return true;
    }

    return substr($haystack, 0, strlen($needle)) === $needle;
}


function fw_auth(): void
{
    if (!isset($_GET['key']) || !is_string($_GET['key']) || !hash_equals(FILEWATCH_KEY, $_GET['key'])) {
        http_response_code(403);
        exit("Access denied\n");
    }
}

function fw_json_response(array $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

function fw_ensure_data_dir(): string
{
    $dir = filewatch_data_dir();

    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
            fw_json_response([
                'ok' => false,
                'error' => 'Cannot create data directory above web-root',
                'data_dir' => $dir,
            ], 500);
        }
    }

    if (!is_writable($dir)) {
        fw_json_response([
            'ok' => false,
            'error' => 'Data directory is not writable',
            'data_dir' => $dir,
        ], 500);
    }

    @chmod($dir, 0700);
    return $dir;
}

function fw_path(string $name): string
{
    return fw_ensure_data_dir() . '/' . $name;
}

function fw_read_json(string $path, array $default = []): array
{
    if (!is_file($path)) {
        return $default;
    }

    $raw = @file_get_contents($path);
    if ($raw === false || $raw === '') {
        return $default;
    }

    $data = json_decode($raw, true);
    return is_array($data) ? $data : $default;
}

function fw_write_json_atomic(string $path, array $data): void
{
    $tmp = $path . '.tmp.' . bin2hex(random_bytes(4));
    $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

    if ($json === false || @file_put_contents($tmp, $json, LOCK_EX) === false) {
        @unlink($tmp);
        throw new RuntimeException("Cannot write: $path");
    }

    @chmod($tmp, 0600);

    if (!@rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException("Cannot replace: $path");
    }

    @chmod($path, 0600);
}

function fw_state(): array
{
    return fw_read_json(fw_path('state.json'), [
        'paused' => false,
        'pause_started_at' => null,
        'baseline_created_after_pause' => true,
        'last_alert_signature' => '',
        'last_quick_signature' => '',
        'last_full_signature' => '',
        'last_alert_time' => null,
        'full_cursor' => 0,
        'full_cycle_started' => null,
    ]);
}

function fw_save_state(array $state): void
{
    fw_write_json_atomic(fw_path('state.json'), $state);
}

function fw_norm_rel(string $absolute): string
{
    $root = str_replace('\\', '/', rtrim(filewatch_site_root(), '/\\'));
    $p = str_replace('\\', '/', $absolute);

    if (fw_starts_with($p, $root . '/')) {
        return substr($p, strlen($root) + 1);
    }

    return ltrim($p, '/');
}

function fw_is_excluded_dir(string $rel): bool
{
    $rel = trim(str_replace('\\', '/', $rel), '/');

    foreach (FILEWATCH_EXCLUDE_DIRS as $ex) {
        $ex = trim(str_replace('\\', '/', $ex), '/');
        if ($rel === $ex || fw_starts_with($rel, $ex . '/')) {
            return true;
        }
    }

    return false;
}

function fw_is_under_uploads(string $rel): bool
{
    $rel = trim(str_replace('\\', '/', $rel), '/');
    $u = trim(str_replace('\\', '/', FILEWATCH_UPLOADS_REL), '/');
    return $rel === $u || fw_starts_with($rel, $u . '/');
}

function fw_is_dangerous_upload_file(string $rel): bool
{
    if (!fw_is_under_uploads($rel)) {
        return false;
    }

    $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
    return $ext !== '' && in_array($ext, FILEWATCH_DANGEROUS_UPLOAD_EXT, true);
}

function fw_should_include_file(string $rel): bool
{
    if (fw_is_under_uploads($rel)) {
        return fw_is_dangerous_upload_file($rel);
    }

    return true;
}

function fw_scan_metadata(?array $baseline = null): array
{
    $root = filewatch_site_root();
    $started = microtime(true);

    $snapshot = [];
    $dirs = 0;
    $files = 0;
    $hashed = 0;

    $dirIt = new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS);
    $filter = new RecursiveCallbackFilterIterator(
        $dirIt,
        function (SplFileInfo $current) {
            $rel = fw_norm_rel($current->getPathname());

            if ($current->isLink()) {
                return false;
            }

            if ($current->isDir() && fw_is_excluded_dir($rel)) {
                return false;
            }

            return true;
        }
    );

    $it = new RecursiveIteratorIterator($filter, RecursiveIteratorIterator::SELF_FIRST);

    foreach ($it as $item) {
        $rel = fw_norm_rel($item->getPathname());

        if ($rel === '' || fw_is_excluded_dir($rel)) {
            continue;
        }

        if ($item->isDir()) {
            $snapshot[$rel] = ['type' => 'dir'];
            $dirs++;
            continue;
        }

        if (!$item->isFile() || !fw_should_include_file($rel)) {
            continue;
        }

        $size = $item->getSize();
        $mtime = $item->getMTime();

        $entry = [
            'type' => 'file',
            'size' => $size,
            'mtime' => $mtime,
        ];

        $needHash = $baseline === null;

        if ($baseline !== null) {
            $old = $baseline[$rel] ?? null;

            if (
                !is_array($old) ||
                ($old['type'] ?? null) !== 'file' ||
                (int)($old['size'] ?? -1) !== $size ||
                (int)($old['mtime'] ?? -1) !== $mtime
            ) {
                $needHash = true;
            } elseif (isset($old['sha256'])) {
                $entry['sha256'] = $old['sha256'];
            }
        }

        if ($needHash) {
            $hash = @hash_file('sha256', $item->getPathname());
            $entry['sha256'] = $hash !== false ? $hash : null;
            $hashed++;
        }

        $snapshot[$rel] = $entry;
        $files++;
    }

    ksort($snapshot, SORT_STRING);

    return [
        'snapshot' => $snapshot,
        'stats' => [
            'dirs' => $dirs,
            'files' => $files,
            'hashed' => $hashed,
            'seconds' => round(microtime(true) - $started, 3),
        ],
    ];
}

function fw_diff(array $baseline, array $current): array
{
    $out = [
        'directory_added' => [],
        'directory_deleted' => [],
        'file_added' => [],
        'file_deleted' => [],
        'file_modified' => [],
    ];

    foreach ($current as $path => $now) {
        if (!isset($baseline[$path])) {
            if (($now['type'] ?? '') === 'dir') {
                $out['directory_added'][] = $path;
            } else {
                $out['file_added'][] = $path;
            }
            continue;
        }

        $old = $baseline[$path];

        if (($old['type'] ?? '') !== ($now['type'] ?? '')) {
            if (($now['type'] ?? '') === 'dir') {
                $out['directory_added'][] = $path;
                $out['file_deleted'][] = $path;
            } else {
                $out['file_added'][] = $path;
                $out['directory_deleted'][] = $path;
            }
            continue;
        }

        if (($now['type'] ?? '') === 'file') {
            $changed =
                (int)($old['size'] ?? -1) !== (int)($now['size'] ?? -2) ||
                (int)($old['mtime'] ?? -1) !== (int)($now['mtime'] ?? -2);

            if ($changed) {
                $out['file_modified'][] = [
                    'path' => $path,
                    'old_sha256' => $old['sha256'] ?? null,
                    'new_sha256' => $now['sha256'] ?? null,
                ];
            }
        }
    }

    foreach ($baseline as $path => $old) {
        if (!isset($current[$path])) {
            if (($old['type'] ?? '') === 'dir') {
                $out['directory_deleted'][] = $path;
            } else {
                $out['file_deleted'][] = $path;
            }
        }
    }

    foreach (['directory_added','directory_deleted','file_added','file_deleted'] as $k) {
        sort($out[$k], SORT_STRING);
    }

    usort($out['file_modified'], fn($a, $b) => strcmp($a['path'], $b['path']));

    return $out;
}

function fw_diff_count(array $diff): int
{
    $n = 0;
    foreach ($diff as $items) {
        $n += count($items);
    }
    return $n;
}

function fw_diff_signature(array $diff): string
{
    return hash('sha256', json_encode($diff, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

function fw_collapse_dirs(array $dirs): array
{
    sort($dirs, SORT_STRING);
    $out = [];

    foreach ($dirs as $dir) {
        $covered = false;

        foreach ($out as $parent) {
            if ($dir === $parent || fw_starts_with($dir, $parent . '/')) {
                $covered = true;
                break;
            }
        }

        if (!$covered) {
            $out[] = $dir;
        }
    }

    return $out;
}

function fw_count_descendant_files(string $dir, array $snapshot): int
{
    $prefix = rtrim($dir, '/') . '/';
    $n = 0;

    foreach ($snapshot as $path => $entry) {
        if (($entry['type'] ?? '') === 'file' && fw_starts_with($path, $prefix)) {
            $n++;
        }
    }

    return $n;
}

function fw_build_report(array $diff, array $baseline, array $current, string $mode): string
{
    $host = $_SERVER['HTTP_HOST'] ?? basename(filewatch_site_root());
    $lines = [
        'FileWatch alert',
        'Site: ' . $host,
        'Mode: ' . $mode,
        'Time: ' . date('Y-m-d H:i:s'),
        '',
    ];

    foreach (fw_collapse_dirs($diff['directory_added']) as $dir) {
        $count = fw_count_descendant_files($dir, $current);
        $lines[] = "DIRECTORY ADDED: {$dir}/" . ($count ? " [files inside: {$count}]" : '');
    }

    foreach (fw_collapse_dirs($diff['directory_deleted']) as $dir) {
        $count = fw_count_descendant_files($dir, $baseline);
        $lines[] = "DIRECTORY DELETED: {$dir}/" . ($count ? " [files inside baseline: {$count}]" : '');
    }

    foreach ($diff['file_added'] as $path) {
        $lines[] = "FILE ADDED: {$path}";
    }

    foreach ($diff['file_deleted'] as $path) {
        $lines[] = "FILE DELETED: {$path}";
    }

    foreach ($diff['file_modified'] as $item) {
        $lines[] = "FILE MODIFIED: " . $item['path'];
        $lines[] = "  old: " . ($item['old_sha256'] ?? '-');
        $lines[] = "  new: " . ($item['new_sha256'] ?? '-');

        if (count($lines) >= FILEWATCH_MAX_REPORT_LINES) {
            $lines[] = '... report truncated ...';
            break;
        }
    }

    $lines[] = '';
    $lines[] = 'Total changes: ' . fw_diff_count($diff);
    $lines[] = 'Baseline is NOT changed automatically.';

    return implode("\n", $lines);
}


function fw_alert_recipients(): array
{
    $emails = [];

    if (defined('FILEWATCH_ALERT_EMAILS') && is_array(FILEWATCH_ALERT_EMAILS)) {
        $emails = FILEWATCH_ALERT_EMAILS;
    } elseif (defined('FILEWATCH_ALERT_EMAIL')) {
        // Backward compatibility with v2.3 config.
        $emails = [FILEWATCH_ALERT_EMAIL];
    }

    $out = [];

    foreach ($emails as $email) {
        if (!is_string($email)) {
            continue;
        }

        $email = trim($email);

        if ($email === '' || $email === 'YOUR_EMAIL@example.com') {
            continue;
        }

        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $out[$email] = true;
        }
    }

    return array_keys($out);
}

function fw_smtp_read($fp): string
{
    $data = '';

    while (($line = fgets($fp, 515)) !== false) {
        $data .= $line;

        if (strlen($line) >= 4 && $line[3] === ' ') {
            break;
        }
    }

    return $data;
}

function fw_smtp_expect($fp, array $codes): string
{
    $response = fw_smtp_read($fp);
    $code = (int)substr($response, 0, 3);

    if (!in_array($code, $codes, true)) {
        throw new RuntimeException(
            'SMTP error: expected ' . implode('/', $codes) .
            ', got ' . $code . ' — ' . trim($response)
        );
    }

    return $response;
}

function fw_smtp_cmd($fp, string $command, array $codes): string
{
    if (@fwrite($fp, $command . "\r\n") === false) {
        throw new RuntimeException('SMTP write failed');
    }

    return fw_smtp_expect($fp, $codes);
}

function fw_smtp_dot_stuff(string $text): string
{
    $text = str_replace(["\r\n", "\r"], "\n", $text);
    $lines = explode("
", $text);

    foreach ($lines as &$line) {
        if (isset($line[0]) && $line[0] === '.') {
            $line = '.' . $line;
        }
    }
    unset($line);

    return implode("\r\n", $lines);
}

function fw_encode_header(string $value): string
{
    if (function_exists('mb_encode_mimeheader')) {
        return mb_encode_mimeheader($value, 'UTF-8', 'B', "\r\n");
    }

    return '=?UTF-8?B?' . base64_encode($value) . '?=';
}

function fw_send_smtp(string $subject, string $body): bool
{
    $recipients = fw_alert_recipients();

    if (!$recipients) {
        throw new RuntimeException('FILEWATCH_ALERT_EMAILS is not configured');
    }

    if (
        FILEWATCH_SMTP_USERNAME === '' ||
        FILEWATCH_SMTP_USERNAME === 'YOUR_GMAIL@gmail.com' ||
        FILEWATCH_SMTP_PASSWORD === '' ||
        FILEWATCH_SMTP_PASSWORD === 'YOUR_16_CHAR_APP_PASSWORD'
    ) {
        throw new RuntimeException('SMTP credentials are not configured in filewatch_config.php');
    }

    $remote = 'tcp://' . FILEWATCH_SMTP_HOST . ':' . FILEWATCH_SMTP_PORT;

    $errno = 0;
    $errstr = '';

    $fp = @stream_socket_client(
        $remote,
        $errno,
        $errstr,
        FILEWATCH_SMTP_TIMEOUT,
        STREAM_CLIENT_CONNECT
    );

    if (!$fp) {
        throw new RuntimeException("SMTP connect failed: {$errno} {$errstr}");
    }

    stream_set_timeout($fp, FILEWATCH_SMTP_TIMEOUT);

    try {
        fw_smtp_expect($fp, [220]);

        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $ehlo = preg_replace('/[^a-z0-9.-]/i', '', $host);
        if (!$ehlo) {
            $ehlo = 'localhost';
        }

        fw_smtp_cmd($fp, 'EHLO ' . $ehlo, [250]);

        if (FILEWATCH_SMTP_ENCRYPTION === 'tls') {
            fw_smtp_cmd($fp, 'STARTTLS', [220]);

            $cryptoOk = @stream_socket_enable_crypto(
                $fp,
                true,
                STREAM_CRYPTO_METHOD_TLS_CLIENT
            );

            if ($cryptoOk !== true) {
                throw new RuntimeException('SMTP STARTTLS negotiation failed');
            }

            fw_smtp_cmd($fp, 'EHLO ' . $ehlo, [250]);
        }

        fw_smtp_cmd($fp, 'AUTH LOGIN', [334]);
        fw_smtp_cmd($fp, base64_encode(FILEWATCH_SMTP_USERNAME), [334]);
        fw_smtp_cmd($fp, base64_encode(FILEWATCH_SMTP_PASSWORD), [235]);

        fw_smtp_cmd($fp, 'MAIL FROM:<' . FILEWATCH_SMTP_FROM_EMAIL . '>', [250]);
        foreach ($recipients as $recipient) {
            fw_smtp_cmd($fp, 'RCPT TO:<' . $recipient . '>', [250, 251]);
        }
        fw_smtp_cmd($fp, 'DATA', [354]);

        $messageIdHost = preg_replace('/[^a-z0-9.-]/i', '', $_SERVER['HTTP_HOST'] ?? 'localhost');
        if (!$messageIdHost) {
            $messageIdHost = 'localhost';
        }

        $headers = [
            'Date: ' . date(DATE_RFC2822),
            'From: ' . fw_encode_header(FILEWATCH_SMTP_FROM_NAME) . ' <' . FILEWATCH_SMTP_FROM_EMAIL . '>',
            'To: ' . implode(', ', array_map(function ($email) { return '<' . $email . '>'; }, $recipients)),
            'Subject: ' . fw_encode_header($subject),
            'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . $messageIdHost . '>',
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
        ];

        $payload = implode("\r\n", $headers) . "\r\n\r\n" . fw_smtp_dot_stuff($body) . "\r\n.";

        if (@fwrite($fp, $payload . "\r\n") === false) {
            throw new RuntimeException('SMTP DATA write failed');
        }

        fw_smtp_expect($fp, [250]);
        @fwrite($fp, "QUIT\r\n");
        @fclose($fp);

        return true;
    } catch (Throwable $e) {
        @fclose($fp);
        throw $e;
    }
}

function fw_send_mail(string $subject, string $body): bool
{
    $recipients = fw_alert_recipients();

    if (!$recipients) {
        throw new RuntimeException('FILEWATCH_ALERT_EMAILS is not configured');
    }

    if (defined('FILEWATCH_MAIL_DRIVER') && FILEWATCH_MAIL_DRIVER === 'smtp') {
        return fw_send_smtp($subject, $body);
    }

    $host = preg_replace('/[^a-z0-9.-]/i', '', $_SERVER['HTTP_HOST'] ?? 'localhost');
    $from = 'filewatch@' . ($host ?: 'localhost');

    $headers = [
        'Content-Type: text/plain; charset=UTF-8',
        'From: FileWatch <' . $from . '>',
    ];

    return @mail($recipients[0], $subject, $body, implode("\r\n", $headers));
}

function fw_subject(string $mode, int $count): string
{
    $host = $_SERVER['HTTP_HOST'] ?? basename(filewatch_site_root());
    return "[FileWatch][$host][$mode] {$count} change(s)";
}
