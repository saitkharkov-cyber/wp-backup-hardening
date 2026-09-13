<?php
declare(strict_types=1);

require_once __DIR__ . '/filewatch_lib.php';

fw_auth();

try {
    $host = $_SERVER['HTTP_HOST'] ?? basename(filewatch_site_root());
    $subject = "[FileWatch][$host] TEST SMTP";
    $body =
        "FileWatch SMTP test message\n" .
        "Site: " . $host . "\n" .
        "Time: " . date('Y-m-d H:i:s') . "\n" .
        "Transport: " . FILEWATCH_MAIL_DRIVER . "\n\n" .
        "If you received this message, FileWatch SMTP delivery is working.";

    $sent = fw_send_mail($subject, $body);

    fw_json_response([
        'ok' => true,
        'transport' => FILEWATCH_MAIL_DRIVER,
        'mail_attempted' => true,
        'mail_sent' => $sent,
        'recipients' => fw_alert_recipients(),
        'smtp_host' => FILEWATCH_SMTP_HOST,
        'smtp_port' => FILEWATCH_SMTP_PORT,
        'note' => $sent
            ? 'SMTP server accepted the message.'
            : 'Message was not accepted.',
    ]);
} catch (Throwable $e) {
    fw_json_response([
        'ok' => false,
        'transport' => defined('FILEWATCH_MAIL_DRIVER') ? FILEWATCH_MAIL_DRIVER : 'unknown',
        'mail_attempted' => true,
        'mail_sent' => false,
        'error' => $e->getMessage(),
    ], 500);
}
