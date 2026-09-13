<?php
declare(strict_types=1);

require_once __DIR__ . '/filewatch_lib.php';

fw_auth();

try {
    $state = fw_state();
    $baseline = fw_read_json(fw_path('baseline.json'));

    fw_json_response([
        'ok' => true,
        'version' => '2.4.1',
        'paused' => (bool)($state['paused'] ?? false),
        'pause_started_at' => $state['pause_started_at'] ?? null,
        'baseline_exists' => isset($baseline['objects']) && is_array($baseline['objects']),
        'baseline_created_at' => $baseline['created_at'] ?? null,
        'baseline_created_after_pause' => (bool)($state['baseline_created_after_pause'] ?? false),
        'resume_allowed' => (($state['paused'] ?? false) !== true) || (($state['baseline_created_after_pause'] ?? false) === true),
        'last_alert_time' => $state['last_alert_time'] ?? null,
        'quick_alert_signature_set' => !empty($state['last_quick_signature'] ?? $state['last_alert_signature'] ?? ''),
        'full_alert_signature_set' => !empty($state['last_full_signature'] ?? ''),
        'full_cursor' => (int)($state['full_cursor'] ?? 0),
    ]);
} catch (Throwable $e) {
    fw_json_response(['ok' => false, 'error' => $e->getMessage()], 500);
}
