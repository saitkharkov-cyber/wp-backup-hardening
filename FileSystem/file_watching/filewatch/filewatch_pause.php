<?php
declare(strict_types=1);

require_once __DIR__ . '/filewatch_lib.php';

fw_auth();

try {
    $state = fw_state();

    if (($state['paused'] ?? false) === true) {
        fw_json_response([
            'ok' => true,
            'message' => 'FILEWATCH ALREADY PAUSED',
            'pause_started_at' => $state['pause_started_at'] ?? null,
            'baseline_created_after_pause' => (bool)($state['baseline_created_after_pause'] ?? false),
        ]);
    }

    $state['paused'] = true;
    $state['pause_started_at'] = date('c');
    $state['baseline_created_after_pause'] = false;
    $state['last_alert_signature'] = '';
    $state['last_quick_signature'] = '';
    $state['last_full_signature'] = '';
    $state['last_alert_time'] = null;

    fw_save_state($state);

    fw_json_response([
        'ok' => true,
        'message' => 'FILEWATCH PAUSED',
        'pause_started_at' => $state['pause_started_at'],
        'resume_requires_new_baseline' => true,
    ]);
} catch (Throwable $e) {
    fw_json_response(['ok' => false, 'error' => $e->getMessage()], 500);
}
