<?php
declare(strict_types=1);

require_once __DIR__ . '/filewatch_lib.php';

fw_auth();

try {
    $state = fw_state();

    if (($state['paused'] ?? false) !== true) {
        fw_json_response([
            'ok' => true,
            'message' => 'FILEWATCH ALREADY ACTIVE',
        ]);
    }

    if (($state['baseline_created_after_pause'] ?? false) !== true) {
        fw_json_response([
            'ok' => false,
            'error' => 'Resume blocked: create a new baseline after planned changes first.',
        ], 409);
    }

    $state['paused'] = false;
    $state['pause_started_at'] = null;
    $state['baseline_created_after_pause'] = true;
    $state['last_alert_signature'] = '';
    $state['last_quick_signature'] = '';
    $state['last_full_signature'] = '';
    $state['last_alert_time'] = null;

    fw_save_state($state);

    fw_json_response([
        'ok' => true,
        'message' => 'FILEWATCH RESUMED',
    ]);
} catch (Throwable $e) {
    fw_json_response(['ok' => false, 'error' => $e->getMessage()], 500);
}
