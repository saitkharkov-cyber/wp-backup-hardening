<?php
	// filewatch version 2.4.1
declare(strict_types=1);

require_once __DIR__ . '/filewatch_lib.php';

fw_auth();

try {
    $state = fw_state();

    /*
     * Разрешаем rebaseline и во время паузы.
     * Если baseline создан после pause, resume станет разрешён.
     */
    $result = fw_scan_metadata(null);

    $baseline = [
        'created_at' => date('c'),
        'site_root' => filewatch_site_root(),
        'objects' => $result['snapshot'],
    ];

    fw_write_json_atomic(fw_path('baseline.json'), $baseline);

    $state['last_alert_signature'] = '';
    $state['last_quick_signature'] = '';
    $state['last_full_signature'] = '';
    $state['last_alert_time'] = null;
    $state['full_cursor'] = 0;
    $state['full_cycle_started'] = null;

    if (($state['paused'] ?? false) === true) {
        $state['baseline_created_after_pause'] = true;
    } else {
        $state['baseline_created_after_pause'] = true;
    }

    fw_save_state($state);

    fw_json_response([
        'ok' => true,
        'message' => 'BASELINE CREATED',
        'paused' => (bool)($state['paused'] ?? false),
        'resume_allowed' => true,
        'data_dir' => filewatch_data_dir(),
        'stats' => $result['stats'],
        'objects_total' => count($result['snapshot']),
    ]);
} catch (Throwable $e) {
    fw_json_response([
        'ok' => false,
        'error' => $e->getMessage(),
    ], 500);
}
