<?php
declare(strict_types=1);

require_once __DIR__ . '/filewatch_lib.php';

fw_auth();

$mode = isset($_GET['mode']) && $_GET['mode'] === 'full' ? 'full' : 'quick';

try {
    $state = fw_state();

    if (($state['paused'] ?? false) === true) {
        fw_json_response([
            'ok' => true,
            'mode' => $mode,
            'status' => 'paused',
            'message' => 'FILEWATCH PAUSED',
            'pause_started_at' => $state['pause_started_at'] ?? null,
            'baseline_created_after_pause' => (bool)($state['baseline_created_after_pause'] ?? false),
        ]);
    }

    $baselineDoc = fw_read_json(fw_path('baseline.json'));

    if (!$baselineDoc || !isset($baselineDoc['objects']) || !is_array($baselineDoc['objects'])) {
        fw_json_response([
            'ok' => false,
            'error' => 'Baseline not found. Run filewatch_init.php first.',
        ], 409);
    }

    $baseline = $baselineDoc['objects'];

    if ($mode === 'quick') {
        $result = fw_scan_metadata($baseline);
        $current = $result['snapshot'];
        $diff = fw_diff($baseline, $current);
        $count = fw_diff_count($diff);
        $sig = fw_diff_signature($diff);

        $mailAttempted = false;
        $mailSent = false;
        $suppressed = false;

        if ($count > 0) {
            if ($sig !== ($state['last_quick_signature'] ?? ($state['last_alert_signature'] ?? ''))) {
                $mailAttempted = true;
                $body = fw_build_report($diff, $baseline, $current, 'QUICK');
                $mailSent = fw_send_mail(fw_subject('QUICK', $count), $body);

                $state['last_quick_signature'] = $sig;
                $state['last_alert_signature'] = $sig; // backward compatibility
                $state['last_alert_time'] = date('c');
                fw_save_state($state);
            } else {
                $suppressed = true;
            }
        } elseif (($state['last_quick_signature'] ?? ($state['last_alert_signature'] ?? '')) !== '') {
            $state['last_quick_signature'] = '';
            $state['last_alert_signature'] = '';
            $state['last_alert_time'] = null;
            fw_save_state($state);
        }

        fw_json_response([
            'ok' => true,
            'mode' => 'quick',
            'status' => 'active',
            'changes' => $count,
            'stats' => $result['stats'],
            'mail_attempted' => $mailAttempted,
            'mail_sent' => $mailSent,
            'same_alert_suppressed' => $suppressed,
            'diff' => $diff,
        ]);
    }

    /*
     * FULL SHA-256 mode, порциями.
     */
    $files = [];
    foreach ($baseline as $path => $entry) {
        if (($entry['type'] ?? '') === 'file') {
            $files[] = $path;
        }
    }
    sort($files, SORT_STRING);

    $total = count($files);
    $cursor = max(0, (int)($state['full_cursor'] ?? 0));

    if ($cursor >= $total) {
        $cursor = 0;
    }

    if ($cursor === 0) {
        $state['full_cycle_started'] = date('c');
    }

    $started = microtime(true);
    $checked = 0;
    $changed = [];

    for ($i = $cursor; $i < $total; $i++) {
        $rel = $files[$i];
        $abs = filewatch_site_root() . '/' . str_replace('/', DIRECTORY_SEPARATOR, $rel);

        if (!is_file($abs)) {
            $changed[] = [
                'path' => $rel,
                'reason' => 'missing',
                'old_sha256' => $baseline[$rel]['sha256'] ?? null,
                'new_sha256' => null,
            ];
        } else {
            $hash = @hash_file('sha256', $abs);
            $old = $baseline[$rel]['sha256'] ?? null;

            if ($hash === false || $old === null || !hash_equals((string)$old, (string)$hash)) {
                $changed[] = [
                    'path' => $rel,
                    'reason' => $hash === false ? 'hash_failed' : 'sha256_mismatch',
                    'old_sha256' => $old,
                    'new_sha256' => $hash === false ? null : $hash,
                ];
            }
        }

        $checked++;
        $state['full_cursor'] = $i + 1;

        if (
            $checked >= FILEWATCH_FULL_MAX_FILES_PER_RUN ||
            (microtime(true) - $started) >= FILEWATCH_TIME_BUDGET
        ) {
            break;
        }
    }

    $cycleDone = ($state['full_cursor'] >= $total);

    if ($cycleDone) {
        $state['full_cursor'] = 0;
    }

    $mailAttempted = false;
    $mailSent = false;

    if ($changed) {
        $diff = [
            'directory_added' => [],
            'directory_deleted' => [],
            'file_added' => [],
            'file_deleted' => [],
            'file_modified' => [],
        ];

        foreach ($changed as $item) {
            if ($item['reason'] === 'missing') {
                $diff['file_deleted'][] = $item['path'];
            } else {
                $diff['file_modified'][] = [
                    'path' => $item['path'],
                    'old_sha256' => $item['old_sha256'],
                    'new_sha256' => $item['new_sha256'],
                ];
            }
        }

        $sig = fw_diff_signature($diff);

        if ($sig !== ($state['last_full_signature'] ?? '')) {
            $mailAttempted = true;
            $body = fw_build_report($diff, $baseline, $baseline, 'FULL');
            $mailSent = fw_send_mail(fw_subject('FULL', fw_diff_count($diff)), $body);

            $state['last_full_signature'] = $sig;
            $state['last_alert_time'] = date('c');
        }
    }

    fw_save_state($state);

    fw_json_response([
        'ok' => true,
        'mode' => 'full',
        'status' => 'active',
        'checked_this_run' => $checked,
        'files_total' => $total,
        'next_cursor' => $state['full_cursor'],
        'cycle_done' => $cycleDone,
        'changes_this_run' => count($changed),
        'seconds' => round(microtime(true) - $started, 3),
        'mail_attempted' => $mailAttempted,
        'mail_sent' => $mailSent,
    ]);

} catch (Throwable $e) {
    fw_json_response(['ok' => false, 'error' => $e->getMessage()], 500);
}
