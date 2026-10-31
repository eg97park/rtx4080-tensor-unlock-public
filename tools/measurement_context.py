"""Validate recorded Windows/display observations offline; no device access."""
import datetime
import re


def instant(value):
    try:
        result = datetime.datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise ValueError('invalid context timestamp') from error
    if result.tzinfo is None:
        raise ValueError('context timestamps must include timezone')
    return result


def validate_context(context):
    try:
        if context['schema_version'] != 1:
            raise ValueError('unknown context schema')
        session, display = context['session'], context['display']
        for field in ('windows_directory', 'system_drive', 'volume_serial', 'os_version', 'os_build'):
            if not isinstance(session[field], str) or not session[field]:
                raise ValueError('missing Windows session identity')
        if not re.fullmatch(r'[A-Za-z]:', session['system_drive']) or not re.fullmatch(r'[0-9A-Fa-f]{8}', session['volume_serial']):
            raise ValueError('invalid Windows volume identity')
        if instant(session['boot_utc']) > instant(context['captured_utc']):
            raise ValueError('context predates Windows boot')
        if (not display['adapter_path'].upper().startswith('\\\\?\\PCI#VEN_8086&DEV_7D67&') or
            not display['monitor_path'].upper().startswith('\\\\?\\DISPLAY#SAME069#') or
            display['path_flags'] != 9 or display['technology'] != 5 or
            display['width'] != 3840 or display['height'] != 2160):
            raise ValueError('unexpected measurement display')
        for field in ('source_id', 'target_id', 'rotation', 'scaling', 'scanline', 'clone_group',
                      'refresh_numerator', 'refresh_denominator'):
            if type(display[field]) is not int or display[field] < 0:
                raise ValueError('invalid display metadata')
        if display['refresh_numerator'] == 0 or display['refresh_denominator'] == 0:
            raise ValueError('invalid display refresh')
        luid = display['adapter_luid']
        if not isinstance(luid, list) or len(luid) != 2 or any(type(x) is not int for x in luid):
            raise ValueError('invalid boot-local display identity')
        words = display['mode_words']
        if (not isinstance(words, list) or len(words) != 3 or
            any(not isinstance(mode, list) or len(mode) != 6 or
                any(not isinstance(word, str) or not re.fullmatch('[0-9a-f]{16}', word) for word in mode)
                for mode in words)):
            raise ValueError('incomplete display timing words')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('incomplete measurement context') from error
    return context


def same_context(before, after):
    validate_context(before)
    validate_context(after)
    if any(before[key] != after[key] for key in ('session', 'display')):
        raise ValueError('Windows session or display changed')


def validate_run_context(run):
    """Legacy runs remain usable, explicitly without automatic context evidence."""
    if run.get('schema_version') == 1:
        if 'context_checks' in run:
            raise ValueError('context checks require measurement schema 2')
        return None
    if run.get('schema_version') != 2:
        raise ValueError('unknown measurement schema')
    checks = run.get('context_checks')
    stages = ['baseline']
    for index in range(len(run['cases'])):
        stages.extend([f'case-{index}-before', f'case-{index}-after'])
    stages.append('final')
    if not isinstance(checks, list) or len(checks) != len(stages):
        raise ValueError('incomplete measurement context checkpoints')
    previous, end = instant(run['start_utc']), instant(run['end_utc'])
    for check, stage in zip(checks, stages):
        same_context(checks[0], check)
        captured = instant(check['captured_utc'])
        if check.get('stage') != stage or not previous <= captured <= end:
            raise ValueError('context checkpoint order or time mismatch')
        previous = captured
    return checks[0]


def comparison_context(a, b):
    """Boot-local handles may change between boots; display timings may not."""
    before, after = validate_run_context(a), validate_run_context(b)
    result = {'before_recorded': before is not None, 'after_recorded': after is not None,
              'same_display_conditions': None, 'same_windows_installation': None,
              'same_boot_session': None}
    if before and after:
        result['same_display_conditions'] = (
            {k: v for k, v in before['display'].items() if k != 'adapter_luid'} ==
            {k: v for k, v in after['display'].items() if k != 'adapter_luid'})
        result['same_windows_installation'] = (
            {k: v for k, v in before['session'].items() if k != 'boot_utc'} ==
            {k: v for k, v in after['session'].items() if k != 'boot_utc'})
        result['same_boot_session'] = (before['session'] == after['session'])
    return result
