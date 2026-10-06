from copy import deepcopy

from lab.telemetry import attach_kernel, normalize
from lab.worker import redacted_share


def test_kernel_is_separate_from_user_mode_nt_and_all_events_are_retained(monkeypatch):
    dynamic = normalize({}, api_events=[{'api': 'ntdll.dll!NtCreateFile', 'pid': 7, 'time': '2026-10-02T10:00:00Z'}])
    original_nt = deepcopy(dynamic['syscall_chain'])
    report = {'status': 'partial', 'events': [
        {'id': 'kernel:1', 'kind': 'syscall_enter', 'pid': 7, 'tid': 8, 'time': '2026-10-02T10:00:00Z',
         'syscall_address': '0xffff800012345678', 'related': True, 'raw': {'opcode': 51}},
        {'id': 'kernel:2', 'kind': 'stackwalk', 'pid': 4, 'tid': 1, 'related': False, 'raw': {'opcode': 32}}],
        'counts': {'events': 2, 'syscall_enter': 1, 'stackwalk': 1},
        'coverage': {'full_coverage': False, 'loss': {'events_lost': 3}}, 'warnings': ['ETW loss observed']}
    monkeypatch.setattr('lab.kernel.normalize_kernel', lambda raw, processes: report)
    result = attach_kernel(dynamic, {}, requested=True)
    assert result['syscall_chain'] == original_nt
    assert result['counts']['kernel_syscalls'] == 1
    assert result['counts']['kernel_events'] == 2
    assert result['counts']['events'] == 2
    assert result['counts']['related_events'] == 1
    assert result['counts']['by_category'] == {'syscall': 1, 'kernel': 1}
    assert result['events'][0]['source'] == 'microsoft_kernel_etw'
    assert result['capabilities']['kernel']['status'] == 'partial'
    assert result['coverage']['kernel']['full_coverage'] is False
    assert 'ETW loss observed' in result['warnings']


def test_unavailable_kernel_never_becomes_available_from_user_mode_calls(monkeypatch):
    dynamic = normalize({}, api_events=[{'api': 'ntdll.dll!NtCreateFile'}])
    monkeypatch.setattr('lab.kernel.normalize_kernel', lambda raw, processes: {
        'status': 'unavailable', 'events': [], 'counts': {}, 'warnings': [], 'coverage': {}})
    result = attach_kernel(dynamic, {}, requested=True)
    assert result['capabilities']['kernel']['status'] == 'unavailable'
    assert result['counts']['kernel_syscalls'] == 0
    assert any('nessuna copertura' in item for item in result['warnings'])


def test_shared_kernel_contains_only_count_and_status_not_payloads_or_receipts():
    job = {'id': 'a'*32, 'name': 'private.ps1', 'sha256': 'b'*64, 'status': 'partial', 'created_at': 'now',
           'runs': [{'profile': 'trace', 'status': 'partial', 'dynamic': {
               'counts': {'kernel_events': 100, 'kernel_syscalls': 50, 'kernel_stacks': 20},
               'capabilities': {'kernel': {'status': 'partial', 'detail': 'C:\\private\\secret'}},
               'kernel': {'events': [{'syscall_address': 'private'}], 'receipts': {'commands': 'private'}},
               'payloads': {'payloads': [{'source_path': 'C:\\private', 'artifact_name': 'payload-000.bin'}]}}}]}
    shared = redacted_share(job)
    dynamic = shared['runs'][0]['dynamic']
    assert dynamic['counts']['kernel_syscalls'] == 50
    assert dynamic['capabilities']['kernel'] == {'status': 'partial'}
    assert 'kernel' not in dynamic and 'payloads' not in dynamic
    assert 'private' not in str(shared) and 'syscall_address' not in str(shared)
