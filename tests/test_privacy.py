import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from lab import vm


@pytest.fixture
def runtime(tmp_path):
    base = tmp_path / 'base'
    base.mkdir()
    for name in ('clean.qcow2', 'OVMF_VARS.fd', 'tpm2-00.permall'):
        (base / name).write_bytes(b'untouched-clean-base')
    (base / 'metadata.json').write_text(json.dumps({'ready': True}))
    instance = vm.AnalysisVM(tmp_path / 'run', base, {'id': 'standard'})
    instance.run_dir.mkdir()
    return instance


def proof_for(runtime):
    return {
        'schema_version': 1, 'nonce': runtime.uuid,
        'status': 'verified', 'verified': True,
        'verified_at': '2026-10-05T10:00:00Z', 'automatic_sample_uploads': False,
        'defender': {
            'MAPSReporting': 0, 'SubmitSamplesConsent': 2, 'CloudBlockLevel': 0,
            'DisableBlockAtFirstSeen': True, 'cloud_block_disabled': True,
            'AMServiceEnabled': True, 'AntivirusEnabled': True,
            'RealTimeProtectionEnabled': True, 'DisableRealtimeMonitoring': False,
            'local_configuration_unchanged': True, 'exclusions_added': False,
        },
        'edge': {
            'verified': True, 'browser_closed': True, 'profiles_reset': True,
            'policy_registry_verified': True, 'runtime_policy_adoption_verified': False,
            'auth_state_present': False, 'cookie_databases_remaining': 0,
            'authentication_rows_remaining': 0, 'identity_stores_remaining': 0,
            'profile_roots': [r'C:\Users\Quickemu'],
            'audited_roots': [r'C:\Users\Quickemu\AppData\Local\Microsoft\Edge\User Data'],
            'policies': {
                'BrowserSignin': 0, 'SyncDisabled': 1, 'NonRemovableProfileEnabled': 0,
                'ImplicitSignInEnabled': 0, 'WebToBrowserSignInEnabled': 0,
                'StartupBoostEnabled': 0, 'BackgroundModeEnabled': 0,
                'MetricsReportingEnabled': 0, 'DiagnosticData': 0,
                'SmartScreenEnabled': 0, 'SmartScreenPuaEnabled': 0,
                'SendSiteInfoToImproveServices': 0,
            },
        },
        'tools': {
            'verified': True, 'config_readback': True,
            'automatic_reputation': False, 'automatic_submission': False,
            'sysinternals': [{
                'verified': True,
                'autoruns': {'CheckVirusTotal': 0, 'SubmitUnknownImages': 0},
                'process_explorer': {'VirusTotalCheck': 0, 'VirusTotalSubmitUnknown': 0},
            }],
            'system_informer': [{
                'verified': True, 'online_checks_plugin_disabled': True,
                'automatic_reputation': False, 'automatic_submission': False,
            }],
        },
        'wer': {'verified': True, 'Disabled': 1, 'DontSendAdditionalData': 1, 'automatic_uploads': False},
        'mde': {
            'verified': True, 'onboarded': False, 'onboarding_state': 0,
            'onboarding_configuration_present': False, 'sense_status': 'Stopped',
        },
        'explorer': {'policy_verified': True, 'EnableSmartScreen': 0},
    }


@pytest.mark.parametrize('proof', [None, {}, {'status': 'verified', 'verified': True}])
def test_missing_privacy_proof_denies_before_any_guest_file_open(runtime, monkeypatch, tmp_path, proof):
    monkeypatch.setattr(runtime, '_assert_isolated', lambda: None)
    agent = Mock()
    monkeypatch.setattr(runtime, '_agent', agent)
    sample = tmp_path / 'sample.bin'
    sample.write_bytes(b'never-transfer')
    runtime.privacy = proof
    runtime._privacy_confirmed = True
    with pytest.raises(vm.PrivacyError, match='trasferimento rifiutato'):
        runtime.push(sample, r'C:\Sandbox\sample.bin')
    agent.assert_not_called()


@pytest.mark.parametrize(('section', 'key', 'value'), [
    ('defender', 'MAPSReporting', 2),
    ('defender', 'MAPSReporting', False),
    ('defender', 'SubmitSamplesConsent', 0),
    ('defender', 'SubmitSamplesConsent', '2'),
    ('defender', 'DisableBlockAtFirstSeen', False),
    ('defender', 'CloudBlockLevel', 2),
    ('defender', 'AMServiceEnabled', False),
    ('defender', 'AntivirusEnabled', False),
    ('defender', 'RealTimeProtectionEnabled', False),
    ('defender', 'DisableRealtimeMonitoring', True),
    ('defender', 'exclusions_added', True),
    ('edge', 'auth_state_present', True),
    ('edge', 'cookie_databases_remaining', 1),
    ('edge', 'authentication_rows_remaining', 1),
    ('edge', 'identity_stores_remaining', 1),
    ('edge', 'browser_closed', False),
    ('edge', 'runtime_policy_adoption_verified', True),
    ('tools', 'automatic_submission', True),
    ('tools', 'automatic_reputation', True),
    ('tools', 'system_informer', []),
    ('wer', 'Disabled', 0),
    ('mde', 'onboarding_state', 1),
    ('mde', 'sense_status', 'Running'),
    ('explorer', 'EnableSmartScreen', 1),
])
def test_wrong_effective_privacy_value_denies_sample(runtime, monkeypatch, tmp_path, section, key, value):
    proof = proof_for(runtime)
    assert runtime._validate_privacy_proof(proof)
    proof[section][key] = value
    runtime.privacy = proof
    runtime._privacy_confirmed = True
    monkeypatch.setattr(runtime, '_assert_isolated', lambda: None)
    transfer = Mock()
    monkeypatch.setattr(runtime, '_push_file', transfer)
    with pytest.raises(vm.PrivacyError):
        runtime.push(tmp_path / 'sample.bin', r'C:\Sandbox\sample.bin')
    transfer.assert_not_called()


@pytest.mark.parametrize(('key', 'value'), [('BrowserSignin', 1), ('SyncDisabled', 0), ('MetricsReportingEnabled', 1)])
def test_wrong_edge_policy_cannot_attest_no_login(runtime, key, value):
    proof = proof_for(runtime)
    proof['edge']['policies'][key] = value
    assert not runtime._validate_privacy_proof(proof)


def test_old_snapshot_or_metadata_cannot_supply_runtime_privacy(runtime):
    proof = proof_for(runtime)
    proof['nonce'] = '0' * 32
    assert not runtime._validate_privacy_proof(proof)
    assert runtime._privacy_confirmed is False
    assert runtime.capabilities['privacy']['verified'] is False


@pytest.mark.parametrize('failure', ['guest', 'desktop', 'denied', 'malformed', 'wrong_policy'])
def test_enforcement_failure_reaps_vm_without_sample_transfer(runtime, monkeypatch, failure):
    monkeypatch.setattr(runtime, '_assert_isolated', lambda: None)
    monkeypatch.setattr(runtime, 'wait_agent', lambda timeout: failure != 'guest')
    monkeypatch.setattr(runtime, 'wait_desktop', lambda timeout: failure != 'desktop')
    proof = proof_for(runtime)
    if failure == 'wrong_policy':
        proof['defender']['SubmitSamplesConsent'] = 1
    answers = iter([(0, '', ''), (1, '', 'tamper protection denied') if failure == 'denied' else
                    (0, 'not JSON' if failure == 'malformed' else json.dumps(proof), '')])
    monkeypatch.setattr(runtime, 'exec', lambda *args, **kwargs: next(answers))
    transfer = Mock()
    monkeypatch.setattr(runtime, '_push_file', transfer)
    stopped = Mock()
    monkeypatch.setattr(runtime, 'stop', stopped)
    with pytest.raises((vm.PrivacyError, ValueError)):
        runtime.ensure_privacy()
    stopped.assert_called_once()
    assert runtime._privacy_confirmed is False
    assert runtime.privacy['verified'] is False
    assert not (runtime.run_dir / 'privacy.json').exists()
    # If readiness passes, ONLY pinned repository privacy.ps1 can precede enforcement.
    for call in transfer.call_args_list:
        assert call.args[0] == Path(vm.__file__).resolve().parent.parent / 'guest' / 'privacy.ps1'
        assert call.args[1] == r'C:\Sandbox\tools\privacy.ps1'


def test_enforcement_persists_verified_proof_and_only_then_allows_public_push(runtime, monkeypatch, tmp_path):
    monkeypatch.setattr(runtime, '_assert_isolated', lambda: None)
    order = []
    monkeypatch.setattr(runtime, 'wait_agent', lambda timeout: order.append('guest') or True)
    monkeypatch.setattr(runtime, 'wait_desktop', lambda timeout: order.append('desktop') or True)
    proof = proof_for(runtime)
    def execute(command, timeout):
        order.append('enforce' if '-Mode apply' in command else 'mkdir')
        return (0, 'informational banner\n' + json.dumps(proof) + '\r\n', '') if '-Mode apply' in command else (0, '', '')
    monkeypatch.setattr(runtime, 'exec', execute)
    monkeypatch.setattr(runtime, '_push_file', lambda src, dst: order.append(('transfer', str(src), dst)))
    result = runtime.ensure_privacy()
    assert result['defender']['RealTimeProtectionEnabled'] is True
    assert json.loads((runtime.run_dir / 'privacy.json').read_text()) == result
    assert order[0:3] == ['guest', 'desktop', 'mkdir']
    assert order[3][0] == 'transfer' and order[3][2] == r'C:\Sandbox\tools\privacy.ps1'
    assert order[4] == 'enforce'
    result['verified'] = False  # callers cannot mutate the live stored proof
    assert runtime.privacy['verified'] is True
    sample = tmp_path / 'sample.bin'
    runtime.push(sample, r'C:\Sandbox\sample.bin')
    assert order[-1][2] == r'C:\Sandbox\sample.bin'
    assert (runtime.base_dir / 'clean.qcow2').read_bytes() == b'untouched-clean-base'


def test_standalone_start_enforces_privacy_before_return_for_base_maintenance(runtime, monkeypatch):
    runtime.profile['_maintenance'] = True
    monkeypatch.setattr(runtime, '_check_paths', lambda: None)
    monkeypatch.setattr(vm.subprocess, 'run', lambda *a, **k: runtime.overlay.write_bytes(b'overlay'))
    tpm = Mock()
    tpm.poll.return_value = None
    qemu = Mock()
    qemu.poll.return_value = None
    def launch(command, name, **kwargs):
        if name == 'tpm.log':
            runtime.tpm_socket.touch()
            return tpm
        (runtime.run_dir / 'namespace.json').write_text(json.dumps({'nonce': runtime.uuid, 'confirmed': True}))
        return qemu
    monkeypatch.setattr(runtime, '_launch', launch)
    monkeypatch.setattr(runtime, '_validate_start_proof', lambda *a: True)
    calls = []
    def enforce():
        assert runtime._started and runtime._isolation_confirmed
        calls.append('privacy')
        runtime.privacy = proof_for(runtime)
        runtime._privacy_confirmed = True
        return runtime.privacy
    monkeypatch.setattr(runtime, 'ensure_privacy', enforce)
    monkeypatch.setattr(runtime, '_kill_group', lambda *a: None)
    try:
        runtime.start()
        assert calls == ['privacy']
        assert json.loads((runtime.run_dir / 'vm.json').read_text())['privacy']['verified'] is True
    finally:
        runtime.stop()


def test_guest_privacy_only_modifies_cloud_defender_flags_and_never_disables_local_sensors():
    root = Path(vm.__file__).resolve().parent.parent
    script = (root / 'guest' / 'privacy.ps1').read_text()
    setters = [line.strip() for line in script.splitlines() if line.strip().startswith('Set-MpPreference ')]
    assert setters == ['Set-MpPreference -MAPSReporting 0 -SubmitSamplesConsent 2 -DisableBlockAtFirstSeen $true -CloudBlockLevel 0 -ErrorAction Stop']
    assert 'Add-MpPreference' not in script
    assert 'Stop-Service' not in script
    assert 'DisableRealtimeMonitoring $true' not in script
    assert "@('msedge','msedgewebview2') + $toolProcesses" in script
    assert "$browserHosts = @('Widgets','WidgetService')" in script
    assert "foreach ($name in @('SearchHost','SearchApp'))" in script
    assert 'NtSuspendProcess($process.Handle)' in script
    assert "Host Search non firmato Microsoft" in script
    assert "$process.Path.StartsWith('C:\\Windows\\SystemApps\\'" in script
    assert "foreach ($name in ($browserHosts + @('msedge','msedgewebview2') + $toolProcesses))" in script
    assert "while ($remaining.Count -and [DateTime]::UtcNow -lt $quiesceDeadline)" in script
    assert script.index("$browserHosts =") < script.index("$profiles =")
    assert 'for ($attempt = 0; $attempt -lt 6; $attempt++)' in script
    assert "($exception.HResult -band 0xffff) -notin @(32,33) -or $attempt -eq 5" in script
    assert script.index("foreach ($name in ($browserHosts + @('msedge','msedgewebview2')))") < script.index('if (Test-Path -LiteralPath $path) { Remove-Item')
    assert "'Sysmon64'" not in script and "'Procmon64'" not in script
    assert len(script.encode('utf-8')) <= vm.MAX_SCRIPT_BYTES


def test_guest_policy_keys_preserve_other_values_and_reparse_webview_fails_closed():
    root = Path(vm.__file__).resolve().parent.parent
    script = (root / 'guest' / 'privacy.ps1').read_text()
    assert 'if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }' in script
    assert 'if ($child.Name -match' in script and 'throw "Store WebView reparse non verificabile:' in script
    assert script.index('throw "Store WebView reparse non verificabile:') < script.index('            $count++')


def test_collector_refreshes_and_verifies_privacy_before_baseline_and_launch():
    root = Path(vm.__file__).resolve().parent.parent
    collector = (root / 'guest' / 'collect.ps1').read_text()
    assert "$ProgressPreference = 'SilentlyContinue'" in collector
    assert collector.count("privacy.ps1') -Mode apply -Nonce ") == 2
    assert collector.index("-Mode apply -Nonce $previousPrivacy.nonce") < collector.index('$baseline = Get-Baseline')
    assert collector.index("-Mode apply -Nonce $state.privacy.nonce") < collector.index("if (-not $SamplePath)")
