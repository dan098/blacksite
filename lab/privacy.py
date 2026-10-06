"""Validation of scoped trusted-tool privacy evidence, never a sample egress guarantee."""
from __future__ import annotations


def validate_privacy_proof(proof: dict, expected_nonce: str | None = None) -> bool:
    """Validate live evidence with a nonce, or persisted base evidence without live freshness."""
    if not isinstance(proof, dict):
        return False
    nonce = proof.get('nonce')
    if (not isinstance(nonce, str) or len(nonce) != 32
            or any(char not in '0123456789abcdef' for char in nonce)
            or (expected_nonce is not None and nonce != expected_nonce)):
        return False
    defender = proof.get('defender', {})
    edge = proof.get('edge', {})
    tools = proof.get('tools', {})
    wer = proof.get('wer', {})
    mde = proof.get('mde', {})
    explorer = proof.get('explorer', {})
    if not all(isinstance(item, dict) for item in (defender, edge, tools, wer, mde, explorer)):
        return False
    policies = edge.get('policies', {})
    if not isinstance(policies, dict):
        return False
    expected = {'MAPSReporting': 0, 'SubmitSamplesConsent': 2, 'CloudBlockLevel': 0}
    edge_expected = {'BrowserSignin': 0, 'SyncDisabled': 1, 'NonRemovableProfileEnabled': 0,
                     'ImplicitSignInEnabled': 0, 'WebToBrowserSignInEnabled': 0,
                     'StartupBoostEnabled': 0, 'BackgroundModeEnabled': 0,
                     'MetricsReportingEnabled': 0, 'DiagnosticData': 0,
                     'SmartScreenEnabled': 0, 'SmartScreenPuaEnabled': 0,
                     'SendSiteInfoToImproveServices': 0}

    def integers(data: dict, values: dict) -> bool:
        return all(type(data.get(key)) is int and data[key] == value for key, value in values.items())

    return (
        type(proof.get('schema_version')) is int and proof['schema_version'] == 1
        and proof.get('status') == 'verified' and proof.get('verified') is True
        and isinstance(proof.get('verified_at'), str) and bool(proof['verified_at'])
        and proof.get('automatic_sample_uploads') is False
        and integers(defender, expected)
        and all(defender.get(key) is True for key in (
            'DisableBlockAtFirstSeen', 'cloud_block_disabled', 'AMServiceEnabled',
            'AntivirusEnabled', 'RealTimeProtectionEnabled', 'local_configuration_unchanged'))
        and defender.get('DisableRealtimeMonitoring') is False
        and defender.get('exclusions_added') is False
        and integers(policies, edge_expected)
        and all(edge.get(key) is True for key in (
            'verified', 'browser_closed', 'profiles_reset', 'policy_registry_verified'))
        and edge.get('auth_state_present') is False
        # A registry readback is deliberately not proof of future unmanaged Edge adoption.
        and edge.get('runtime_policy_adoption_verified') is False
        and integers(edge, {'cookie_databases_remaining': 0, 'authentication_rows_remaining': 0,
                            'identity_stores_remaining': 0})
        and isinstance(edge.get('profile_roots'), list) and bool(edge['profile_roots'])
        and isinstance(edge.get('audited_roots'), list) and bool(edge['audited_roots'])
        and tools.get('verified') is True and tools.get('config_readback') is True
        and tools.get('automatic_reputation') is False and tools.get('automatic_submission') is False
        and isinstance(tools.get('sysinternals'), list) and bool(tools['sysinternals'])
        and isinstance(tools.get('system_informer'), list) and bool(tools['system_informer'])
        and all(isinstance(item, dict) and item.get('verified') is True
                and isinstance(item.get('autoruns'), dict)
                and integers(item['autoruns'], {'CheckVirusTotal': 0, 'SubmitUnknownImages': 0})
                and isinstance(item.get('process_explorer'), dict)
                and integers(item['process_explorer'], {'VirusTotalCheck': 0, 'VirusTotalSubmitUnknown': 0})
                for item in tools['sysinternals'])
        and all(isinstance(item, dict) and item.get('verified') is True
                and item.get('online_checks_plugin_disabled') is True
                and item.get('automatic_reputation') is False
                and item.get('automatic_submission') is False
                for item in tools['system_informer'])
        and wer.get('verified') is True and integers(wer, {'Disabled': 1, 'DontSendAdditionalData': 1})
        and wer.get('automatic_uploads') is False
        and mde.get('verified') is True and mde.get('onboarded') is False
        and integers(mde, {'onboarding_state': 0})
        and mde.get('onboarding_configuration_present') is False
        and mde.get('sense_status') in ('Stopped', 'not_installed')
        and explorer.get('policy_verified') is True and integers(explorer, {'EnableSmartScreen': 0})
    )
