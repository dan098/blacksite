[CmdletBinding()]
param(
    [ValidateSet('apply','audit')][string]$Mode = 'apply',
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce,
    [string]$ProofPath = 'C:\Sandbox\privacy.json'
)
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
if ($PSScriptRoot -ine 'C:\Sandbox\tools' -or $ProofPath -ine 'C:\Sandbox\privacy.json') {
    throw 'Privacy consentita solo nel guest di analisi C:\Sandbox\tools'
}
function Assert-PlainPath([string]$Path) {
    $item = $Path
    while ($item) {
        if (Test-Path -LiteralPath $item) {
            if ((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Percorso privacy reparse non consentito: $item"
            }
        }
        $parent = Split-Path -Parent $item
        if ($parent -eq $item) { break }
        $item = $parent
    }
}
function Set-CheckedDword([string]$Path,[string]$Name,[int]$Value) {
    if ($Mode -eq 'apply') {
        # Registry New-Item -Force recreates keys, erasing previously set policies.
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
    }
    $read = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
    if ($null -eq $read.$Name -or [int]$read.$Name -ne $Value) { throw "Policy non efficace: $Path $Name" }
}
function Get-LocalProtection($Preference) {
    # Compare, never modify local scanning switches or any exclusion.
    $result = [ordered]@{}
    foreach ($name in @('DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableIOAVProtection','DisableScriptScanning','DisableArchiveScanning','ExclusionPath','ExclusionExtension','ExclusionProcess','ExclusionIpAddress','AttackSurfaceReductionOnlyExclusions')) {
        $result[$name] = $Preference.$name
    }
    return ($result | ConvertTo-Json -Depth 8 -Compress)
}
function Get-ChildDirectories([string]$Root) {
    # Explicit traversal avoids following junctions; unreadable directories are not a clean audit.
    if (-not (Test-Path -LiteralPath $Root)) { return }
    Assert-PlainPath $Root
    $pending = New-Object 'System.Collections.Generic.Queue[string]'
    $pending.Enqueue($Root)
    $count = 0
    while ($pending.Count) {
        $path = $pending.Dequeue()
        foreach ($child in @(Get-ChildItem -LiteralPath $path -Directory -Force -ErrorAction Stop)) {
            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                # A browser-store junction is a privacy failure, not missing/clean coverage.
                if ($child.Name -match '^(EBWebView|.*\.WebView2)$') { throw "Store WebView reparse non verificabile: $($child.FullName)" }
                continue
            }
            $count++
            if ($count -gt 60000) { throw 'Audit directory privacy oltre limite; nessun esito pulito' }
            $child.FullName
            # Browser profiles are reset as a whole; their descendants need not be walked.
            if ($child.Name -notmatch '^(EBWebView|.*\.WebView2)$') { $pending.Enqueue($child.FullName) }
        }
    }
}
function Set-InformerConfig([string]$Path) {
    Assert-PlainPath $Path
    if (Test-Path -LiteralPath $Path) { [xml]$xml = [IO.File]::ReadAllText($Path) }
    elseif ($Mode -eq 'apply') { [xml]$xml = '<settings></settings>' }
    else { throw "Configurazione System Informer mancante: $Path" }
    if ($xml.DocumentElement.Name -ne 'settings') { throw "Formato System Informer non supportato: $Path" }
    $values = [ordered]@{
        'OnlineChecks.EnableScanning'='0'
        'OnlineChecks.VirusTotalEnableLookups'='0'
        'OnlineChecks.HybridAnalysisEnableLookups'='0'
        'OnlineChecks.HybridAnalysisEnableAutoSubmit'='0'
        'ProcessHacker.OnlineChecks.EnableVirusTotalScanning'='0'
    }
    $disabled = $xml.SelectSingleNode('/settings/setting[@name="DisabledPlugins"]')
    $plugins = @()
    if ($disabled) { $plugins = @($disabled.InnerText.Split('|') | Where-Object { $_ }) }
    $values['DisabledPlugins'] = ((@($plugins | Where-Object { $_ -ine 'OnlineChecks.dll' }) + @('OnlineChecks.dll')) -join '|')
    foreach ($entry in $values.GetEnumerator()) {
        $nodes = @($xml.SelectNodes('/settings/setting[@name="'+$entry.Key+'"]'))
        if ($Mode -eq 'apply') {
            foreach ($node in $nodes) { [void]$xml.DocumentElement.RemoveChild($node) }
            $node = $xml.CreateElement('setting')
            $node.SetAttribute('name',$entry.Key)
            $node.InnerText = $entry.Value
            [void]$xml.DocumentElement.AppendChild($node)
        } elseif ($nodes.Count -ne 1 -or $nodes[0].InnerText -ne $entry.Value) {
            throw "OnlineChecks non disabilitato: $Path $($entry.Key)"
        }
    }
    if ($Mode -eq 'apply') {
        New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
        $xml.Save($Path)
        [xml]$read = [IO.File]::ReadAllText($Path)
        foreach ($entry in $values.GetEnumerator()) {
            $nodes = @($read.SelectNodes('/settings/setting[@name="'+$entry.Key+'"]'))
            if ($nodes.Count -ne 1 -or $nodes[0].InnerText -ne $entry.Value) { throw "Readback System Informer fallito: $Path" }
        }
    }
    return @{path=$Path;verified=$true;online_checks_plugin_disabled=$true;automatic_reputation=$false;automatic_submission=$false;settings=$values}
}
Assert-PlainPath $PSScriptRoot
$before = Get-MpPreference -ErrorAction Stop
$localBefore = Get-LocalProtection $before
if ($Mode -eq 'apply' -and ([int]$before.MAPSReporting -ne 0 -or [int]$before.SubmitSamplesConsent -ne 2 -or $before.DisableBlockAtFirstSeen -ne $true -or [int]$before.CloudBlockLevel -ne 0)) {
    Set-MpPreference -MAPSReporting 0 -SubmitSamplesConsent 2 -DisableBlockAtFirstSeen $true -CloudBlockLevel 0 -ErrorAction Stop
}
$deadline = [DateTime]::UtcNow.AddSeconds(15)
do {
    $preference = Get-MpPreference -ErrorAction Stop
    $defenderOK = $null -ne $preference.MAPSReporting -and [int]$preference.MAPSReporting -eq 0 -and $null -ne $preference.SubmitSamplesConsent -and [int]$preference.SubmitSamplesConsent -eq 2 -and $preference.DisableBlockAtFirstSeen -eq $true -and $null -ne $preference.CloudBlockLevel -and [int]$preference.CloudBlockLevel -eq 0
    if ($defenderOK -or $Mode -eq 'audit') { break }
    Start-Sleep -Milliseconds 500
} while ([DateTime]::UtcNow -lt $deadline)
$status = Get-MpComputerStatus -ErrorAction Stop
if (-not $defenderOK) { throw 'Defender cloud/submission policy non efficace (possibile tamper protection); campione rifiutato' }
if ($status.AMServiceEnabled -ne $true -or $status.AntivirusEnabled -ne $true -or $status.RealTimeProtectionEnabled -ne $true -or $preference.DisableRealtimeMonitoring -ne $false) {
    throw 'Defender locale/servizio/realtime non attivo; campione rifiutato'
}
if ((Get-LocalProtection $preference) -ne $localBefore) { throw 'La configurazione della protezione locale o esclusioni è cambiata; campione rifiutato' }
$edgePolicy = [ordered]@{BrowserSignin=0;SyncDisabled=1;NonRemovableProfileEnabled=0;ImplicitSignInEnabled=0;WebToBrowserSignInEnabled=0;StartupBoostEnabled=0;BackgroundModeEnabled=0;MetricsReportingEnabled=0;DiagnosticData=0;SmartScreenEnabled=0;SmartScreenPuaEnabled=0;SendSiteInfoToImproveServices=0}
foreach ($entry in $edgePolicy.GetEnumerator()) { Set-CheckedDword 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' $entry.Key $entry.Value }
# Disable background cloud Search/highlights that recreate WebView
# account-capable stores. Keep local search/indexing, explorer and antivirus running.
Set-CheckedDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCloudSearch' 0
Set-CheckedDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'EnableDynamicContentInWSB' 0
Set-CheckedDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'ConnectedSearchUseWeb' 0
Set-CheckedDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'DisableWebSearch' 1
foreach ($profile in @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.Loaded -and $_.LocalPath -imatch '^C:\\Users\\' })) {
    $userHive = 'Registry::HKEY_USERS\' + $profile.SID
    if (-not (Test-Path -LiteralPath $userHive)) { throw 'Hive utente caricato non accessibile per policy Search' }
    Set-CheckedDword ($userHive+'\Software\Policies\Microsoft\Windows\Explorer') 'DisableSearchBoxSuggestions' 1
    Set-CheckedDword ($userHive+'\Software\Microsoft\Windows\CurrentVersion\SearchSettings') 'IsDynamicSearchBoxEnabled' 0
    Set-CheckedDword ($userHive+'\Software\Microsoft\Windows\CurrentVersion\Search') 'BingSearchEnabled' 0
}
Set-CheckedDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 0
$explorer = @{policy_verified=$true;EnableSmartScreen=0;readback='HKLM\SOFTWARE\Policies\Microsoft\Windows\System; registry policy, not an attestation of arbitrary executable traffic'}
# WER reporting is disabled; independent local crash dumps and existing analysis sensors remain.
Set-CheckedDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1
Set-CheckedDword 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1
Set-CheckedDword 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' 'DontSendAdditionalData' 1
Set-CheckedDword 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps' 'DumpType' 1
Set-CheckedDword 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps' 'DumpCount' 10
$wer = @{verified=$true;Disabled=1;DontSendAdditionalData=1;automatic_uploads=$false;local_dumps=@{DumpType=1;DumpCount=10;independent_of_reporting=$true};readback='HKLM policy and WER/LocalDumps registry'}
# Never silently switch off or offboard EDR. Enrollment is a hard privacy blocker.
$mdeState = 0
$mdeStatusPath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
if (Test-Path -LiteralPath $mdeStatusPath) {
    $mdeStatus = Get-ItemProperty -LiteralPath $mdeStatusPath -ErrorAction Stop
    if ($null -ne $mdeStatus.OnboardingState) { $mdeState = [int]$mdeStatus.OnboardingState }
}
$onboardingPresent = $false
foreach ($path in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection','HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection')) {
    if (Test-Path -LiteralPath $path) {
        $configuration = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace([string]$configuration.OnboardingInfo)) { $onboardingPresent=$true }
    }
}
$sense = Get-Service -Name Sense -ErrorAction SilentlyContinue
if ($mdeState -ne 0 -or $onboardingPresent -or ($sense -and $sense.Status -eq 'Running')) {
    throw 'MDE/Sense attivo o onboarding presente: invii EDR non verificabili; campione rifiutato'
}
$mde = @{verified=$true;onboarded=$false;onboarding_state=$mdeState;onboarding_configuration_present=$false;sense_status=$(if($sense){[string]$sense.Status}else{'not_installed'});readback='MDE OnboardingState, onboarding configuration presence and Sense service; no enrollment secrets exported'}
$toolProcesses = @('autoruns','autoruns64','autoruns64a','procexp','procexp64','procexp64a','SystemInformer','ProcessHacker')
$pausedSearchHosts = @{}
if ($Mode -eq 'apply') {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SandboxSearchHostControl {
    [DllImport("ntdll.dll")]
    public static extern int NtSuspendProcess(IntPtr handle);
}
'@ -ErrorAction Stop
}
function Suspend-SearchHosts {
    # Killing SearchHost makes AppModel relaunch it. Freeze only signed Windows
    # Search hosts for this disposable guest's lifetime; never explorer or sensors.
    foreach ($name in @('SearchHost','SearchApp')) {
        foreach ($process in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            if ($pausedSearchHosts.ContainsKey([string]$process.Id)) { continue }
            if (-not $process.Path.StartsWith('C:\Windows\SystemApps\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Host Search fuori dal percorso Windows fidato' }
            $signature = Get-AuthenticodeSignature -LiteralPath $process.Path
            if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft') { throw 'Host Search non firmato Microsoft' }
            if ([SandboxSearchHostControl]::NtSuspendProcess($process.Handle) -ne 0) { throw 'Impossibile sospendere il solo host Search cloud' }
            $pausedSearchHosts[[string]$process.Id] = $process.ProcessName
        }
    }
}
if ($Mode -eq 'apply') {
    # Suspend Search hosts before closing their WebViews; stop Widgets hosts.
    # Keep explorer, desktop, Defender, QGA and sensors running.
    $browserHosts = @('Widgets','WidgetService')
    $quiesceDeadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        Suspend-SearchHosts
        foreach ($name in ($browserHosts + @('msedge','msedgewebview2') + $toolProcesses)) {
            Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Milliseconds 500
        $remaining = @(Get-Process -Name (@('msedge','msedgewebview2') + $toolProcesses) -ErrorAction SilentlyContinue)
    } while ($remaining.Count -and [DateTime]::UtcNow -lt $quiesceDeadline)
}
if (@(Get-Process -Name (@('msedge','msedgewebview2') + $toolProcesses) -ErrorAction SilentlyContinue).Count) {
    throw ('Browser o tool cloud ancora attivo; reset/audit non sicuro: ' + (($remaining | ForEach-Object { $_.ProcessName }) -join ', '))
}
$profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) })
if (-not @($profiles | Where-Object { $_.LocalPath -imatch '\\Quickemu$' }).Count) { throw 'Profilo Quickemu assente; audit privacy incompleto' }
$profileRoots = @($profiles.LocalPath) + @('C:\Users\Default','C:\Windows\SysWOW64\config\systemprofile')
$profileRoots += @(Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction Stop | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | ForEach-Object { $_.FullName })
$profileRoots = @($profileRoots | Where-Object { Test-Path -LiteralPath $_ } | Sort-Object -Unique)
$resetRoots = New-Object 'System.Collections.Generic.List[string]'
$configs = New-Object 'System.Collections.Generic.List[string]'
foreach ($root in $profileRoots) {
    Assert-PlainPath $root
    $local = Join-Path $root 'AppData\Local'
    foreach ($relative in @('Microsoft\Edge\User Data','Microsoft\Edge Beta\User Data','Microsoft\Edge Dev\User Data','Microsoft\Edge SxS\User Data','Microsoft\EdgeWebView','Microsoft\IdentityCache','Microsoft\OneAuth','Microsoft\TokenBroker','Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker')) {
        $resetRoots.Add((Join-Path $local $relative))
    }
    foreach ($directory in @(Get-ChildDirectories $local)) {
        if ((Split-Path -Leaf $directory) -match '^(EBWebView|.*\.WebView2)$') { $resetRoots.Add($directory) }
    }
    $configs.Add((Join-Path $root 'AppData\Roaming\SystemInformer\settings.xml'))
    $configs.Add((Join-Path $root 'AppData\Roaming\Process Hacker 2\settings.xml'))
}
$resetRoots = @($resetRoots | Sort-Object -Unique)
$removed = @()
foreach ($path in $resetRoots) {
    Assert-PlainPath $path
    if ($Mode -eq 'apply' -and (Test-Path -LiteralPath $path)) {
        # Full reset avoids relying on encrypted values, guessed cookie domains or SQLite versions.
        # Profile enumeration can outlast the initial quiescence. Re-close hosts here
        # and allow only bounded retries for transient sharing/lock violations.
        for ($attempt = 0; $attempt -lt 6; $attempt++) {
            Suspend-SearchHosts
            foreach ($name in ($browserHosts + @('msedge','msedgewebview2'))) {
                Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            }
            Start-Sleep -Milliseconds 400
            Assert-PlainPath $path
            try {
                if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop }
                break
            } catch {
                $exception = $_.Exception
                while ($exception.InnerException) { $exception = $exception.InnerException }
                if (($exception.HResult -band 0xffff) -notin @(32,33) -or $attempt -eq 5) { throw }
                Start-Sleep -Milliseconds 500
            }
        }
        $removed += $path
    }
    if (Test-Path -LiteralPath $path) { throw "Profilo/cookie/identità Edge-WebView ancora presente: $path" }
}
# Audit loaded hives and offline profile hives; never touch any host or Rewards file.
$registryProof = @()
foreach ($profile in $profiles) {
    $hive = 'Registry::HKEY_USERS\'+$profile.SID
    $mounted = $false
    if (-not (Test-Path -LiteralPath $hive)) {
        $ntuser = Join-Path $profile.LocalPath 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $ntuser)) {
            if ($profile.Special) { continue }
            throw "Hive utente assente: $($profile.LocalPath)"
        }
        Assert-PlainPath $ntuser
        $mountName = 'SandboxPrivacy_'+[Guid]::NewGuid().ToString('N')
        & reg.exe load ('HKU\'+$mountName) $ntuser | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Caricamento hive privacy fallito' }
        $hive = 'Registry::HKEY_USERS\'+$mountName
        $mounted = $true
    }
    try {
        $autoruns = $hive+'\Software\Sysinternals\Autoruns'
        $procexp = $hive+'\Software\Sysinternals\Process Explorer'
        Set-CheckedDword $autoruns 'CheckVirusTotal' 0
        Set-CheckedDword $autoruns 'SubmitUnknownImages' 0
        Set-CheckedDword $procexp 'VirusTotalCheck' 0
        Set-CheckedDword $procexp 'VirusTotalSubmitUnknown' 0
        $registryProof += @{sid=$profile.SID;autoruns=@{CheckVirusTotal=0;SubmitUnknownImages=0};process_explorer=@{VirusTotalCheck=0;VirusTotalSubmitUnknown=0};verified=$true}
    } finally {
        if ($mounted) {
            [GC]::Collect();[GC]::WaitForPendingFinalizers()
            & reg.exe unload ('HKU\'+$mountName) | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Rilascio hive privacy fallito' }
        }
    }
}
# Portable settings beside executables override AppData. Cover installed analysis conventions.
$installRoots = @('C:\Tools','C:\Sandbox\tools','C:\Program Files\SystemInformer','C:\Program Files\System Informer','C:\Program Files\Process Hacker 2')
$informerExecutables = @()
foreach ($root in $installRoots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    Assert-PlainPath $root
    foreach ($directory in (@($root) + @(Get-ChildDirectories $root))) {
        foreach ($file in @(Get-ChildItem -LiteralPath $directory -File -Force -ErrorAction Stop)) {
            if ($file.Name -imatch '^(SystemInformer|ProcessHacker)\.exe$') { $informerExecutables += $file.FullName }
            if ($file.Name -imatch '^(SystemInformer|ProcessHacker)\.exe\.settings\.xml$') { $configs.Add($file.FullName) }
            if ($file.Name -imatch '^(SystemInformer|ProcessHacker)\.exe\.settings\.json$') { throw 'System Informer JSON settings non supportate: richiesta verifica esplicita' }
        }
    }
}
# Force a verified portable XML beside each installed binary (known XML-format releases).
foreach ($exe in $informerExecutables) { $configs.Add(($exe+'.settings.xml')) }
$informerProof = @()
foreach ($config in @($configs | Sort-Object -Unique)) { $informerProof += Set-InformerConfig $config }
foreach ($path in $resetRoots) {
    if (Test-Path -LiteralPath $path) { throw "Stato browser ricreato durante audit: $path" }
}
if (@(Get-Process -Name @('msedge','msedgewebview2') -ErrorAction SilentlyContinue).Count) { throw 'Browser riavviato durante audit; privacy non verificata' }
# Publish a fresh effective Defender readback, not the pre-reset snapshot.
$preference = Get-MpPreference -ErrorAction Stop
$status = Get-MpComputerStatus -ErrorAction Stop
if ($null -eq $preference.MAPSReporting -or [int]$preference.MAPSReporting -ne 0 -or $null -eq $preference.SubmitSamplesConsent -or [int]$preference.SubmitSamplesConsent -ne 2 -or $preference.DisableBlockAtFirstSeen -ne $true -or $null -eq $preference.CloudBlockLevel -or [int]$preference.CloudBlockLevel -ne 0 -or $preference.DisableRealtimeMonitoring -ne $false -or $status.AMServiceEnabled -ne $true -or $status.AntivirusEnabled -ne $true -or $status.RealTimeProtectionEnabled -ne $true -or (Get-LocalProtection $preference) -ne $localBefore) {
    throw 'Readback finale Defender cambiato/non conforme; privacy non verificata'
}
$proof = [ordered]@{
    schema_version=1;status='verified';verified=$true;nonce=$Nonce;verified_at=[DateTime]::UtcNow.ToString('o')
    automatic_sample_uploads=$false
    scope='Trusted Defender, WER, Sysinternals and System Informer automatic submissions; no onboarded MDE; pre-sample Edge/WebView account state. Signed Windows Search hosts suspended in this disposable analysis guest to prevent background WebView relaunch; Explorer, desktop and local antivirus remain active. Browser/Explorer registry policies configured, future runtime adoption not attested. Not a block on arbitrary sample Internet traffic or future explicit user uploads.'
    defender=@{MAPSReporting=[int]$preference.MAPSReporting;SubmitSamplesConsent=[int]$preference.SubmitSamplesConsent;DisableBlockAtFirstSeen=[bool]$preference.DisableBlockAtFirstSeen;CloudBlockLevel=[int]$preference.CloudBlockLevel;cloud_block_disabled=$true;AMServiceEnabled=[bool]$status.AMServiceEnabled;AntivirusEnabled=[bool]$status.AntivirusEnabled;RealTimeProtectionEnabled=[bool]$status.RealTimeProtectionEnabled;DisableRealtimeMonitoring=[bool]$preference.DisableRealtimeMonitoring;IsTamperProtected=$status.IsTamperProtected;AntivirusSignatureVersion=$status.AntivirusSignatureVersion;local_configuration_unchanged=$true;exclusions_added=$false;readback='Get-MpPreference + Get-MpComputerStatus'}
    windows_search=@{suspended_signed_hosts=$pausedSearchHosts;scope='analysis guest lifetime only';local_search_ui_may_be_unavailable=$true;explorer_stopped=$false;indexing_service_stopped=$false}
    edge=@{verified=$true;policies=$edgePolicy;policy_registry_verified=$true;runtime_policy_adoption_verified=$false;policy_readback='HKLM\SOFTWARE\Policies\Microsoft\Edge; future runtime adoption not verified, some policies require managed enterprise Edge';browser_closed=$true;profiles_reset=$true;auth_state_present=$false;cookie_databases_remaining=0;authentication_rows_remaining=0;identity_stores_remaining=0;profile_roots=$profileRoots;audited_roots=$resetRoots;removed_roots=$removed;audit_method='Whole-profile/auth-store reset and verified absence: no cookie database or identity file remains in these roots. Nonstandard future application stores are not attested.'}
    tools=@{verified=$true;sysinternals=$registryProof;system_informer=$informerProof;informer_executables=$informerExecutables;automatic_reputation=$false;automatic_submission=$false;config_readback=$true;settings_sources=@('https://download.sysinternals.com/files/Autoruns.zip','https://download.sysinternals.com/files/ProcessExplorer.zip','https://github.com/winsiderss/systeminformer/blob/v3.2.25011.2103/plugins/OnlineChecks/onlnchk.h','https://github.com/winsiderss/systeminformer/blob/master/plugins/OnlineChecks/onlnchk.h','https://github.com/winsiderss/systeminformer/blob/master/SystemInformer/plugin.c')}
    wer=$wer;mde=$mde;explorer=$explorer
}
$json = $proof | ConvertTo-Json -Depth 16 -Compress
[IO.File]::WriteAllText($ProofPath,$json,$utf8)
$json
