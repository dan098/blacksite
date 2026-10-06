[CmdletBinding()]
param(
    [string]$ToolDir = 'C:\Sandbox\tools',
    [switch]$InstallPython,
    [switch]$InstallFrida
)
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force -Path $ToolDir | Out-Null
$privacyScript = Join-Path $ToolDir 'privacy.ps1'
if (-not (Test-Path -LiteralPath $privacyScript -PathType Leaf)) { throw 'Enforcement privacy fidato obbligatorio prima del setup' }
$privacy = (& $privacyScript -Mode apply -Nonce ([Guid]::NewGuid().ToString('N')) | ConvertFrom-Json)
if ($privacy.verified -ne $true -or $privacy.status -ne 'verified') { throw 'Privacy non verificata: provisionamento rifiutato' }
function Save-Json($Path, $Object) {
    [IO.File]::WriteAllText($Path, ($Object | ConvertTo-Json -Depth 14), $utf8)
}
function Status($State, $Detail) { return @{ status=$State; detail=$Detail } }
function Require-MicrosoftSignature([string]$Path) {
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid' -or $null -eq $sig.SignerCertificate -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') {
        throw "Firma Microsoft valida richiesta per il sensore: $Path ($($sig.Status))"
    }
}
function Native-Text([string]$File, [string[]]$Arguments) {
    # Sysmon writes informational banners to stderr; PS 5.1 must not treat them as fatal.
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $File
    $info.Arguments = ($Arguments | ForEach-Object { '"' + $_.Replace('"','\"') + '"' }) -join ' '
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.Encoding]::Unicode
    $info.StandardErrorEncoding = [Text.Encoding]::Unicode
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(120000)) { $process.Kill(); throw 'Timeout strumento di provisioning' }
        $text = $outTask.Result + "`n" + $errTask.Result
        if ($text.Length -gt 2097152) { throw 'Output strumento oltre limite' }
        return @{exitcode=$process.ExitCode;text=$text}
    } finally { $process.Dispose() }
}
$sensors = [ordered]@{
    sysmon=(Status 'unavailable' 'Binario non provisionato')
    procmon=(Status 'unavailable' 'Binario non provisionato')
    python=(Status 'unavailable' 'Interprete non provisionato')
    frida=(Status 'unavailable' 'Installazione opzionale non richiesta')
    defender=(Status 'unavailable' 'Stato da interrogare')
    privacy=$privacy
    channels=@{}
    prerequisites=@{
        sysmon='https://download.sysinternals.com/files/Sysmon.zip -> Sysmon64.exe'
        procmon='https://download.sysinternals.com/files/ProcessMonitor.zip -> Procmon64.exe'
        python='Installer ufficiale Python Windows x64 offline -> python-installer.exe (opzionale)'
        uv='https://github.com/astral-sh/uv/releases -> uv.exe Windows x64 (opzionale)'
        frida='Wheel Windows amd64 frida e dipendenze provisionati offline in frida-wheels (opzionale)'
    }
    safety=@{ defender_modified=$true; defender_local_protection_modified=$false; defender_exclusions_added=$false; cloud_submission_disabled=$true; guest_downloads=$false; untrusted_drivers_installed=$false }
}
# Reuse the official tools already installed in the clean source snapshot.
foreach ($binary in @('Sysmon64.exe','Procmon64.exe')) {
    $destination = Join-Path $ToolDir $binary
    $existingTool = Join-Path 'C:\Tools\Sysinternals' $binary
    if (-not (Test-Path -LiteralPath $destination) -and (Test-Path -LiteralPath $existingTool)) {
        Copy-Item -LiteralPath $existingTool -Destination $destination -Force
    }
}
try {
    $sysmon = Join-Path $ToolDir 'Sysmon64.exe'
    if (Test-Path -LiteralPath $sysmon) {
        Require-MicrosoftSignature $sysmon
        $schemaResult = Native-Text $sysmon @('-accepteula','-s')
        $schemaText = $schemaResult.text
        $schemaExit = $schemaResult.exitcode
        [IO.File]::WriteAllText((Join-Path $ToolDir 'sysmon-schema.txt'), $schemaText, $utf8)
        if ($schemaExit -ne 0) { throw "Sysmon schema exit=$schemaExit" }
        $begin = $schemaText.IndexOf('<manifest')
        $end = $schemaText.LastIndexOf('</manifest>')
        if ($begin -lt 0 -or $end -lt $begin) { throw 'Schema Sysmon non leggibile; installazione rifiutata' }
        [xml]$schema = $schemaText.Substring($begin, $end + 11 - $begin)
        [xml]$config = [IO.File]::ReadAllText((Join-Path $ToolDir 'sysmon.xml'))
        $schemaVersion = $schema.DocumentElement.GetAttribute('schemaversion')
        if ([string]::IsNullOrWhiteSpace($schemaVersion)) { throw 'schemaversion mancante' }
        $names = @($schema.SelectNodes('//event') | ForEach-Object { if ($_.HasAttribute('rulename')) { $_.GetAttribute('rulename') } elseif ($_.HasAttribute('ruleName')) { $_.GetAttribute('ruleName') } else { $_.GetAttribute('name') } })
        if ($names.Count -eq 0) { throw 'Definizioni eventi schema Sysmon assenti' }
        $requested = @($config.SelectNodes('/Sysmon/EventFiltering/RuleGroup/*'))
        foreach ($node in $requested) {
            if ($node.Name -notin $names) { throw "Evento non supportato dallo schema Sysmon installato: $($node.Name)" }
        }
        $config.DocumentElement.SetAttribute('schemaversion', $schemaVersion)
        $runtime = Join-Path $ToolDir 'sysmon-validated.xml'
        $config.Save($runtime)
        $existing = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue
        if ($existing) { $installResult = Native-Text $sysmon @('-accepteula','-c',$runtime) }
        else { $installResult = Native-Text $sysmon @('-accepteula','-i',$runtime) }
        $installOutput = $installResult.text
        $installExit = $installResult.exitcode
        [IO.File]::WriteAllText((Join-Path $ToolDir 'sysmon-install.txt'), $installOutput, $utf8)
        if ($installExit -ne 0) { throw "Validazione/installazione Sysmon fallita: exit=$installExit" }
        $service = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $service -or $service.Status -ne 'Running') { throw 'Servizio Sysmon non attivo' }
        $sensors.sysmon = @{status='available';detail='Schema controllato e configurazione accettata dal binario';schema_version=$schemaVersion;events=$requested.Name}
    }
} catch { $sensors.sysmon = Status 'error' $_.Exception.Message }
try {
    $procmon = Join-Path $ToolDir 'Procmon64.exe'
    if (Test-Path -LiteralPath $procmon) {
        Require-MicrosoftSignature $procmon
        $sensors.procmon = Status 'available' 'Sensore ufficiale firmato; cattura attivata solo nella VM isolata'
    }
} catch { $sensors.procmon = Status 'error' $_.Exception.Message }
$channels = @('Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-Windows Defender/Operational',
              'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-TaskScheduler/Operational',
              'Microsoft-Windows-CodeIntegrity/Operational')
foreach ($channel in $channels) {
    try {
        $result = (& wevtutil.exe sl $channel /e:true /ms:134217728 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) { throw $result }
        $sensors.channels[$channel] = Status 'available' 'Canale attivo; 128 MiB (possibile rollover)'
    } catch { $sensors.channels[$channel] = Status 'error' $_.Exception.Message }
}
try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    $sensors.defender = @{status='available';detail='Privacy cloud/submission verificata; protezione locale/servizio/realtime mantenuta';privacy=$privacy.defender;snapshot=@{
        AntivirusEnabled=$status.AntivirusEnabled;RealTimeProtectionEnabled=$status.RealTimeProtectionEnabled
        AMServiceEnabled=$status.AMServiceEnabled;AntivirusSignatureVersion=$status.AntivirusSignatureVersion
        AntivirusSignatureLastUpdated=$status.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')
    }}
} catch { $sensors.defender = Status 'unavailable' $_.Exception.Message }
try {
    $python = 'C:\Sandbox\Python\python.exe'
    if (-not (Test-Path -LiteralPath $python) -and $InstallPython) {
        $installer = Join-Path $ToolDir 'python-installer.exe'
        if (-not (Test-Path -LiteralPath $installer)) { throw 'Installer Python offline non provisionato' }
        $signature = Get-AuthenticodeSignature -LiteralPath $installer
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
            throw 'Firma Python Software Foundation valida richiesta'
        }
        $proc = Start-Process -FilePath $installer -ArgumentList @('/quiet','InstallAllUsers=1','TargetDir=C:\Sandbox\Python','Include_pip=0','Include_test=0','PrependPath=0') -Wait -PassThru
        if ($proc.ExitCode -notin @(0,3010)) { throw "Installer Python exit=$($proc.ExitCode)" }
    }
    if (-not (Test-Path -LiteralPath $python)) {
        $found = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($found -and $found.Source -notmatch 'WindowsApps') { $python = $found.Source }
    }
    if (Test-Path -LiteralPath $python) {
        $version = (& $python --version 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'Python non eseguibile' }
        $sensors.python = @{status='available';detail=$version;executable=$python}
    }
    if ($InstallFrida) {
        if ($sensors.python.status -ne 'available') { throw 'Python necessario per Frida' }
        $uv = Join-Path $ToolDir 'uv.exe'
        $wheels = Join-Path $ToolDir 'frida-wheels'
        if (-not (Test-Path -LiteralPath $uv) -or -not (Test-Path -LiteralPath $wheels)) { throw 'uv.exe o wheel offline assenti' }
        $venv = Join-Path $ToolDir 'frida-venv'
        $env:UV_OFFLINE = 'true'
        $env:UV_PYTHON_DOWNLOADS = 'never'
        & $uv venv --python $python --no-managed-python --no-python-downloads $venv
        if ($LASTEXITCODE -ne 0) { throw 'uv venv fallita' }
        $tracePython = Join-Path $venv 'Scripts\python.exe'
        & $uv pip install --python $tracePython --no-index --find-links $wheels frida
        if ($LASTEXITCODE -ne 0) { throw 'Installazione Frida offline fallita' }
        $version = (& $tracePython -c 'import frida; print(frida.__version__)' 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'Import Frida fallito' }
        $sensors.frida = @{status='available';detail="Frida $version user-mode; nessuna copertura syscall kernel";executable=$tracePython}
    }
} catch {
    if ($InstallFrida) { $sensors.frida = Status 'error' $_.Exception.Message }
    else { $sensors.python = Status 'error' $_.Exception.Message }
}
Save-Json (Join-Path $ToolDir 'sensors.json') $sensors
$required = @('privacy.ps1','collect.ps1','baseline.ps1','launch.ps1','sysmon.xml')
$missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $ToolDir $_)) })
$ready = $sensors.sysmon.status -eq 'available' -and $missing.Count -eq 0
Save-Json 'C:\Sandbox\provision.json' @{schema_version=1;ready=$ready;capabilities=$sensors;privacy=$privacy;missing_files=$missing;tool_dir=$ToolDir;provisioned_at=[DateTime]::UtcNow.ToString('o')}
$sensors | ConvertTo-Json -Depth 14
if ($sensors.sysmon.status -ne 'available') { exit 2 }
