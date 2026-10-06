[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$EncodedConfig)
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($EncodedConfig)) | ConvertFrom-Json
$output = [IO.Path]::GetFullPath([string]$config.output_dir)
$sample = [IO.Path]::GetFullPath([string]$config.sample_path)
$tools = [string]$config.tool_dir
function Save-Json($Path,$Object) { [IO.File]::WriteAllText($Path,($Object | ConvertTo-Json -Depth 16),$utf8) }
function Quote-WindowsArgument([string]$Value) {
    if ($Value -notmatch '[\s"]' -and $Value.Length -gt 0) { return $Value }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}
$launch = [ordered]@{sample_path=$sample;root_pid=$null;launch_time=[DateTime]::UtcNow.ToString('o');status='error';method='interactive_scheduled_task';trace=@{status='unavailable';detail='Non richiesta'};user=[Security.Principal.WindowsIdentity]::GetCurrent().Name}
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
    $session = (Get-Process -Id $PID).SessionId
    if ($identity -ine 'Quickemu' -or $session -eq 0) { $launch.status='denied'; throw 'Richiesta sessione interattiva Quickemu; vietato avvio come SYSTEM/servizio' }
    if (-not (Test-Path -LiteralPath $sample -PathType Leaf)) { throw 'Campione assente' }
    if ($output -ine 'C:\Sandbox' -and -not $output.StartsWith('C:\Sandbox\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Output fuori da C:\Sandbox' }
    $extension = [IO.Path]::GetExtension($sample).ToLowerInvariant()
    $executable = $null
    $arguments = @()
    switch ($extension) {
        '.exe' { $executable = $sample }
        '.ps1' { $executable = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"; $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$sample) }
        {$_ -in '.cmd','.bat'} {
            # cmd performs its own percent/metacharacter expansion: execute a fixed safe copy.
            if ($output -match '[&|<>^%!\r\n"]') { throw 'Percorso output non sicuro per cmd.exe' }
            $executionDir = Join-Path $output 'execution'
            New-Item -ItemType Directory -Force -Path $executionDir | Out-Null
            $copy = Join-Path $executionDir ('sample' + $extension)
            Copy-Item -LiteralPath $sample -Destination $copy -Force
            $executable = "$env:WINDIR\System32\cmd.exe"
            $arguments = @('/d','/s','/c',('""' + $copy + '""'))
            $launch.execution_path = $copy
        }
        '.py' {
            $sensors = Get-Content -LiteralPath (Join-Path $tools 'sensors.json') -Raw | ConvertFrom-Json
            if ($sensors.python.status -ne 'available') { $launch.status='unavailable'; throw 'Interprete Python guest non disponibile' }
            $executable = [string]$sensors.python.executable
            $arguments = @($sample)
        }
        default { $launch.status='unsupported'; throw 'Formato non eseguibile supportato: sola analisi statica; nessun driver .sys installato automaticamente' }
    }
    $argv = @($executable) + $arguments
    $launch.command = $argv
    if ($config.trace) {
        $sensors = Get-Content -LiteralPath (Join-Path $tools 'sensors.json') -Raw | ConvertFrom-Json
        if ($sensors.frida.status -eq 'available' -and (Test-Path -LiteralPath ([string]$sensors.frida.executable))) {
            $traceConfig = @{output_dir=$output;sample_path=$sample;argv=$argv;cwd=[IO.Path]::GetDirectoryName($sample);duration=[int]$config.duration;hooks_path=(Join-Path $tools 'hooks.js')}
            $tracePath = Join-Path $output 'trace-config.json'
            Save-Json $tracePath $traceConfig
            $traceArgs = @((Join-Path $tools 'frida_trace.py'),'--config',$tracePath)
            $traceCommand = ($traceArgs | ForEach-Object { Quote-WindowsArgument $_ }) -join ' '
            $supervisor = Start-Process -FilePath ([string]$sensors.frida.executable) -ArgumentList $traceCommand -PassThru -WindowStyle Hidden
            Save-Json (Join-Path $output 'trace-supervisor.json') @{pid=$supervisor.Id;status='started';time=[DateTime]::UtcNow.ToString('o')}
            $deadline = [DateTime]::UtcNow.AddSeconds(25)
            do {
                if (Test-Path -LiteralPath (Join-Path $output 'launch.json')) {
                    try { $traceLaunch = Get-Content -LiteralPath (Join-Path $output 'launch.json') -Raw | ConvertFrom-Json } catch { $traceLaunch=$null }
                    if ($traceLaunch -and $traceLaunch.root_pid) { return }
                    if ($traceLaunch -and $supervisor.HasExited) { break }
                }
                Start-Sleep -Milliseconds 200
                $supervisor.Refresh()
            } while ([DateTime]::UtcNow -lt $deadline -and -not $supervisor.HasExited)
            $supervisor.Refresh()
            # Do not start another copy while Frida might still spawn one.
            if (-not $supervisor.HasExited) { $launch.status='error'; throw 'Supervisore Frida non pronto: nessun avvio duplicato' }
            if (Test-Path -LiteralPath (Join-Path $output 'launch.json')) {
                $traceLaunch = Get-Content -LiteralPath (Join-Path $output 'launch.json') -Raw | ConvertFrom-Json
                if ($traceLaunch.root_pid) { return }
            }
            $launch.trace = @{status='error';detail='Frida fallita prima dello spawn; fallback esplicito al solo collector Sysmon'}
        } else { $launch.trace = @{status='unavailable';detail='Frida/venv offline non provisionata; nessuna traccia API simulata'} }
    }
    $launch.launch_time = [DateTime]::UtcNow.ToString('o')
    if ($extension -in '.cmd','.bat') {
        # Preserve cmd's documented /s /c double quoting verbatim.
        $commandLine = '/d /s /c ' + $arguments[3]
    } else { $commandLine = ($arguments | ForEach-Object { Quote-WindowsArgument $_ }) -join ' ' }
    if ($commandLine) { $process = Start-Process -FilePath $executable -ArgumentList $commandLine -WorkingDirectory ([IO.Path]::GetDirectoryName($sample)) -PassThru }
    else { $process = Start-Process -FilePath $executable -WorkingDirectory ([IO.Path]::GetDirectoryName($sample)) -PassThru }
    $launch.root_pid = $process.Id
    $launch.status = 'started'
    Save-Json (Join-Path $output 'launch.json') $launch
} catch {
    $launch.detail = $_.Exception.Message
    $native = $_.Exception
    while ($native -and $native -isnot [ComponentModel.Win32Exception]) { $native=$native.InnerException }
    if ($native) {
        $launch.native_error_code = $native.NativeErrorCode
        if ($native.NativeErrorCode -in @(225,226)) { $launch.status='blocked' }
        elseif ($native.NativeErrorCode -in @(5,740)) { $launch.status='denied' }
    }
    Save-Json (Join-Path $output 'launch.json') $launch
    exit 2
}
