[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('prepare','launch','finish')][string]$Mode,
    [string]$SamplePath,
    [string]$OutputDir = 'C:\Sandbox',
    [ValidateRange(15,600)][int]$Duration = 60,
    [switch]$Trace,
    [switch]$Kernel
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$ToolDir = $PSScriptRoot
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
if ($OutputDir -ine 'C:\Sandbox' -and -not $OutputDir.StartsWith('C:\Sandbox\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Output consentito solo in C:\Sandbox' }
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
. (Join-Path $ToolDir 'baseline.ps1')
function Save-Json($Path,$Object,[long]$MaxBytes=201326592) {
    $json = $Object | ConvertTo-Json -Depth 24 -Compress
    if ($utf8.GetByteCount($json) -gt $MaxBytes) { throw "Artefatto JSON oltre limite $MaxBytes byte: $Path" }
    [IO.File]::WriteAllText($Path,$json,$utf8)
}
function Read-Json($Path) { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json) }
function State($Status,$Detail) { return @{status=$Status;detail=$Detail} }
function Quote-Argument([string]$Value) { return '"' + [regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1') + '"' }
function Run-Tool([string]$File,[string[]]$Arguments,[int]$Timeout=60,[int[]]$AcceptedCodes=@(0)) {
    $command = ($Arguments | ForEach-Object { Quote-Argument $_ }) -join ' '
    $process = Start-Process -FilePath $File -ArgumentList $command -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit($Timeout*1000)) {
        try { $process.Kill() } catch {}
        throw "Timeout $Timeout secondi: $File"
    }
    if ($process.ExitCode -notin $AcceptedCodes) { throw "$File exit=$($process.ExitCode)" }
}
function Get-Events([string]$Channel,[DateTime]$Start,[DateTime]$End,[string]$Name,[int]$Cap=50000) {
    $items = New-Object 'System.Collections.Generic.List[object]'
    $result = @{events=@();status='completed';detail='Finestra UTC';truncated=$false;bytes=0;xml_bytes=0;cap=$Cap;channel=$Channel}
    $jsonlPath = Join-Path $OutputDir ($Name+'.jsonl')
    $writer = New-Object IO.StreamWriter($jsonlPath,$false,$utf8)
    $xmlWriter = New-Object IO.StreamWriter((Join-Path $OutputDir ($Name+'.xml')),$false,$utf8)
    $xmlWriter.WriteLine('<Events>')
    try {
        $log = Get-WinEvent -ListLog $Channel -ErrorAction Stop
        if (-not $log.IsEnabled) { throw 'Canale disabilitato' }
        $a=$Start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
        $b=$End.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
        $query = "*[System[TimeCreated[@SystemTime>='$a' and @SystemTime<='$b']]]"
        $result.query = $query
        # FilterHashtable interprets DateTime through the guest timezone; XML uses explicit UTC.
        try { $records = Get-WinEvent -LogName $Channel -FilterXPath $query -MaxEvents ($Cap+1) -Oldest -ErrorAction Stop }
        catch {
            if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { $records=@() }
            else { throw }
        }
        foreach ($record in $records) {
            if ($items.Count -ge $Cap) { $result.truncated=$true;break }
            $rawXml = $record.ToXml()
            [xml]$xml = $rawXml
            $data = [ordered]@{}
            $fieldCut = $false
            foreach ($node in $xml.Event.EventData.Data) {
                $key = $node.GetAttribute('Name')
                if (-not $key) { $key='Data'+$data.Count }
                $value = $node.InnerText
                if ($value.Length -gt 32768) { $value=$value.Substring(0,32768);$fieldCut=$true }
                $data[$key]=$value
            }
            if ($xml.Event.UserData) {
                $userData = $xml.Event.UserData.InnerXml
                $data.UserData = $userData.Substring(0,[Math]::Min($userData.Length,32768))
                if ($userData.Length -gt 32768) { $fieldCut=$true }
            }
            $event = @{event_id=[int]$record.Id;record_id=[long]$record.RecordId;time=$record.TimeCreated.ToUniversalTime().ToString('o');provider=$record.ProviderName;data=$data;fields_truncated=$fieldCut}
            $line = $event | ConvertTo-Json -Depth 12 -Compress
            $bytes = $utf8.GetByteCount($line)+1
            $xmlBytes = $utf8.GetByteCount($rawXml)+1
            if ($result.bytes+$bytes -gt 67108864 -or $result.xml_bytes+$xmlBytes -gt 67108864) { $result.truncated=$true;break }
            $writer.WriteLine($line)
            $xmlWriter.WriteLine($rawXml)
            $result.xml_bytes += $xmlBytes
            $result.bytes += $bytes
            $items.Add($event)
            if ($fieldCut) { $result.truncated=$true }
        }
        $result.events = $items.ToArray()
        if ($result.truncated) { $result.status='partial';$result.detail='Limite eventi/64 MiB/campi raggiunto; log EVTX separato quando esportabile' }
    } catch { $result.events=$items.ToArray();$result.status=$(if($items.Count){'partial'}else{'unavailable'});$result.detail=$_.Exception.Message }
    finally { $writer.Close();$xmlWriter.WriteLine('</Events>');$xmlWriter.Close() }
    return $result
}
function Export-Evtx([string]$Channel,[DateTime]$Start,[DateTime]$End,[string]$Name) {
    $path = Join-Path $OutputDir ($Name+'.evtx')
    $a=$Start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
    $b=$End.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
    $query = "*[System[TimeCreated[@SystemTime>='$a' and @SystemTime<='$b']]]"
    try {
        $text = (& wevtutil.exe epl $Channel $path "/q:$query" /ow:true 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) { throw $text }
        $size = (Get-Item -LiteralPath $path).Length
        if ($size -gt 134217728) { throw 'EVTX oltre 128 MiB: non esportabile con il limite artefatti' }
        return @{status='completed';path=$path;bytes=$size;query=$query}
    } catch { return @{status='error';detail=$_.Exception.Message;path=$path;max_bytes=134217728} }
}
function Get-Defender([DateTime]$Start,[DateTime]$End) {
    $events = Get-Events 'Microsoft-Windows-Windows Defender/Operational' $Start $End 'defender' 10000
    $result = @{status=$events.status;events=$events.events;detections=@();status_snapshot=@{};event_coverage=$events;warnings=@()}
    $result.event_coverage.Remove('events')
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $result.status_snapshot = @{AntivirusEnabled=$status.AntivirusEnabled;RealTimeProtectionEnabled=$status.RealTimeProtectionEnabled;AMServiceEnabled=$status.AMServiceEnabled;AntivirusSignatureVersion=$status.AntivirusSignatureVersion;AntivirusSignatureLastUpdated=$status.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o');BehaviorMonitorEnabled=$status.BehaviorMonitorEnabled;IoavProtectionEnabled=$status.IoavProtectionEnabled;IsTamperProtected=$status.IsTamperProtected}
        $preference = Get-MpPreference -ErrorAction Stop
        $result.cloud_policy_snapshot = @{MAPSReporting=[int]$preference.MAPSReporting;SubmitSamplesConsent=[int]$preference.SubmitSamplesConsent;DisableBlockAtFirstSeen=$preference.DisableBlockAtFirstSeen;CloudBlockLevel=[int]$preference.CloudBlockLevel;DisableRealtimeMonitoring=$preference.DisableRealtimeMonitoring;readback='Get-MpPreference, post-execution (not pre-transfer proof)'}
        $ageDays = [Math]::Floor(([DateTime]::UtcNow - $status.AntivirusSignatureLastUpdated.ToUniversalTime()).TotalDays)
        $result.status_snapshot.AntivirusSignatureAgeDays = $ageDays
        $result.signature_status = $(if ($ageDays -gt 7) { 'stale' } else { 'current' })
        if ($ageDays -gt 7) { $result.warnings += "Firme Defender vecchie di $ageDays giorni: il guest isolato non aggiorna via Internet. Nessun hit non prova innocuita." }
        $result.status_query = State 'completed' 'Solo lettura; nessuna impostazione Defender modificata'
    } catch { $result.status_query=State 'unavailable' $_.Exception.Message;$result.warnings += $_.Exception.Message }
    try {
        $detections = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object {
            ($_.InitialDetectionTime -and $_.InitialDetectionTime.ToUniversalTime() -ge $Start -and $_.InitialDetectionTime.ToUniversalTime() -le $End) -or
            ($_.LastThreatStatusChangeTime -and $_.LastThreatStatusChangeTime.ToUniversalTime() -ge $Start -and $_.LastThreatStatusChangeTime.ToUniversalTime() -le $End)
        } | Select-Object -First 10001)
        $result.detections = @($detections | Select-Object -First 10000 | ForEach-Object {
            @{id=('defender-detection:'+$_.DetectionID);DetectionID=[string]$_.DetectionID;ThreatID=[string]$_.ThreatID;ProcessName=$_.ProcessName;Resources=@($_.Resources | Select-Object -First 128);ActionSuccess=$_.ActionSuccess;ThreatStatusID=$_.ThreatStatusID;CurrentThreatExecutionStatusID=$_.CurrentThreatExecutionStatusID;InitialDetectionTime=$_.InitialDetectionTime.ToUniversalTime().ToString('o');LastThreatStatusChangeTime=$_.LastThreatStatusChangeTime.ToUniversalTime().ToString('o')}
        })
        $result.detection_query = @{status=$(if($detections.Count -gt 10000){'partial'}else{'completed'});cap=10000;truncated=($detections.Count -gt 10000)}
    } catch { $result.detection_query=State 'unavailable' $_.Exception.Message;$result.warnings += $_.Exception.Message }
    if ($result.status_query.status -ne 'completed' -or $result.detection_query.status -ne 'completed') {
        if ($result.status -eq 'completed') { $result.status='partial' }
    }
    $result.assessment = 'no_hit_not_clean'
    if ($result.detections.Count -gt 0 -or @($result.events | Where-Object {$_.event_id -eq 1116}).Count -gt 0) { $result.assessment='detections_observed' }
    return $result
}
$statePath = Join-Path $OutputDir 'collector-state.json'
try {
    switch ($Mode) {
        'prepare' {
            if (Test-Path -LiteralPath $statePath) { throw 'Directory run già preparata: non sovrascrivere baseline/evidenze' }
            if (-not (Test-Path -LiteralPath 'C:\Sandbox\privacy.json')) { throw 'Proof privacy pre-trasferimento assente' }
            $previousPrivacy = Read-Json 'C:\Sandbox\privacy.json'
            if ($previousPrivacy.status -ne 'verified' -or $previousPrivacy.verified -ne $true) { throw 'Proof privacy non verificata' }
            $privacy = (& (Join-Path $ToolDir 'privacy.ps1') -Mode apply -Nonce $previousPrivacy.nonce | ConvertFrom-Json)
            if ($privacy.status -ne 'verified' -or $privacy.verified -ne $true) { throw 'Audit privacy non conforme; campione rifiutato' }
            Save-Json (Join-Path $OutputDir 'privacy.json') $privacy
            $acl = Get-Acl -LiteralPath $OutputDir
            $rule = New-Object Security.AccessControl.FileSystemAccessRule(($env:COMPUTERNAME+'\Quickemu'),'Modify','ContainerInherit,ObjectInherit','None','Allow')
            $acl.SetAccessRule($rule)
            Set-Acl -LiteralPath $OutputDir -AclObject $acl
            $sensors = @{}
            if (Test-Path -LiteralPath (Join-Path $ToolDir 'sensors.json')) { $sensors=Read-Json (Join-Path $ToolDir 'sensors.json') }
            $baseline = Get-Baseline $OutputDir
            Save-Json (Join-Path $OutputDir 'baseline-before.json') $baseline
            $state = @{schema_version=1;sample_path=$SamplePath;duration=$Duration;trace=[bool]$Trace;tool_dir=$ToolDir;prepared_at=[DateTime]::UtcNow.ToString('o');start_time=[DateTime]::UtcNow.ToString('o');sensors=$sensors;warnings=@();baseline_coverage=$baseline.coverage;procmon=@{status='unavailable';detail='Procmon non provisionato'}}
            $state.privacy = $privacy
            $state.procmon_clock = @{local_at_start=[DateTimeOffset]::Now.ToString('o');utc_at_start=[DateTime]::UtcNow.ToString('o');offset_minutes=[DateTimeOffset]::Now.Offset.TotalMinutes;time_zone_id=[TimeZoneInfo]::Local.Id}
            $procmon = Join-Path $ToolDir 'Procmon64.exe'
            if ($sensors.procmon.status -eq 'available' -and (Test-Path -LiteralPath $procmon)) {
                try {
                    $pml = Join-Path $OutputDir 'procmon.pml'
                    # /NoFilter explicitly removes any preset; no system-image denylist.
                    $args = @('/AcceptEula','/Quiet','/Minimized','/NoFilter','/BackingFile',$pml,'/Runtime',([string]($Duration+180)))
                    $process = Start-Process -FilePath $procmon -ArgumentList (($args | ForEach-Object {Quote-Argument $_}) -join ' ') -WindowStyle Hidden -PassThru
                    Run-Tool $procmon @('/WaitForIdle') 30
                    $state.procmon = @{status='available';detail='Cattura PML senza filtri; limite 256 MiB monitorato';pid=$process.Id;max_bytes=268435456}
                    # Separate bounded watcher closes capture if sample floods the sensor.
                    $watch = '$p='+$process.Id+';$f='+"'"+$pml.Replace("'","''")+"'"+';$until=[DateTime]::UtcNow.AddSeconds('+($Duration+180)+');while([DateTime]::UtcNow -lt $until){if(-not(Get-Process -Id $p -ErrorAction SilentlyContinue)){break};if((Test-Path -LiteralPath $f) -and (Get-Item -LiteralPath $f).Length -ge 268435456){& '+"'"+$procmon.Replace("'","''")+"'"+' /Terminate;[IO.File]::WriteAllText('+"'"+(Join-Path $OutputDir 'procmon-cap.txt').Replace("'","''")+"'"+',"PML cap reached");break};Start-Sleep -Milliseconds 500}'
                    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($watch))
                    $watcher = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-EncodedCommand',$encoded) -WindowStyle Hidden -PassThru
                    $state.procmon.watcher_pid=$watcher.Id
                } catch { $state.procmon=State 'error' $_.Exception.Message;$state.warnings += $_.Exception.Message }
            }
            $state.kernel = State 'unavailable' 'Tracing kernel non richiesto'
            if ($Kernel) {
                try {
                    & (Join-Path $ToolDir 'kernel_trace.ps1') -Mode start -OutputDir $OutputDir | Out-Null
                    $state.kernel = Read-Json (Join-Path $OutputDir 'kernel_start.json')
                } catch {
                    $state.kernel = State 'unavailable' $_.Exception.Message
                    $state.warnings += 'Tracing kernel non avviato: '+$_.Exception.Message
                }
            }
            Save-Json $statePath $state
            Save-Json (Join-Path $OutputDir 'sensors.json') $sensors
            @{status='prepared';start_time=$state.start_time;baseline=$baseline.coverage;procmon=$state.procmon} | ConvertTo-Json -Depth 12
        }
        'launch' {
            if (-not (Test-Path -LiteralPath $statePath)) { throw 'Prepare richiesto prima del lancio' }
            $state = Read-Json $statePath
            $privacy = (& (Join-Path $ToolDir 'privacy.ps1') -Mode apply -Nonce $state.privacy.nonce | ConvertFrom-Json)
            if ($privacy.status -ne 'verified' -or $privacy.verified -ne $true) { throw 'Audit privacy prima del lancio non conforme' }
            if (-not $SamplePath) { $SamplePath=$state.sample_path }
            if (-not $SamplePath -or -not (Test-Path -LiteralPath $SamplePath -PathType Leaf)) { throw 'Campione mancante' }
            if (Test-Path -LiteralPath (Join-Path $OutputDir 'launch.json')) { throw 'Campione già avviato o rifiutato: nessun lancio duplicato' }
            $principal = New-ScheduledTaskPrincipal -UserId ($env:COMPUTERNAME+'\Quickemu') -LogonType Interactive -RunLevel Limited
            $config = @{output_dir=$OutputDir;sample_path=$SamplePath;tool_dir=$ToolDir;duration=$Duration;trace=([bool]$Trace -or [bool]$state.trace)}
            $encoded = [Convert]::ToBase64String($utf8.GetBytes(($config | ConvertTo-Json -Compress)))
            $launcher = Join-Path $ToolDir 'launch.ps1'
            $action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -ExecutionPolicy Bypass -File '+(Quote-Argument $launcher)+' -EncodedConfig '+$encoded)
            $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds ($Duration+90)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            $taskName = 'Sandbox-Launch-'+[Guid]::NewGuid().ToString('N')
            Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
            Start-ScheduledTask -TaskName $taskName
            $deadline = [DateTime]::UtcNow.AddSeconds(40)
            do {
                if (Test-Path -LiteralPath (Join-Path $OutputDir 'launch.json')) { break }
                Start-Sleep -Milliseconds 250
            } while ([DateTime]::UtcNow -lt $deadline)
            if (-not (Test-Path -LiteralPath (Join-Path $OutputDir 'launch.json'))) {
                Save-Json (Join-Path $OutputDir 'launch.json') @{status='denied';detail='Nessuna sessione Quickemu interattiva disponibile o task non avviato';sample_path=$SamplePath;root_pid=$null;launch_time=[DateTime]::UtcNow.ToString('o')}
                Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            }
            # Task cleanup can occur only after launcher/Frida supervisor exits.
            Save-Json (Join-Path $OutputDir 'launch-task.json') @{name=$taskName}
            Read-Json (Join-Path $OutputDir 'launch.json') | ConvertTo-Json -Depth 16
        }
        'finish' {
            if (-not (Test-Path -LiteralPath $statePath)) { throw 'Stato preparazione assente' }
            $state = Read-Json $statePath
            Save-Json (Join-Path $OutputDir 'collector-stage.json') @{stage='stop_sensors';time=[DateTime]::UtcNow.ToString('o')}
            [DateTime]$start = [DateTime]::Parse($state.start_time,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
            [IO.File]::WriteAllText((Join-Path $OutputDir 'stop-trace'),'stop',$utf8)
            Start-Sleep -Seconds 2
            if ($Kernel -or $state.kernel.status -in @('started','available','recording')) {
                try { & (Join-Path $ToolDir 'kernel_trace.ps1') -Mode stop -OutputDir $OutputDir | Out-Null }
                catch { $state.warnings += 'Stop/export kernel parziale: '+$_.Exception.Message }
            }
            $end = [DateTime]::UtcNow
            $procmonState = @{status=$state.procmon.status;detail=$state.procmon.detail}
            if ($state.procmon.status -eq 'available') {
                try {
                    $procmon = Join-Path $ToolDir 'Procmon64.exe'
                    # /Terminate may return 1 when the bounded capture already exited.
                    Run-Tool $procmon @('/Terminate') 30 @(0,1)
                    $pml = Join-Path $OutputDir 'procmon.pml'
                    $csv = Join-Path $OutputDir 'procmon.csv'
                    if (-not (Test-Path -LiteralPath $pml)) { throw 'PML non creato' }
                    $size = (Get-Item -LiteralPath $pml).Length
                    $procmonState = @{status='completed';pml_bytes=$size;pml_cap=268435456;truncated=(Test-Path -LiteralPath (Join-Path $OutputDir 'procmon-cap.txt'))}
                    if ($size -gt 268435456) { $procmonState.truncated=$true;$procmonState.status='partial';$procmonState.detail='PML può oltrepassare leggermente il cap tra controlli; pull host deve imporre limite' }
                    # CSV export is bounded by time, and by an independent output watcher.
                    $exportArgs = @('/AcceptEula','/Quiet','/OpenLog',$pml,'/SaveAs',$csv)
                    $export = Start-Process -FilePath $procmon -ArgumentList (($exportArgs | ForEach-Object {Quote-Argument $_}) -join ' ') -WindowStyle Hidden -PassThru
                    $deadline = [DateTime]::UtcNow.AddSeconds(60)
                    $csvCapped = $false
                    do {
                        Start-Sleep -Milliseconds 200
                        if ((Test-Path -LiteralPath $csv) -and (Get-Item -LiteralPath $csv).Length -ge 67108864) { $csvCapped=$true;break }
                        $export.Refresh()
                    } while (-not $export.HasExited -and [DateTime]::UtcNow -lt $deadline)
                    if (-not $export.HasExited) { try {$export.Kill()}catch{};$procmonState.status='partial';$procmonState.detail='Export CSV parziale/timeout o limite 64 MiB' }
                    if ($csvCapped) { $procmonState.csv_truncated=$true }
                    if (Test-Path -LiteralPath $csv) { $procmonState.csv_bytes=(Get-Item -LiteralPath $csv).Length }
                    else { $procmonState.status='error';$procmonState.detail='CSV non prodotto' }
                } catch { $procmonState.status='error';$procmonState.detail=$_.Exception.Message }
            }
            Save-Json (Join-Path $OutputDir 'collector-stage.json') @{stage='events';time=[DateTime]::UtcNow.ToString('o')}
            $sysmon = Get-Events 'Microsoft-Windows-Sysmon/Operational' $start $end 'sysmon' 50000
            $defender = Get-Defender $start $end
            try { Save-Json (Join-Path $OutputDir 'defender-state.json') $defender 33554432 }
            catch { $state.warnings += 'Export standalone Defender non completo: '+$_.Exception.Message }
            $exports = @{
                sysmon=(Export-Evtx 'Microsoft-Windows-Sysmon/Operational' $start $end 'sysmon')
                defender=(Export-Evtx 'Microsoft-Windows-Windows Defender/Operational' $start $end 'defender')
                powershell=(Export-Evtx 'Microsoft-Windows-PowerShell/Operational' $start $end 'powershell')
                tasks=(Export-Evtx 'Microsoft-Windows-TaskScheduler/Operational' $start $end 'tasks')
                codeintegrity=(Export-Evtx 'Microsoft-Windows-CodeIntegrity/Operational' $start $end 'codeintegrity')
            }
            Save-Json (Join-Path $OutputDir 'collector-stage.json') @{stage='after_snapshot';time=[DateTime]::UtcNow.ToString('o')}
            $after = Get-Baseline $OutputDir
            Save-Json (Join-Path $OutputDir 'baseline-after.json') $after
            # Large per-record PowerShell comparisons can exceed the collection timeout.
            # Preserve both bounded snapshots; the host compares them after VM shutdown.
            $before = @{coverage=$state.baseline_coverage}
            $changes = @{registry=@();files=@();services=@();tasks=@();coverage=@{comparison='deferred_to_host'}}
            $launch = @{status='not_launched';root_pid=$null;sample_path=$state.sample_path}
            if (Test-Path -LiteralPath (Join-Path $OutputDir 'launch.json')) { $launch=Read-Json (Join-Path $OutputDir 'launch.json') }
            try {
                . (Join-Path $ToolDir 'payload_capture.ps1')
                Invoke-PayloadCapture -Events $sysmon.events -Launch $launch -OutputDir $OutputDir | Out-Null
            } catch {
                $state.warnings += 'Acquisizione payload secondari parziale: '+$_.Exception.Message
            }
            $sensors = [ordered]@{sysmon=@{status=$sysmon.status;detail=$sysmon.detail;events=$sysmon.events.Count;bytes=$sysmon.bytes;truncated=$sysmon.truncated};procmon=$procmonState;defender=@{status=$defender.status;detail='Assenza di hit non significa pulito'};frida=@{status='unavailable';detail='Sensore non richiesto/non disponibile'};baseline_before=$before.coverage;baseline_after=$after.coverage;evtx=$exports;provision=$state.sensors}
            if ($launch.trace) { $sensors.frida=$launch.trace }
            if (Test-Path -LiteralPath (Join-Path $OutputDir 'trace-status.json')) { $sensors.frida=Read-Json (Join-Path $OutputDir 'trace-status.json') }
            $sensors.kernel = $state.kernel
            if (Test-Path -LiteralPath (Join-Path $OutputDir 'kernel_stop.json')) { $sensors.kernel=Read-Json (Join-Path $OutputDir 'kernel_stop.json') }
            $warnings = @($state.warnings)
            if ($sysmon.truncated) { $warnings += 'Sysmon parziale: cap eventi/dati raggiunto' }
            if ($procmonState.status -ne 'completed') { $warnings += 'Procmon non completo/disponibile: consultare stato sensore' }
            $telemetry = @{schema_version=1;sample_path=$launch.sample_path;root_pid=$launch.root_pid;launch_time=$launch.launch_time;launch=$launch;start_time=$start.ToString('o');end_time=$end.ToString('o');procmon_clock=$state.procmon_clock;sysmon=$sysmon.events;defender=$defender;changes=$changes;baseline=@{before=$before.coverage;after=$after.coverage;artifacts=@('baseline-before.json','baseline-after.json');note='Snapshot globale non prova causalità; metadata file senza hash; differenze possibili durante raccolta after'};sensors=$sensors;event_cap=50000;truncated=$sysmon.truncated;warnings=$warnings;exports=$exports}
            $telemetry.privacy = $state.privacy
            Save-Json (Join-Path $OutputDir 'telemetry.json') $telemetry 134217728
            Save-Json (Join-Path $OutputDir 'collector-stage.json') @{stage='completed';time=[DateTime]::UtcNow.ToString('o')}
            Save-Json (Join-Path $OutputDir 'sensors.json') $sensors
            if (Test-Path -LiteralPath (Join-Path $OutputDir 'launch-task.json')) {
                $task = Read-Json (Join-Path $OutputDir 'launch-task.json')
                Stop-ScheduledTask -TaskName $task.name -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName $task.name -Confirm:$false -ErrorAction SilentlyContinue
            }
            @{status='completed';output_dir=$OutputDir;end_time=$end.ToString('o');sensors=$sensors;counts=@{sysmon=$sysmon.events.Count;defender=$defender.events.Count}} | ConvertTo-Json -Depth 16
        }
    }
} catch {
    $errorRecord = @{status='error';mode=$Mode;detail=$_.Exception.Message;time=[DateTime]::UtcNow.ToString('o')}
    Save-Json (Join-Path $OutputDir ('collector-error-'+$Mode+'.json')) $errorRecord
    $errorRecord | ConvertTo-Json
    exit 2
}
