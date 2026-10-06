[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('start','stop')][string]$Mode,
    [string]$OutputDir = 'C:\Sandbox',
    [ValidateRange(1,100000)][int]$MaxEvents = 50000,
    [ValidateRange(1,134217728)][long]$MaxBytes = 67108864
)
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
if ($OutputDir -ine 'C:\Sandbox' -and -not $OutputDir.StartsWith('C:\Sandbox\',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Kernel artifacts permitted only under C:\Sandbox'
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$profile = Join-Path $PSScriptRoot 'kernel.wprp'
$decoder = Join-Path $PSScriptRoot 'kernel_decode.cs'
$etl = Join-Path $OutputDir 'kernel.etl'
$events = Join-Path $OutputDir 'kernel_events.jsonl'
$sessionPath = Join-Path $OutputDir 'kernel_session.json'
$wpr = Join-Path $env:SystemRoot 'System32\wpr.exe'
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $wpr = Join-Path $env:SystemRoot 'Sysnative\wpr.exe'
}
$requested = [ordered]@{
    source='microsoft_kernel_etw'; scope='system_wide'; logging_mode='memory_ring';
    buffer_size_kib=1024; buffers=128; requested_buffer_bytes=134217728;
    keywords=@('SystemCall','ProcessThread','Loader','FileIO','FileIOInit','Filename','Registry','Drivers');
    strict_keywords=$true;
    stacks=@('SystemCallEnter','SystemCallExit','ProcessCreate','ProcessDelete','ThreadCreate','ThreadDelete','ImageLoad','FileCreate','FileRead','FileWrite','FileDelete','RegistryCreateKey','RegistryOpenKey','RegistrySetValue','RegistryDeleteValue','RegistryDeleteKey');
    syscall_events='not_yet_observed'; kernel_stacks='not_yet_observed'; full_coverage=$false;
    security_changes=@(); user_mode_hooks=$false; symbol_resolution='raw_addresses_only';
    max_decoded_events=$MaxEvents; max_decoded_bytes=$MaxBytes;
    limitations=@('Memory ring may overwrite earlier events; buffer loss counters do not quantify ring overwrite.',
                 'Stacks are individual observed ETW stackwalks, not inferred full causal stacks.',
                 'No security feature, driver signature policy, or Defender setting is changed.')
}
function Save-KernelJson([string]$Name,$Object) {
    $text = $Object | ConvertTo-Json -Depth 20 -Compress
    if ($utf8.GetByteCount($text) -gt 2097152) { throw 'Kernel receipt exceeded 2 MiB' }
    [IO.File]::WriteAllText((Join-Path $OutputDir $Name),$text,$utf8)
}
function New-Receipt([string]$Phase,[string]$Status,[string]$Detail) {
    return [ordered]@{schema='sandbox.kernel.receipt.v1';phase=$Phase;status=$Status;detail=$Detail;
        time_utc=[DateTime]::UtcNow.ToString('o');capabilities=$requested;commands=@();
        loss=@{events_lost=$null;buffers_lost=$null;counter_source='unknown'};
        artifacts=@{etl='kernel.etl';events='kernel_events.jsonl';commands='kernel_commands.jsonl'} }
}
function Quote-Argument([string]$Value) {
    return '"' + [regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1') + '"'
}
# Native stdout/stderr are drained concurrently, retained text is bounded. This is
# only a process launcher for Microsoft's built-in WPR, not an ETW provider.
$runnerSource = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
namespace SandboxKernel {
    public static class ToolRunner {
        public static Dictionary<string,object> Run(string file, string arguments, int seconds) {
            StringBuilder stdout=new StringBuilder(), stderr=new StringBuilder();
            object gate=new object(); bool truncated=false;
            Action<StringBuilder,string> append=delegate(StringBuilder target,string line) {
                if (line==null) return;
                lock(gate) {
                    int room=32768-target.Length;
                    if (room<=0) { truncated=true; return; }
                    string text=line+"\n";
                    if (text.Length>room) { text=text.Substring(0,room); truncated=true; }
                    target.Append(text);
                }
            };
            using(Process p=new Process()) {
                p.StartInfo=new ProcessStartInfo(file,arguments) { UseShellExecute=false,
                    CreateNoWindow=true, RedirectStandardOutput=true, RedirectStandardError=true };
                p.OutputDataReceived+=delegate(object sender,DataReceivedEventArgs e) { append(stdout,e.Data); };
                p.ErrorDataReceived+=delegate(object sender,DataReceivedEventArgs e) { append(stderr,e.Data); };
                p.Start(); p.BeginOutputReadLine(); p.BeginErrorReadLine();
                bool timeout=!p.WaitForExit(seconds*1000);
                if(timeout) { try {p.Kill();} catch {} }
                if (!p.WaitForExit(5000)) throw new InvalidOperationException("WPR could not be stopped after deadline");
                p.WaitForExit();
                lock(gate) {
                    return new Dictionary<string,object> { {"exit_code",p.ExitCode}, {"timed_out",timeout},
                        {"stdout",stdout.ToString()}, {"stderr",stderr.ToString()},
                        {"output_truncated",truncated}, {"max_output_characters_per_stream",32768} };
                }
            }
        }
    }
}
'@
function Run-Wpr([string]$Phase,[string[]]$Arguments,[int]$Timeout=30) {
    $argumentsText = ($Arguments | ForEach-Object { Quote-Argument $_ }) -join ' '
    $record = [ordered]@{schema='sandbox.kernel.command.v1';phase=$Phase;
        time_utc=[DateTime]::UtcNow.ToString('o');executable=$wpr;arguments=$Arguments;
        command_line=((Quote-Argument $wpr)+' '+$argumentsText);timeout_seconds=$Timeout;
        exit_code=$null;timed_out=$false;status='error';stdout='';stderr=''}
    try {
        $native = [SandboxKernel.ToolRunner]::Run($wpr,$argumentsText,$Timeout)
        foreach ($key in $native.Keys) { $record[$key]=$native[$key] }
        $record.status = $(if ($record.exit_code -eq 0 -and -not $record.timed_out) {'completed'} else {'error'})
    } catch { $record.error=$_.Exception.Message }
    $record.finished_utc=[DateTime]::UtcNow.ToString('o')
    $line=$record | ConvertTo-Json -Depth 12 -Compress
    # At most the fixed lifecycle's few commands, each with <=64 KiB native text.
    $commandPath=Join-Path $OutputDir 'kernel_commands.jsonl'
    if ((Test-Path -LiteralPath $commandPath) -and (Get-Item -LiteralPath $commandPath).Length -gt 1048576) {
        throw 'Kernel command receipt log exceeded 1 MiB'
    }
    [IO.File]::AppendAllText($commandPath,$line+"`n",$utf8)
    return $record
}
function Status-Receipt([string]$Phase) {
    $command=Run-Wpr $Phase @('-status','collectors','-details') 15
    $result=New-Receipt $Phase $(if ($command.status -eq 'completed') {'recording_status'} else {'unknown'}) 'Native WPR status retained; recording is not evidence that syscalls were decoded.'
    $result.commands=@($command)
    # WPR localizes status text. Parse only recognized English labels; unknown is
    # null, never zero. ETL TRACE_LOGFILE_HEADER counters are the preferred source.
    $text=$command.stdout+"`n"+$command.stderr
    $eventMatches=[regex]::Matches($text,'(?im)^\s*Events\s+Lost\s*[:=]\s*([0-9,]+)')
    $bufferMatches=[regex]::Matches($text,'(?im)^\s*Buffers\s+Lost\s*[:=]\s*([0-9,]+)')
    if ($eventMatches.Count) {
        $sum=[long]0; foreach($m in $eventMatches) {$sum += [long]($m.Groups[1].Value.Replace(',',''))}
        $result.loss.events_lost=$sum; $result.loss.counter_source='wpr_status_english_labels'
    }
    if ($bufferMatches.Count) {
        $sum=[long]0; foreach($m in $bufferMatches) {$sum += [long]($m.Groups[1].Value.Replace(',',''))}
        $result.loss.buffers_lost=$sum; $result.loss.counter_source='wpr_status_english_labels'
    }
    Save-KernelJson 'kernel_status.json' $result
    return $result
}
$receipt=New-Receipt $Mode 'unavailable' 'Kernel capture has not produced observed events.'
try {
    if (-not (Test-Path -LiteralPath $wpr -PathType Leaf)) { throw 'Built-in Microsoft WPR is unavailable' }
    if (-not ('SandboxKernel.ToolRunner' -as [type])) { Add-Type -TypeDefinition $runnerSource -Language CSharp }
    if ($Mode -eq 'start') {
        if (Test-Path -LiteralPath $sessionPath) { throw 'Capture already initialized in this output directory; use a fresh run directory' }
        if (-not (Test-Path -LiteralPath $profile -PathType Leaf)) { throw 'Trusted kernel.wprp asset is missing' }
        $receipt.profile_sha256=(Get-FileHash -LiteralPath $profile -Algorithm SHA256).Hash.ToLowerInvariant()
        # No -filemode, no -cancel, and no fallback that silently drops SystemCall.
        $start=Run-Wpr 'start' @('-start',($profile+'!SandboxKernel')) 30
        $receipt.commands=@($start)
        if ($start.status -ne 'completed') { throw 'Strict SystemCall kernel WPR start failed; no downgraded profile was attempted' }
        $receipt.status='recording'
        $receipt.detail='Microsoft kernel collector started in bounded memory mode; capabilities still await actual events.'
        Save-KernelJson 'kernel_session.json' @{schema='sandbox.kernel.session.v1';status='recording';
            output_dir=$OutputDir;start_utc=[DateTime]::UtcNow.ToString('o');profile=$profile;
            profile_sha256=$receipt.profile_sha256;start_command=$start;capabilities=$requested}
        $receipt.start_status=Status-Receipt 'after_start'
    } else {
        if (-not (Test-Path -LiteralPath $sessionPath -PathType Leaf)) { throw 'No successful capture ownership receipt; refusing to stop another WPR session' }
        if ((Get-Item -LiteralPath $sessionPath).Length -gt 2097152) { throw 'Capture ownership receipt exceeded 2 MiB' }
        $session=Get-Content -LiteralPath $sessionPath -Raw | ConvertFrom-Json
        if ($session.status -ne 'recording' -or $session.output_dir -ine $OutputDir) {
            throw 'Capture ownership receipt is not recording for this directory'
        }
        $status=Status-Receipt 'before_stop'
        $receipt.loss=$status.loss
        $receipt.pre_stop_status=$status
        # Stop FIRST, before TDH compilation/decoding or integration's CSV/baseline export.
        $stop=Run-Wpr 'stop' @('-stop',$etl,'-skipPdbGen') 120
        $receipt.commands=@($stop)
        $receipt.etl_retained=Test-Path -LiteralPath $etl -PathType Leaf
        if ($receipt.etl_retained) { $receipt.etl_bytes=(Get-Item -LiteralPath $etl).Length }
        if ($stop.status -ne 'completed') {
            $receipt.status=$(if ($receipt.etl_retained) {'partial'} else {'unavailable'})
            throw 'WPR stop failed; any existing ETL was retained unchanged'
        }
        Save-KernelJson 'kernel_session.json' @{schema='sandbox.kernel.session.v1';status='stopped';output_dir=$OutputDir;
            start_utc=$session.start_utc;stop_utc=[DateTime]::UtcNow.ToString('o');stop_command=$stop}
        $receipt.status='captured'
        $receipt.detail='ETL retained; availability is determined only from observed decoded kernel events.'
        # Save successful stop even if subsequent decoding throws or the process is interrupted.
        Save-KernelJson 'kernel_stop.json' $receipt
        # PID selection only prioritizes the bounded decoded index. The host
        # still owns GUID/time attribution; all original ETL bytes are retained.
        $selection=New-Object 'System.Collections.Generic.HashSet[uint32]'
        try {
            $launchPath=Join-Path $OutputDir 'launch.json'
            if ((Test-Path -LiteralPath $launchPath) -and (Get-Item -LiteralPath $launchPath).Length -le 2097152) {
                $launch=Get-Content -LiteralPath $launchPath -Raw | ConvertFrom-Json
                if ($launch.root_pid -gt 0) {
                    [void]$selection.Add([uint32]$launch.root_pid)
                    $lower=[DateTime]::Parse($session.start_utc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
                    $xpath="*[System[(EventID=1) and TimeCreated[@SystemTime >= '$lower']]]"
                    $created=@(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath $xpath -Oldest -MaxEvents 5000 -ErrorAction Stop)
                    $known=New-Object 'System.Collections.Generic.HashSet[string]'
                    $rows=@($created | ForEach-Object {
                        $xml=[xml]$_.ToXml();$data=@{}
                        foreach($field in $xml.Event.EventData.Data){$data[$field.Name]=[string]$field.'#text'}
                        @{pid=[uint32]$data.ProcessId;guid=$data.ProcessGuid;parent=$data.ParentProcessGuid}
                    })
                    foreach($row in $rows) {
                        if($row.pid -eq [uint32]$launch.root_pid -or $known.Contains([string]$row.parent)) {
                            if($known.Count -ge 256){break}
                            [void]$known.Add([string]$row.guid);[void]$selection.Add($row.pid)
                        }
                    }
                }
            }
        } catch { $receipt.pid_selection_error=$_.Exception.Message }
        [uint32[]]$selectionPids=@($selection)
        $decode=[ordered]@{schema='sandbox.kernel.decode.v1';status='unavailable';artifact='kernel_events.jsonl';
            etl='kernel.etl';etl_retained=$receipt.etl_retained;max_events=$MaxEvents;max_bytes=$MaxBytes;
            full_coverage=$false;loss=@{events_lost=$null;buffers_lost=$null;counter_source='unknown'};
            capabilities=$requested;
            compile_command=@{cmdlet='Add-Type';path=$decoder;referenced_assemblies=@('System.dll','System.Core.dll','System.Web.Extensions.dll')};
            decode_call=@{type='SandboxKernel.Decoder';method='Export';arguments=@($etl,$events,$MaxEvents,$MaxBytes,$selectionPids)}}
        try {
            if (-not [Environment]::Is64BitProcess) { throw 'Kernel TDH decoder requires 64-bit PowerShell' }
            if (-not (Test-Path -LiteralPath $decoder -PathType Leaf)) { throw 'Trusted kernel_decode.cs asset is missing; ETL is still retained' }
            $receipt.decoder_sha256=(Get-FileHash -LiteralPath $decoder -Algorithm SHA256).Hash.ToLowerInvariant()
            if (-not ('SandboxKernel.Decoder' -as [type])) {
                Add-Type -Path $decoder -ReferencedAssemblies @('System.dll','System.Core.dll','System.Web.Extensions.dll')
            }
            $compileCommand=$decode.compile_command
            $decodeCall=$decode.decode_call
            $decode=[SandboxKernel.Decoder]::Export($etl,$events,$MaxEvents,$MaxBytes,$selectionPids) | ConvertFrom-Json
            $decode | Add-Member -NotePropertyName capabilities -NotePropertyValue $requested -Force
            $decode | Add-Member -NotePropertyName compile_command -NotePropertyValue $compileCommand -Force
            $decode | Add-Member -NotePropertyName decode_call -NotePropertyValue $decodeCall -Force
        } catch { $decode.error=$_.Exception.Message }
        Save-KernelJson 'kernel_decode.json' $decode
        $receipt.decode_status=$decode.status
        if ($decode.status -ne 'completed') { $receipt.status='partial' }
    }
} catch {
    $receipt.error=$_.Exception.Message
    if ($receipt.status -eq 'recording') {
        $receipt.detail='Collector started; status query/receipt incomplete. Ownership retained for stop.'
    } elseif ($receipt.status -notin @('partial','captured')) { $receipt.status='unavailable' }
    $errorReceipt=New-Receipt ('error_'+$Mode) $receipt.status $_.Exception.Message
    $errorReceipt.commands=$receipt.commands
    Save-KernelJson ('kernel_error_'+$Mode+'.json') $errorReceipt
} finally {
    Save-KernelJson ('kernel_'+$Mode+'.json') $receipt
}
# Emit a receipt, not a false successful/available sensor claim.
$receipt | ConvertTo-Json -Depth 20 -Compress
