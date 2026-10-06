"""Exercise real Microsoft kernel ETW in a disposable clone; no malware or host networking."""
import json
from datetime import datetime, timezone
from pathlib import Path
import uuid

from lab.vm import AnalysisVM
from lab.kernel import read_kernel, normalize_kernel

ROOT = Path(__file__).resolve().parents[1]


def main():
    run_id = 'kernel-' + uuid.uuid4().hex[:10]
    run_dir = ROOT / 'data' / run_id
    run_dir.mkdir(mode=0o700)
    collected = run_dir / 'collected'
    collected.mkdir(mode=0o700)
    vm = AnalysisVM(run_dir, ROOT / 'data/bases', {'id': 'trace', 'network': 'offline'})
    guest_dir = 'C:\\Sandbox\\runs\\' + run_id
    root_process = None
    try:
        vm.start()
        if not vm.wait_agent(360) or not vm.wait_desktop(180):
            raise RuntimeError('Guest/desktop not ready')
        for name in ('kernel_trace.ps1', 'kernel.wprp', 'kernel_decode.cs'):
            vm.push(ROOT / 'guest' / name, 'C:\\Sandbox\\tools\\' + name)
        rc, out, err = vm.exec("New-Item -ItemType Directory -Force '" + guest_dir + "' | Out-Null", timeout=60)
        if rc:
            raise RuntimeError('Diagnostic directory creation failed')
        rc, out, err = vm.exec("& 'C:\\Sandbox\\tools\\kernel_trace.ps1' -Mode start -OutputDir '" + guest_dir + "'", timeout=180)
        vm.pull(guest_dir + '\\kernel_start.json', collected / 'kernel_start.json', max_bytes=2 * 1024 * 1024)
        if rc:
            raise RuntimeError('Kernel start failed: ' + err[-500:])
        workload = r"""
$ErrorActionPreference='Stop'
$probe=@'
$ErrorActionPreference='Stop'
New-Item -Path 'HKCU:\Software\SandboxKernelProof' -Force | Out-Null
New-ItemProperty -Path 'HKCU:\Software\SandboxKernelProof' -Name Marker -Value 'authored benign kernel proof' -Force | Out-Null
[IO.File]::WriteAllText('C:\Sandbox\kernel-proof.txt','authored benign kernel proof')
Start-Process 'cmd.exe' -ArgumentList '/d /c echo kernel-child>C:\Sandbox\kernel-child.txt' -Wait -WindowStyle Hidden
$until=[DateTime]::UtcNow.AddSeconds(45)
while([DateTime]::UtcNow -lt $until) {
    [IO.File]::WriteAllText('C:\Sandbox\kernel-proof.txt','authored benign kernel proof')
    Start-Sleep -Milliseconds 50
}
'@
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))
$child=Start-Process 'powershell.exe' -ArgumentList ('-NoProfile -EncodedCommand '+$encoded) -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 2
$query="*[System[(EventID=1)] and EventData[Data[@Name='ProcessId']='$($child.Id)']]"
$created=Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath $query -MaxEvents 1
$xml=[xml]$created.ToXml()
$identity=@{}
foreach($field in $xml.Event.EventData.Data){$identity[$field.Name]=[string]$field.'#text'}
if(-not $identity.ProcessGuid){throw 'Actual Sysmon process identity missing'}
@{pid=$child.Id;process_guid=$identity.ProcessGuid;start_time=$created.TimeCreated.ToUniversalTime().ToString('o');end_time=$null;file_marker=(Test-Path 'C:\Sandbox\kernel-proof.txt');child_marker=(Test-Path 'C:\Sandbox\kernel-child.txt')} | ConvertTo-Json -Compress
"""
        rc, out, err = vm.exec(workload, timeout=120)
        if rc:
            raise RuntimeError('Benign workload failed: ' + err[-500:])
        root_process = json.loads(out.strip())
        assert root_process['file_marker'] and root_process['child_marker']
        rc, out, err = vm.exec("& 'C:\\Sandbox\\tools\\kernel_trace.ps1' -Mode stop -OutputDir '" + guest_dir + "'", timeout=240)
        for name in ('kernel.etl', 'kernel_events.jsonl', 'kernel_status.json', 'kernel_stop.json', 'kernel_decode.json', 'kernel_commands.jsonl'):
            try:
                vm.pull(guest_dir + '\\' + name, collected / name,
                        max_bytes=256 * 1024 * 1024 if name.endswith('.etl') else 128 * 1024 * 1024 if name.endswith('_events.jsonl') else 2 * 1024 * 1024)
            except Exception as exc:
                (collected / (name + '.error')).write_text(str(exc)[:1000])
    finally:
        vm.cleanup()
    normalized = normalize_kernel(read_kernel(collected), processes=[{
        'guid': root_process['process_guid'], 'pid': root_process['pid'], 'start_time': root_process['start_time'],
        'end_time': root_process['end_time'], 'related': True, 'image': 'powershell.exe'}] if root_process else [])
    proof = {'verified_at': datetime.now(timezone.utc).isoformat(), 'run_dir': str(run_dir),
             'isolation': vm.isolation, 'counts': normalized.get('counts'), 'status': normalized.get('status'),
             'capabilities': normalized.get('capabilities'), 'coverage': normalized.get('coverage'),
             'warnings': normalized.get('warnings'), 'benign_markers': root_process}
    (ROOT / 'data/kernel-live-proof.json').write_text(json.dumps(proof, ensure_ascii=False, indent=2))
    print(json.dumps({key: proof[key] for key in ('verified_at', 'run_dir', 'counts', 'status', 'capabilities', 'benign_markers')}, ensure_ascii=False, indent=2))
    counts = normalized.get('counts', {})
    if not all(counts.get(key, 0) > 0 for key in ('syscall_enter', 'syscall_exit', 'stackwalk')):
        raise AssertionError('Genuine kernel syscall entry/exit/stackwalk not all observed')
    if counts.get('related_events', 0) <= 0:
        raise AssertionError('No kernel event attributed to actual benign workload identity')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
