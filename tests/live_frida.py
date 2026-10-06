"""Authored benign diagnostic only: isolate injection from hook and stack overhead."""
import argparse
import json
from pathlib import Path
import time
import uuid

from lab.bootstrap import DEFAULT_BASE, _ps_quote
from lab.vm import AnalysisVM

ROOT = Path(__file__).resolve().parents[1]
HELLO = "send({type:'coverage',pid:Process.id,detail:'hello control: no hooks'});"
MINIMAL = r"""
'use strict';
const own = Process.getCurrentThreadId();
const wanted=[['kernel32.dll','CreateFileW'],['kernel32.dll','CreateProcessW'],['advapi32.dll','RegSetValueExW'],['ntdll.dll','NtCreateFile'],['ntdll.dll','NtSetValueKey']];
let serial=0;
for(const [dll,api] of wanted){
  const mod=Process.findModuleByName(dll);if(!mod)continue;
  const address=mod.findExportByName(api);if(!address)continue;
  send({type:'status',sensor:'install',api:dll+'!'+api,stage:'before'});
  Interceptor.attach(address,{onEnter(args){
    if(Process.getCurrentThreadId()===own)return;
    this.id=String(++serial);
    let frames=[];try{frames=Thread.backtrace(this.context,Backtracer.FUZZY).slice(0,16).map(a=>({address:a.toString()}))}catch(_){}
    send({type:'call',pid:Process.id,tid:Process.getCurrentThreadId(),api:dll+'!'+api,phase:'enter',call_id:this.id,timestamp:new Date().toISOString(),stack:frames,stack_accuracy:'fuzzy'});
  },onLeave(value){if(this.id)send({type:'call',pid:Process.id,tid:Process.getCurrentThreadId(),api:dll+'!'+api,phase:'leave',call_id:this.id,return_value:value.toString(),timestamp:new Date().toISOString()})}});
}
send({type:'coverage',pid:Process.id,detail:'minimal file/registry/process C and Nt hooks; fuzzy stack; no allocator/read/write hooks'});
"""


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--modes',default='candidate')
    selected=parser.parse_args().modes.split(',')
    modes={'hello':(HELLO,0),'minimal':(MINIMAL,0),'minimal-warm':(MINIMAL,2),
           'candidate':((ROOT/'guest/hooks.js').read_text(),0)}
    if any(mode not in modes for mode in selected):
        parser.error('Unsupported diagnostic mode')
    run = ROOT / 'data' / ('diag-frida-' + uuid.uuid4().hex[:10])
    vm = AnalysisVM(run, DEFAULT_BASE, {'id':'diagnostic','interaction':False,'trace':True})
    proofs=[]
    try:
        vm.start()
        if not vm.wait_agent(240):
            raise RuntimeError('No guest agent')
        if not vm.wait_desktop(180):
            raise RuntimeError('No interactive Quickemu desktop; no fixture transferred')
        for name in ('prepare.ps1','collect.ps1','launch.ps1'):
            vm.push(ROOT/'guest'/name,'C:\\Sandbox\\tools\\'+name)
        fixture = run/'benign.ps1'
        for mode in selected:
            hooks,delay=modes[mode]
            marker='sandbox-probe-'+mode+'.txt'
            fixture.write_text((ROOT/'tests/benign_probe.ps1').read_text().replace('Start-Sleep -Seconds 2','Start-Sleep -Seconds 5').replace('sandbox-probe.txt',marker))
            host_hooks=run/(mode+'.js');host_hooks.write_text(hooks)
            tracer=(ROOT/'guest/frida_trace.py').read_text()
            if delay:
                old='            attach(root)\n'
                assert tracer.count(old)==1
                tracer=tracer.replace(old,'            time.sleep(2)\n'+old)
            host_tracer=run/(mode+'.py');host_tracer.write_text(tracer)
            vm.push(host_hooks,'C:\\Sandbox\\tools\\hooks.js')
            vm.push(host_tracer,'C:\\Sandbox\\tools\\frida_trace.py')
            guest='C:\\Sandbox\\diagnostic\\'+mode
            setup=r"""
$ErrorActionPreference='Stop';$d=GUEST;New-Item -ItemType Directory -Path $d -Force|Out-Null
$acl=Get-Acl $d;$rule=New-Object Security.AccessControl.FileSystemAccessRule(($env:COMPUTERNAME+'\Quickemu'),'Modify','ContainerInherit,ObjectInherit','None','Allow');$acl.SetAccessRule($rule);Set-Acl $d $acl
$s=@{sample_path=($d+'\sample.ps1');duration=20;trace=$true};[IO.File]::WriteAllText(($d+'\collector-state.json'),($s|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
""".replace('GUEST',_ps_quote(guest))
            rc,out,err=vm.exec(setup,120)
            if rc:raise RuntimeError(err or out)
            vm.push(fixture,guest+'\\sample.ps1')
            rc,out,err=vm.exec("& 'C:\\Sandbox\\tools\\collect.ps1' -Mode launch -OutputDir "+_ps_quote(guest)+" -SamplePath "+_ps_quote(guest+'\\sample.ps1')+" -Duration 20 -Trace",90)
            time.sleep(27)
            local=run/mode;local.mkdir()
            for filename in ('launch.json','api.jsonl','trace-status.json'):
                try:vm.pull(guest+'\\'+filename,local/filename,max_bytes=64*1024*1024)
                except Exception as exc:(local/(filename+'.error')).write_text(str(exc))
            marker_path='C:\\Users\\Quickemu\\Desktop\\'+marker
            rc,out,err=vm.exec("Write-Output ([bool](Test-Path -LiteralPath "+_ps_quote(marker_path)+"))",60)
            rows=[json.loads(line) for line in (local/'api.jsonl').read_text().splitlines()] if (local/'api.jsonl').exists() else []
            proof={'mode':mode,'file_created':rc==0 and 'true' in out.lower(),'calls':sum(x.get('type')=='call' for x in rows),'sensor_events':[x for x in rows if x.get('type')!='call'][-12:]}
            proofs.append(proof)
            print(json.dumps(proof,ensure_ascii=False),flush=True)
        (run/'proof.json').write_text(json.dumps(proofs,indent=2))
        return 0 if any(p['calls']>0 and p['file_created'] for p in proofs) else 1
    finally:
        vm.cleanup()


if __name__=='__main__':
    raise SystemExit(main())
