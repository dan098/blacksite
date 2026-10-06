"""Real API scenario: download and execute only the authored SHA256-pinned benign stage2 in a guest."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
from urllib.parse import urlparse

import httpx

ROOT = Path(__file__).resolve().parents[1]
TERMINAL = {'completed', 'partial', 'failed', 'cancelled'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage2-url', required=True)
    parser.add_argument('--duration', type=int, default=35)
    args = parser.parse_args()
    url = urlparse(args.stage2_url)
    if url.scheme != 'https' or not url.hostname or url.username or url.password:
        raise ValueError('Use a public HTTPS URL without credentials')
    expected_bytes = (ROOT / 'tests/stage2_fixture/sandbox-stage2.ps1').read_bytes()
    expected_sha = hashlib.sha256(expected_bytes).hexdigest()
    quoted_url = args.stage2_url.replace("'", "''")
    stager = f"""$ErrorActionPreference='Stop'
Start-Sleep -Seconds 2
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$directory=Join-Path $env:TEMP 'SandboxStage2Probe'
New-Item -ItemType Directory -Force -Path $directory | Out-Null
$stage=Join-Path $directory 'sandbox-stage2.ps1'
Invoke-WebRequest -UseBasicParsing -Uri '{quoted_url}' -OutFile $stage
if((Get-FileHash -LiteralPath $stage -Algorithm SHA256).Hash.ToLowerInvariant() -ne '{expected_sha}'){{throw 'Benign fixture hash mismatch; no execution'}}
$child=Start-Process 'powershell.exe' -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "'+$stage+'"') -WindowStyle Hidden -PassThru -Wait
if($child.ExitCode -ne 0){{throw 'Benign stage2 did not complete'}}
Start-Sleep -Seconds 2
""".encode()
    with httpx.Client(base_url='http://127.0.0.1:8765',
                      headers={'Authorization':'Bearer '+(ROOT/'data/api-token').read_text().strip()},
                      timeout=120, trust_env=False) as client:
        for _ in range(20):
            try:
                if client.get('/api/health').status_code == 200:
                    break
            except httpx.ConnectError:
                pass
            time.sleep(.5)
        response = client.post('/api/jobs', files={'file':('benign-internet-stager.ps1', stager)},
                               data={'profiles':json.dumps(['trace']), 'duration':args.duration, 'static_only':'false'})
        response.raise_for_status()
        job_id = response.json()['id']
        print(json.dumps({'job_id':job_id,'stage2_sha256':expected_sha}), flush=True)
        deadline = time.monotonic()+3300
        while time.monotonic()<deadline:
            response=client.get('/api/jobs/'+job_id)
            response.raise_for_status()
            preview=response.json()
            if preview['status'] in TERMINAL:
                break
            time.sleep(4)
        else:
            raise TimeoutError('Internet stage2 scenario exceeded bounded deadline')
        report=next(item for item in preview['artifacts'] if item['name']=='report.json')
        full=client.get(report['url'])
        full.raise_for_status()
        job=full.json()
        run=next(item for item in job['runs'] if item['profile']=='trace')
        dynamic=run.get('dynamic',{})
        events=dynamic.get('events',[])
        kernel=dynamic.get('kernel',{})
        payloads=dynamic.get('payloads',{})
        matching=[item for item in payloads.get('payloads',[]) if item.get('sha256')==expected_sha and item.get('status')=='verified']
        candidates=[item for item in run.get('artifacts',[]) if item.get('kind')=='payload' and expected_sha in item['name']]
        preserved=bool(matching and candidates)
        if preserved:
            content=client.get(candidates[0]['url'])
            preserved=content.status_code==200 and content.content==expected_bytes
        pcap=next((item for item in run.get('artifacts',[]) if item['name']=='network.pcap'),None)
        network_capture=client.get(pcap['url']) if pcap else None
        pdf=client.get('/api/jobs/'+job_id+'/report.pdf')
        defender=dynamic.get('defender',{})
        protection=defender.get('status_snapshot',{})
        proof={'verified_at':datetime.now(timezone.utc).isoformat(),'job_id':job_id,'status':run['status'],
               'isolation':dynamic.get('isolation',{}),'kernel_counts':kernel.get('counts',{}),
               'kernel_coverage':kernel.get('coverage',{}),'kernel_capabilities':kernel.get('capabilities',{}),
               'api_calls':len(dynamic.get('api_calls',[])),
               'downloaded_stage2_sha256':expected_sha,'downloaded_stage2_bytes_preserved':preserved,
               'stage2_registry':any('sandboxlabstage2' in str(item.get('target','')).lower() and item.get('related') for item in events),
               'stage2_marker':any('sandbox-stage2-marker.txt' in str(item.get('target','')).lower() and item.get('related') for item in events),
               'stage2_child':any('cmd.exe' in str(item.get('image','')).lower() and item.get('related') for item in dynamic.get('processes',[])),
               'pcap_downloadable':bool(network_capture is not None and network_capture.status_code==200 and len(network_capture.content)>24),
               'pdf':pdf.status_code==200 and pdf.content.startswith(b'%PDF-'),
               'defender_current_active':defender.get('signature_status')=='current' and all(protection.get(key) is True for key in ('AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled')),
               'vt_status':job.get('static',{}).get('reputation',{}).get('status'),
               'warnings':run.get('warnings',[])+dynamic.get('warnings',[])}
        (ROOT/'data/internet-live-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2))
        print(json.dumps({**{key:value for key,value in proof.items() if key not in ('isolation','kernel_coverage','warnings')}, 'isolation':{key:proof['isolation'].get(key) for key in ('confirmed','network_mode','guest_internet','guest_lan','guest_host')}, 'kernel_loss':proof['kernel_coverage'].get('loss'), 'kernel_truncated':proof['kernel_coverage'].get('truncated'), 'warnings':proof['warnings'][:10]},ensure_ascii=False,indent=2),flush=True)
        assert proof['isolation'].get('confirmed') is True and proof['isolation'].get('guest_internet') is True
        assert proof['isolation'].get('guest_lan') is False and proof['isolation'].get('guest_host') is False
        assert all(proof[key] is True for key in ('downloaded_stage2_bytes_preserved','stage2_registry','stage2_marker','stage2_child','pcap_downloadable','pdf','defender_current_active'))
        assert proof['api_calls']>0
        assert all(proof['kernel_counts'].get(key,0)>0 for key in ('syscall_enter','syscall_exit','stackwalk','related_events'))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
