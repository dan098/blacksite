"""Run only the authored benign fixture through the real local API."""
import argparse
import json
import sys
import time
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profiles', default='standard,interactive,trace,driver')
    parser.add_argument('--duration', type=int, default=20)
    args = parser.parse_args()
    selected = args.profiles.split(',')
    token = (ROOT / 'data/api-token').read_text().strip()
    headers = {'Authorization': 'Bearer ' + token}
    with httpx.Client(base_url='http://127.0.0.1:8765', headers=headers, timeout=90) as client:
        ready = False
        for _ in range(20):
            try:
                ready = client.get('/api/health').status_code == 200
            except httpx.ConnectError:
                ready = False
            if ready:
                break
            time.sleep(0.5)
        if not ready:
            raise RuntimeError('API not ready within startup budget')
        with (ROOT / 'tests/benign_probe.ps1').open('rb') as stream:
            response = client.post('/api/jobs', files={'file': ('benign_probe.ps1', stream)}, data={'profiles': json.dumps(selected), 'duration': args.duration, 'static_only': 'false'})
        response.raise_for_status()
        job_id = response.json()['id']
        print(json.dumps({'job_id': job_id, 'profiles': selected}), flush=True)
        deadline = time.monotonic() + 3300
        while time.monotonic() < deadline:
            response = client.get('/api/jobs/' + job_id)
            response.raise_for_status()
            job = response.json()
            if job['status'] in {'completed', 'partial', 'failed', 'cancelled'}:
                break
            time.sleep(4)
        else:
            raise TimeoutError('Benign scenario exceeded total budget')
        # Full raw report, not the initial web view's bounded list.
        report = next((x for x in job['artifacts'] if x['name'] == 'report.json'), None)
        if not report:
            raise AssertionError('Terminal job has no downloadable full report.json')
        raw = client.get(f'/api/jobs/{job_id}/artifacts/{report["id"]}')
        raw.raise_for_status()
        job = raw.json()
        proofs = []
        for run in job.get('runs', []):
            dynamic = run.get('dynamic', {})
            events = dynamic.get('events', [])
            defender = dynamic.get('defender', {})
            protection = defender.get('status_snapshot', {})
            proof = {'profile': run['profile'], 'status': run['status'], 'counts': dynamic.get('counts'),
                     'isolation': dynamic.get('isolation', {}).get('confirmed') is True,
                     'registry': any('sandboxlabprobe' in str(event.get('target','')).lower() and event.get('related') for event in events),
                     'file': any('sandbox-probe.txt' in str(event.get('target','')).lower() and event.get('related') for event in events),
                     'child_process': any('cmd.exe' in str(process.get('image','')).lower() and process.get('related') for process in dynamic.get('processes', [])),
                     'api_calls': len(dynamic.get('api_calls', [])), 'nt_calls': len(dynamic.get('syscall_chain', [])),
                     'warnings': run.get('warnings', []) + dynamic.get('warnings', []),
                     'defender_current': defender.get('signature_status') == 'current' and all(protection.get(x) is True for x in ('AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled')),
                     'defender_signature': protection.get('AntivirusSignatureVersion')}
            pcap = next((x for x in run.get('artifacts', []) if x['name'] == 'network.pcap'), None)
            proof['pcap'] = False
            if pcap:
                capture = client.get(f'/api/jobs/{job_id}/artifacts/{pcap["id"]}')
                proof['pcap'] = capture.status_code == 200 and len(capture.content) > 24 and capture.content[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4')
            proofs.append(proof)
        pdf = client.get(f'/api/jobs/{job_id}/report.pdf')
        result = {'job_id': job_id, 'status': job['status'], 'proofs': proofs, 'pdf': pdf.status_code == 200 and pdf.content.startswith(b'%PDF-')}
        (ROOT / 'data/live-proof.json').write_text(json.dumps(result, ensure_ascii=False, indent=2))
        print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
        good = len(proofs) == len(selected) and result['pdf'] and all(x['isolation'] and x['registry'] and x['file'] and x['child_process'] and x['pcap'] and x['defender_current'] for x in proofs)
        if 'trace' in selected:
            trace = next((x for x in proofs if x['profile'] == 'trace'), {})
            good = good and trace.get('api_calls', 0) > 0 and trace.get('nt_calls', 0) > 0
        return 0 if good else 1

if __name__ == '__main__':
    raise SystemExit(main())
