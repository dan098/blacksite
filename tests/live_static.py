import json
import time
from pathlib import Path
import httpx
from benign_pe import build

ROOT = Path(__file__).resolve().parents[1]

def main():
    token = (ROOT / 'data/api-token').read_text().strip()
    fixture = build(ROOT / 'data/tools/fixtures/benign-parser-probe.exe')
    with httpx.Client(base_url='http://127.0.0.1:8765', headers={'Authorization':'Bearer '+token}, timeout=60) as client:
        with fixture.open('rb') as source:
            response = client.post('/api/jobs', files={'file':(fixture.name,source)}, data={'static_only':'true','profiles':'[]','duration':15})
        response.raise_for_status()
        job_id = response.json()['id']
        print('Static benign PE job: '+job_id, flush=True)
        deadline = time.monotonic()+500
        while time.monotonic()<deadline:
            job = client.get('/api/jobs/'+job_id).json()
            if job['status'] in {'completed','partial','failed','cancelled'}:
                break
            time.sleep(3)
        else:
            raise TimeoutError('Static analysis deadline')
        static = job['static']
        results = {name: {'status':static.get(name,{}).get('status'), 'detail':static.get(name,{}).get('detail')} for name in ('floss','capa','yara','av','hybrid_analysis')}
        proof = {'id':job_id,'status':job['status'],'tools':results}
        (ROOT/'data/live-static-proof.json').write_text(json.dumps(proof,indent=2,ensure_ascii=False))
        print(json.dumps(proof,indent=2,ensure_ascii=False),flush=True)
        return 0 if all(results[name]['status']=='completed' for name in ('floss','capa','yara','av')) else 1

if __name__=='__main__':
    raise SystemExit(main())
