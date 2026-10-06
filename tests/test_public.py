import httpx
from fastapi.testclient import TestClient
from lab.public import create_public_app
from lab.sharing import public_origin
from lab.config import Settings
from lab.worker import redacted_share


def test_public_gateway_never_proxies_admin_samples_or_mutations():
    calls=[]
    def handler(request):
        calls.append(request)
        assert request.method=='GET'
        assert request.url.path.startswith('/api/shared/')
        assert 'authorization' not in request.headers
        assert 'cookie' not in request.headers
        return httpx.Response(200,json={'name':'Sample abc','sha256':'a'*64,'runs':[]})
    with TestClient(create_public_app(httpx.MockTransport(handler))) as client:
        token='a'*43
        assert client.get('/s/'+token).status_code==200
        assert client.get('/api/shared/'+token,headers={'Authorization':'Bearer private-token','Cookie':'private-cookie=secret'}).status_code==200
        for path in ('/','/api/jobs','/api/capabilities','/api/session','/api/openapi.json','/docs','/static/../lab/api.py','/static/index.html'):
            assert client.get(path).status_code==404
        assert client.post('/api/shared/'+token,data=b'large-untrusted-body').status_code==405
        assert client.post('/api/jobs',data=b'sample').status_code==404
        assert client.get('/static/app.js').headers['x-content-type-options']=='nosniff'
        assert client.get('/api/shared/too-short').status_code==404
    assert len(calls)==1


def test_invalid_or_redirecting_upstream_not_forwarded():
    with TestClient(create_public_app(httpx.MockTransport(lambda request: httpx.Response(302,headers={'Location':'http://untrusted.invalid'})))) as client:
        assert client.get('/api/shared/'+'a'*43).status_code==503


def test_temporary_origin_is_validated_and_no_symlink(tmp_path):
    settings=Settings(data=tmp_path)
    path=tmp_path/'public-origin'
    path.write_text('https://sandbox-test.trycloudflare.com\n')
    assert public_origin(settings)=='https://sandbox-test.trycloudflare.com'
    for value in ('http://sandbox-test.trycloudflare.com','https://attacker.test','https://safe.trycloudflare.com/evil'):
        path.write_text(value)
        assert public_origin(settings)==''
    path.unlink()
    path.symlink_to(tmp_path/'elsewhere')
    assert public_origin(settings)==''


def test_public_summary_omits_untrusted_sensor_keys_and_values():
    job={'id':'a'*32,'name':'PRIVATE.exe','sha256':'a'*64,'status':'completed','created_at':'now',
         'static':{},'runs':[{'profile':'standard','status':'completed','dynamic':{
             'counts':{'events':12,'private_path':'C:\\PRIVATE'},
             'capabilities':{'PRIVATE':{'status':'available'},'sysmon':{'status':'PRIVATE'}},
             'defender':{'status':'PRIVATE'}}}]}
    result=redacted_share(job)
    assert 'PRIVATE' not in str(result)
    assert result['runs'][0]['dynamic']['counts']=={'events':12}
    assert result['runs'][0]['dynamic']['capabilities']=={'sysmon':{'status':'unknown'}}
