"""Executed only by the logged-in guest launcher; offline uv venv owns Frida."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import subprocess
import threading
import time


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding='utf-8-sig'))
    output = Path(config['output_dir'])
    output.mkdir(parents=True, exist_ok=True)
    launch_path = output / 'launch.json'
    launch = {'sample_path': config['sample_path'], 'launch_time': utc(), 'root_pid': None,
              'status': 'error', 'method': 'interactive_frida_spawn', 'user': os.environ.get('USERNAME'),
              'trace': {'status': 'error', 'detail': 'Inizializzazione non conclusa'}}
    # Defense in depth: this payload is not a host execution tool.
    if sys.platform != 'win32' or os.environ.get('USERNAME', '').casefold() != 'quickemu':
        launch['detail'] = 'Avvio negato: richiesta sessione Windows interattiva Quickemu'
        atomic_json(launch_path, launch)
        return 2
    try:
        import ctypes
        if ctypes.windll.kernel32.ProcessIdToSessionId is None:
            raise RuntimeError('Windows session API unavailable')
        session_id = ctypes.c_uint32()
        if not ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session_id)) or session_id.value == 0:
            raise RuntimeError('Sessione di servizio non autorizzata')
        import frida
        hooks = Path(config['hooks_path']).read_text(encoding='utf-8')
        device = frida.get_local_device()
    except Exception as exc:
        launch['detail'] = str(exc)[:2048]
        launch['trace'] = {'status': 'unavailable', 'detail': str(exc)[:2048]}
        atomic_json(launch_path, launch)
        return 3

    lock = threading.RLock()
    sessions = {}
    scripts = {}
    known = set()
    count = 0
    byte_count = 0
    truncated = False
    api_path = output / 'api.jsonl'
    stream = api_path.open('w', encoding='utf-8', newline='\n')

    def record(event: dict) -> None:
        nonlocal count, byte_count, truncated
        with lock:
            event.setdefault('timestamp', utc())
            event.setdefault('time', event['timestamp'])
            encoded = json.dumps(event, ensure_ascii=False, default=str)
            if len(encoded.encode('utf-8')) > 32768:
                event = {'type': 'error', 'pid': event.get('pid'), 'timestamp': utc(),
                         'detail': 'Record sensore oltre 32 KiB: dati omessi', 'original_type': event.get('type')}
                encoded = json.dumps(event)
                truncated = True
            if count >= 50000 or byte_count + len(encoded.encode('utf-8')) > 64 * 1024 * 1024:
                truncated = True
                return
            stream.write(encoded + '\n')
            stream.flush()
            count += 1
            byte_count += len(encoded.encode('utf-8')) + 1

    def attach(pid: int, parent_pid: int | None = None) -> None:
        with lock:
            known.add(pid)
        stage = 'attach_session'
        try:
            session = device.attach(pid)
            sessions[pid] = session
            stage = 'load_hooks'
            script = session.create_script(hooks)
            scripts[pid] = script

            def on_message(message, data):
                if message.get('type') == 'send' and isinstance(message.get('payload'), dict):
                    payload = dict(message['payload'])
                    payload.setdefault('pid', pid)
                    record(payload)
                else:
                    record({'type': 'error', 'pid': pid, 'detail': str(message)[:2048]})
            script.on('message', on_message)
            script.load()
            stage = 'child_gating'
            try:
                session.enable_child_gating()
                gating = 'available'
            except Exception as exc:
                gating = 'unavailable'
                record({'type': 'status', 'pid': pid, 'sensor': 'descendant_gating',
                        'status': 'unavailable', 'detail': str(exc)[:1024]})
            record({'type': 'process', 'pid': pid, 'parent_pid': parent_pid,
                    'status': 'attached', 'descendant_gating': gating})
        except Exception as exc:
            record({'type': 'error', 'pid': pid, 'sensor': 'attach', 'stage': stage, 'detail': str(exc)[:2048]})
            raise

    def instrument_child(child):
        try:
            attach(child.pid, child.parent_pid)
        except Exception:
            pass
        finally:
            try:
                device.resume(child.pid)
            except Exception as exc:
                record({'type': 'error', 'pid': child.pid, 'detail': 'Resume figlio: ' + str(exc)[:1024]})

    def on_child(child):
        # Never block Frida's event dispatch thread with synchronous attach/load RPC.
        # Only known descendants are instrumented; every gated child is released.
        if child.parent_pid not in known:
            record({'type': 'error', 'pid': child.pid, 'detail': 'Figlio senza parent attribuibile; nessun attach'})
            try:
                device.resume(child.pid)
            except Exception:
                pass
            return
        threading.Thread(target=instrument_child, args=(child,), daemon=True).start()

    device.on('child-added', on_child)
    root = None
    try:
        launch['launch_time'] = utc()
        # Running attach avoids a CLR/loader-lock deadlock in suspended Windows spawn.
        # The pre-attach startup interval is explicitly outside this sensor's coverage.
        target = subprocess.Popen(config['argv'], cwd=config.get('cwd'), stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        root = target.pid
        launch['root_pid'] = root
        launch['method'] = 'interactive_frida_attach_running'
        launch['status'] = 'started'
        launch['trace'] = {'status': 'pending', 'detail': 'Processo avviato una sola volta; attach in corso'}
        atomic_json(launch_path, launch)
        try:
            attach(root)
            launch['trace'] = {'status': 'available', 'detail': 'Hook user-mode su processo in esecuzione; startup precedente all’attach non catturato'}
        except Exception as exc:
            launch['trace'] = {'status': 'partial', 'detail': 'Attach fallito; processo non rieseguito: ' + str(exc)[:1024]}
        launch['status'] = 'started'
        atomic_json(launch_path, launch)
        deadline = time.monotonic() + min(600, max(15, int(config.get('duration', 60))))
        while time.monotonic() < deadline and not (output / 'stop-trace').exists():
            time.sleep(.25)
        launch['trace'].update({'events': count, 'bytes': byte_count, 'truncated': truncated,
                                'detail': 'User-mode soltanto; API non agganciate/direct syscall/kernel non coperti'})
        if truncated:
            launch['trace']['status'] = 'partial'
        atomic_json(launch_path, launch)
        return 0
    except Exception as exc:
        launch['status'] = 'error'
        launch['detail'] = str(exc)[:2048]
        # root_pid stays non-null after spawn: callers MUST NOT launch a second copy.
        atomic_json(launch_path, launch)
        record({'type': 'error', 'pid': root, 'detail': str(exc)[:2048]})
        return 4
    finally:
        device.off('child-added', on_child)
        for session in list(sessions.values()):
            try:
                session.disable_child_gating()
                session.detach()
            except Exception:
                pass
        stream.close()
        atomic_json(output / 'trace-status.json', {'status': launch['trace']['status'], 'events': count,
                    'bytes': byte_count, 'truncated': truncated, 'processes': sorted(known),
                    'coverage': 'running-process user-mode C API/Nt entry hooks; pre-attach startup and kernel syscalls not captured'})


if __name__ == '__main__':
    raise SystemExit(main())
