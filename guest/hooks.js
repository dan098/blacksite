'use strict';
// Observation only. No interception/replacement, anti-analysis patches or kernel claims.
const maxEvents = 50000;
let emitted = 0;
let sequence = 0;
const hooked = new Set();
const failures = [];
const agentThread = Process.getCurrentThreadId();
// Hot allocator/pipe/loader hooks can re-enter Frida and stall the application.
// Keep them explicitly outside coverage instead of sacrificing sample execution.
const excluded = new Set(['ReadFile','WriteFile','VirtualAlloc','VirtualProtect',
  'LoadLibraryW','LoadLibraryExW','NtReadFile','NtWriteFile','NtAllocateVirtualMemory',
  'NtProtectVirtualMemory','NtWriteVirtualMemory','NtCreateThreadEx','NtDeviceIoControlFile']);
const scalar = value => { try { return value.toString(); } catch (_) { return '?'; } };
function text(pointer, wide) {
  try { if (pointer.isNull()) return null; return wide ? pointer.readUtf16String(512) : pointer.readUtf8String(512); }
  catch (_) { return '<unreadable>'; }
}
function objectName(pointer) {
  try {
    if (pointer.isNull()) return null;
    const offset = Process.pointerSize === 8 ? 16 : 8;
    const unicode = pointer.add(offset).readPointer();
    if (unicode.isNull()) return null;
    const length = unicode.readU16();
    const buffer = unicode.add(Process.pointerSize === 8 ? 8 : 4).readPointer();
    return buffer.readUtf16String(Math.min(length / 2, 512));
  } catch (_) { return '<unreadable OBJECT_ATTRIBUTES>'; }
}
function stack(context) {
  // Fuzzy return-address candidates avoid DbgHelp/module lookup inside loader hooks.
  // Accuracy is explicit; these are not symbol-resolved/kernel stacks.
  let frames;
  try { frames = Thread.backtrace(context, Backtracer.FUZZY); }
  catch (_) { return {accuracy:'unavailable',frames:[]}; }
  return {accuracy:'fuzzy',frames:frames.slice(0,24).map(address => ({address:address.toString()}))};
}
function emit(event) {
  if (emitted >= maxEvents) return;
  emitted++;
  send(Object.assign({ type: 'call', timestamp: new Date().toISOString(), pid: Process.id,
    tid: Process.getCurrentThreadId(), coverage: 'user-mode only; not kernel syscall telemetry' }, event));
}
const specs = [
  ['kernel32.dll','CreateFileW',a => ({path:text(a[0],true),access:scalar(a[1]),disposition:scalar(a[4])})],
  ['kernel32.dll','CreateFileA',a => ({path:text(a[0],false),access:scalar(a[1]),disposition:scalar(a[4])})],
  ['kernel32.dll','ReadFile',a => ({handle:scalar(a[0]),bytes:scalar(a[2])})],
  ['kernel32.dll','WriteFile',a => ({handle:scalar(a[0]),bytes:scalar(a[2])})],
  ['kernel32.dll','DeleteFileW',a => ({path:text(a[0],true)})],
  ['kernel32.dll','MoveFileExW',a => ({from:text(a[0],true),to:text(a[1],true),flags:scalar(a[2])})],
  ['kernel32.dll','CreateProcessW',a => ({application:text(a[0],true),command_line:text(a[1],true),flags:scalar(a[5])})],
  ['kernel32.dll','CreateProcessA',a => ({application:text(a[0],false),command_line:text(a[1],false),flags:scalar(a[5])})],
  ['kernel32.dll','OpenProcess',a => ({access:scalar(a[0]),target_pid:a[2].toUInt32()})],
  ['kernel32.dll','VirtualAlloc',a => ({address:scalar(a[0]),size:scalar(a[1]),protection:scalar(a[3])})],
  ['kernel32.dll','VirtualProtect',a => ({address:scalar(a[0]),size:scalar(a[1]),protection:scalar(a[2])})],
  ['kernel32.dll','WriteProcessMemory',a => ({process:scalar(a[0]),address:scalar(a[1]),bytes:scalar(a[3])})],
  ['kernel32.dll','CreateRemoteThread',a => ({process:scalar(a[0]),start:scalar(a[3])})],
  ['kernel32.dll','LoadLibraryW',a => ({path:text(a[0],true)})],
  ['kernel32.dll','LoadLibraryExW',a => ({path:text(a[0],true),flags:scalar(a[2])})],
  ['advapi32.dll','RegCreateKeyExW',a => ({hive:scalar(a[0]),key:text(a[1],true),access:scalar(a[5])})],
  ['advapi32.dll','RegOpenKeyExW',a => ({hive:scalar(a[0]),key:text(a[1],true),access:scalar(a[3])})],
  ['advapi32.dll','RegSetValueExW',a => ({key:scalar(a[0]),name:text(a[1],true),value_type:scalar(a[3]),bytes:scalar(a[5])})],
  ['advapi32.dll','RegDeleteKeyW',a => ({hive:scalar(a[0]),key:text(a[1],true)})],
  ['advapi32.dll','RegDeleteValueW',a => ({key:scalar(a[0]),name:text(a[1],true)})],
  ['advapi32.dll','OpenSCManagerW',a => ({machine:text(a[0],true),database:text(a[1],true),access:scalar(a[2])})],
  ['advapi32.dll','CreateServiceW',a => ({name:text(a[1],true),display:text(a[2],true),service_type:scalar(a[4]),image:text(a[7],true)})],
  ['advapi32.dll','StartServiceW',a => ({service:scalar(a[0]),argc:scalar(a[1])})],
  ['advapi32.dll','DeleteService',a => ({service:scalar(a[0])})],
  ['shell32.dll','ShellExecuteW',a => ({verb:text(a[1],true),file:text(a[2],true),parameters:text(a[3],true)})],
  ['ws2_32.dll','connect',a => ({socket:scalar(a[0]),sockaddr:scalar(a[1]),length:scalar(a[2])})],
  ['ws2_32.dll','send',a => ({socket:scalar(a[0]),bytes:scalar(a[2])})],
  ['ws2_32.dll','recv',a => ({socket:scalar(a[0]),bytes:scalar(a[2])})],
  ['winhttp.dll','WinHttpConnect',a => ({server:text(a[1],true),port:a[2].toUInt32()})],
  ['winhttp.dll','WinHttpOpenRequest',a => ({verb:text(a[1],true),path:text(a[2],true)})],
  ['wininet.dll','InternetOpenUrlW',a => ({url:text(a[1],true)})],
  ['ucrtbase.dll','fopen',a => ({path:text(a[0],false),mode:text(a[1],false)})],
  ['ucrtbase.dll','_wfopen',a => ({path:text(a[0],true),mode:text(a[1],true)})],
  ['msvcrt.dll','fopen',a => ({path:text(a[0],false),mode:text(a[1],false)})],
  ['ntdll.dll','NtCreateFile',a => ({access:scalar(a[1]),object_name:objectName(a[2]),disposition:scalar(a[7])})],
  ['ntdll.dll','NtOpenFile',a => ({access:scalar(a[1]),object_name:objectName(a[2])})],
  ['ntdll.dll','NtReadFile',a => ({handle:scalar(a[0]),bytes:scalar(a[6])})],
  ['ntdll.dll','NtWriteFile',a => ({handle:scalar(a[0]),bytes:scalar(a[6])})],
  ['ntdll.dll','NtDeleteFile',a => ({object_name:objectName(a[0])})],
  ['ntdll.dll','NtSetInformationFile',a => ({handle:scalar(a[0]),information_class:scalar(a[4])})],
  ['ntdll.dll','NtCreateKey',a => ({access:scalar(a[1]),object_name:objectName(a[2])})],
  ['ntdll.dll','NtOpenKey',a => ({access:scalar(a[1]),object_name:objectName(a[2])})],
  ['ntdll.dll','NtSetValueKey',a => ({key:scalar(a[0]),value_type:scalar(a[3]),bytes:scalar(a[5])})],
  ['ntdll.dll','NtDeleteKey',a => ({key:scalar(a[0])})],
  ['ntdll.dll','NtOpenProcess',a => ({access:scalar(a[1]),client_id:scalar(a[3])})],
  ['ntdll.dll','NtAllocateVirtualMemory',a => ({process:scalar(a[0]),allocation_type:scalar(a[4]),protection:scalar(a[5])})],
  ['ntdll.dll','NtProtectVirtualMemory',a => ({process:scalar(a[0]),protection:scalar(a[3])})],
  ['ntdll.dll','NtWriteVirtualMemory',a => ({process:scalar(a[0]),address:scalar(a[1]),bytes:scalar(a[3])})],
  ['ntdll.dll','NtCreateThreadEx',a => ({process:scalar(a[3]),start:scalar(a[4]),flags:scalar(a[6])})],
  ['ntdll.dll','NtCreateUserProcess',a => ({process_flags:scalar(a[6]),thread_flags:scalar(a[7])})],
  ['ntdll.dll','NtDeviceIoControlFile',a => ({handle:scalar(a[0]),control_code:scalar(a[5]),input_bytes:scalar(a[7]),output_bytes:scalar(a[9])})],
  ['ntdll.dll','NtLoadDriver',a => ({registry_unicode_string:scalar(a[0])})],
];
function install(moduleName, api, describe) {
  const key = moduleName + '!' + api;
  if (excluded.has(api)) return;
  if (hooked.has(key)) return;
  const module = Process.findModuleByName(moduleName);
  if (!module) return;
  let address;
  try { address = module.findExportByName(api); } catch (_) { return; }
  if (!address) return;
  try {
    send({type:'status',sensor:'hook_install',stage:'installing',api:key,pid:Process.id,timestamp:new Date().toISOString()});
    Interceptor.attach(address, {
      onEnter(args) {
        if (emitted >= maxEvents || Process.getCurrentThreadId() === agentThread) return;
        this.callId = Process.id + ':' + (++sequence);
        this.callTime = new Date().toISOString();
        const trace = stack(this.context);
        let values; try { values = describe(args); } catch (_) { values = {error:'argument decoding unavailable'}; }
        emit({api:key,phase:'enter',call_id:this.callId,time:this.callTime,arguments:values,
          stack:trace.frames,stack_accuracy:trace.accuracy});
      },
      onLeave(retval) {
        if (!this.callId) return;
        emit({api:key,phase:'leave',call_id:this.callId,time:new Date().toISOString(),
          return_value:scalar(retval),entry_time:this.callTime});
      }
    });
    hooked.add(key);
  } catch (error) { failures.push({api:key,error:String(error).slice(0,512)}); }
}
function refresh() {
  specs.forEach(spec => install(spec[0],spec[1],spec[2]));
}
refresh();
// Refresh outside module-loader callbacks; never load an extra DLL to gain a hook.
setInterval(refresh, 500);
send({type:'coverage',pid:Process.id,timestamp:new Date().toISOString(),hooked:Array.from(hooked),
  requested:specs.map(s => s[0]+'!'+s[1]),excluded:Array.from(excluded),failures,limit:maxEvents,stack_accuracy:'fuzzy',
  detail:'C APIs and Nt user-mode entry points only; direct syscalls, unhooked code, protected processes and kernel are not covered'});
