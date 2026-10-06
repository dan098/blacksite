# Dot-source, then Invoke-PayloadCapture -Events $sysmon.events -Launch $launch -OutputDir $OutputDir.
# Windows PowerShell 5.1; reads evidence only. No artifact is executed, extracted or uploaded.
function Invoke-PayloadCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Events,
        [Parameter(Mandatory=$true)][object]$Launch,
        [Parameter(Mandatory=$true)][string]$OutputDir
    )
    $ErrorActionPreference = 'Stop'
    $maxFiles=16; $maxFileBytes=16777216L; $maxTotalBytes=67108864L
    $maxRecords=256; $maxManifestBytes=1048576; $maxSeconds=45
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $utf8 = New-Object Text.UTF8Encoding($false)
    $items = New-Object 'System.Collections.Generic.List[object]'
    $manifest = [ordered]@{
        schema_version=1; status='completed'; truncated=$false; root_process=$null; payloads=@()
        budgets=[ordered]@{max_files=$maxFiles;max_file_bytes=$maxFileBytes;max_total_bytes=$maxTotalBytes;max_manifest_bytes=$maxManifestBytes;max_metadata_records=$maxRecords;max_seconds=$maxSeconds;collected_files=0;collected_bytes=0L;bytes_read=0L;candidate_events=0;metadata_records=0}
        flags=@('private_artifacts_only','untrusted_guest_metadata','capture_at_finish_not_download_time');warnings=@()
    }
    # Open native handles with OPEN_REPARSE_POINT. Pin every ancestor without
    # FILE_SHARE_DELETE, inspect attributes, and compare the handle's final path.
    # This closes the ordinary check/open symlink and directory-swap race.
    if (-not ('SandboxPayload.SafeFile' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace SandboxPayload {
  public sealed class SafeFile : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct FileInfo {
      public uint Attributes;
      public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
      public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInfo info);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder path,uint length,uint flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle handle,int informationClass,IntPtr info,uint size);
    List<SafeFileHandle> directories = new List<SafeFileHandle>();
    string parentPath;
    public FileStream Stream { get; private set; }
    public long Length { get; private set; }
    public DateTime LastWriteUtc { get; private set; }
    static FileInfo Inspect(SafeFileHandle handle,string expected,bool directory) {
      if(handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
      FileInfo info;
      if(!GetFileInformationByHandle(handle,out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
      if((info.Attributes & 0x400)!=0) throw new IOException("reparse_path_rejected");
      if(((info.Attributes & 0x10)!=0)!=directory) throw new IOException("directory_or_non_directory_rejected");
      if(!directory && info.Links!=1) throw new IOException("hardlink_rejected");
      StringBuilder path = new StringBuilder(32768);
      uint length=GetFinalPathNameByHandle(handle,path,(uint)path.Capacity,0);
      if(length==0 || length>=path.Capacity) throw new IOException("final_path_unavailable");
      string final=path.ToString();
      if(final.StartsWith(@"\\?\")) final=final.Substring(4);
      if(!String.Equals(final.TrimEnd('\\'),expected.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))
        throw new IOException("redirected_path_rejected");
      return info;
    }
    public static SafeFile Open(string path,bool write,bool createNew) {
      SafeFile result=new SafeFile();
      SafeFileHandle handle=null;
      try {
        string full=Path.GetFullPath(path);
        string parent=Path.GetDirectoryName(full);
        string root=Path.GetPathRoot(full);
        List<string> parents=new List<string>();
        parents.Add(root);
        string current=root;
        foreach(string part in parent.Substring(root.Length).Split(new char[]{'\\'},StringSplitOptions.RemoveEmptyEntries)) {
          current=Path.Combine(current,part); parents.Add(current);
        }
        foreach(string dir in parents) {
          SafeFileHandle pinned=CreateFile(dir,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
          result.directories.Add(pinned); Inspect(pinned,dir,true);
        }
        handle=CreateFile(full,write?0xC0010000u:0x80000000u,write?0u:1u,IntPtr.Zero,write?(createNew?1u:4u):3u,0x08200000,IntPtr.Zero);
        FileInfo info=Inspect(handle,full,false);
        result.parentPath=parent;
        result.Length=((long)info.SizeHigh<<32)|info.SizeLow;
        long written=((long)info.Written.dwHighDateTime<<32)|(uint)info.Written.dwLowDateTime;
        result.LastWriteUtc=DateTime.FromFileTimeUtc(written);
        result.Stream=new FileStream(handle,write?FileAccess.ReadWrite:FileAccess.Read,65536,false);
        handle=null;
        if(write) result.Stream.SetLength(0);
        return result;
      } catch { if(handle!=null) handle.Dispose(); result.Dispose(); throw; }
    }
    public void Rename(string basename) {
      if(String.IsNullOrEmpty(basename) || basename!=Path.GetFileName(basename) || basename.IndexOfAny(new char[]{'\\','/',':'})>=0)
        throw new IOException("unsafe_rename_name");
      // Win32 expects an absolute DOS path with a null RootDirectory here.
      // All ancestors remain pinned without FILE_SHARE_DELETE during rename.
      byte[] name=Encoding.Unicode.GetBytes(Path.Combine(parentPath,basename));
      int rootOffset=IntPtr.Size==8?8:4;
      int lengthOffset=rootOffset+IntPtr.Size;
      int nameOffset=lengthOffset+4;
      int size=nameOffset+name.Length+2;
      IntPtr info=Marshal.AllocHGlobal(size);
      try {
        for(int i=0;i<size;i++) Marshal.WriteByte(info,i,0); // ReplaceIfExists=false.
        Marshal.WriteInt32(info,lengthOffset,name.Length);
        Marshal.Copy(name,0,IntPtr.Add(info,nameOffset),name.Length);
        // FileRenameInfo=3; the output handle remains exclusively open.
        if(!SetFileInformationByHandle(Stream.SafeFileHandle,3,info,(uint)size))
          throw new Win32Exception(Marshal.GetLastWin32Error());
      } finally { Marshal.FreeHGlobal(info); }
    }
    public void Dispose() {
      if(Stream!=null) { Stream.Dispose(); Stream=null; }
      for(int i=directories.Count-1;i>=0;i--) directories[i].Dispose();
      directories.Clear();
    }
  }
}
'@ | Out-Null
    }
    function Field($Object,[string]$Name) {
        if ($null -eq $Object) { return $null }
        if ($Object -is [Collections.IDictionary]) { return $Object[$Name] }
        $p=$Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }; return $null
    }
    function Text($Value,[int]$Limit=1024) {
        $s=[string]$Value; if($s.Length -gt $Limit){return $s.Substring(0,$Limit)}; return $s
    }
    function Parse-Time($Value) {
        try { return [DateTimeOffset]::Parse([string]$Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime }
        catch { return $null }
    }
    function Parse-Pid($Value) {
        $number=0L; if([long]::TryParse([string]$Value,[ref]$number) -and $number -gt 0 -and $number -le 4294967295L){return $number}; return $null
    }
    function Guid-Key($Value) { return ([string]$Value).Trim().ToLowerInvariant() }
    function Event-Ref($Event) {
        return @{source='sysmon';event_id=$Event.id;record_id=$Event.record_id;index=$Event.index;time=$Event.time.ToString('o')}
    }
    function Process-Metadata($Process) {
        if(-not $Process){return $null}
        return @{identity=$Process.identity;guid=$Process.guid;pid=$Process.pid;start_time=$Process.start.ToString('o');image=(Text $Process.image);identity_source=$Process.identity_source;parent_identity=$Process.parent_identity}
    }
    function Path-Rejection([string]$Path) {
        if (-not $Path -or $Path.Length -gt 2048) { return 'invalid_source_path' }
        if ($Path -notmatch '^[cC]:\\' -or $Path.Contains('/') -or $Path -match '[\x00-\x1f]') { return 'unsafe_source_path' }
        foreach($part in $Path.Substring(3).Split('\')) {
            if(-not $part -or $part -in '.','..' -or $part.EndsWith('.') -or $part.EndsWith(' ') -or $part -match '[:*?"<>|]') { return 'unsafe_source_path' }
            if($part.Split('.')[0].TrimEnd(' ') -match '^(?i:con|conin\$|conout\$|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])$') { return 'device_path_rejected' }
        }
        return ''
    }
    $outputReason=Path-Rejection $OutputDir
    if($outputReason -or $OutputDir -notmatch '^(?i:C:\\Sandbox\\runs\\)[^\\]+$') { throw 'Payload output must be a local C:\Sandbox\runs\<run> directory without redirects' }
    $all = New-Object 'System.Collections.Generic.List[object]'
    $processes=@{}; $pidHistory=@{}
    $inputIndex=0
    foreach($raw in $Events) {
        if($inputIndex -ge 50000){$manifest.truncated=$true;$manifest.warnings+= 'sysmon_input_event_cap';break}
        $eventTime=Parse-Time (Field $raw 'time')
        $id=Field $raw 'event_id';if($null -eq $id){$id=Field $raw 'id'}
        $parsedId=0
        if($eventTime -and [int]::TryParse([string]$id,[ref]$parsedId)) {
            $all.Add(@{id=$parsedId;record_id=(Field $raw 'record_id');index=$inputIndex;time=$eventTime;data=(Field $raw 'data')})
        }
        $inputIndex++
    }
    $ordered=@($all | Sort-Object @{Expression={$_.time}},@{Expression={$_.index}})
    foreach($e in $ordered) {
        if($e.id -ne 1){continue}
        $processPid=Parse-Pid (Field $e.data 'ProcessId'); if(-not $processPid){continue}
        $guid=Guid-Key (Field $e.data 'ProcessGuid')
        $key=$guid; $basis='sysmon_guid'
        if(-not $key){$key='pid:'+ $processPid + ':' + $e.time.ToString('o') + ':' + $e.index;$basis='pid_time'}
        if($processes.ContainsKey($key)){continue}
        $p=@{identity=$key;guid=$guid;pid=$processPid;start=$e.time;end=$null;end_index=$null;reuse_event=$null;image=(Field $e.data 'Image');command_line=(Field $e.data 'CommandLine');identity_source=$basis;parent_guid=(Guid-Key (Field $e.data 'ParentProcessGuid'));ppid=(Parse-Pid (Field $e.data 'ParentProcessId'));parent_identity='';related=$false;create_event=$e}
        $processes[$key]=$p
        $pidKey=[string]$processPid
        if(-not $pidHistory.ContainsKey($pidKey)){$pidHistory[$pidKey]=New-Object 'System.Collections.Generic.List[object]'}
        $pidHistory[$pidKey].Add($p)
    }
    # Input index preserves the actual Get-Events -Oldest Sysmon record order.
    # Use (UTC time, record order) boundaries: timestamps alone lose tied events.
    function Within-Process($Process,$Event) {
        if(-not $Process){return $false}
        if($Event.time -lt $Process.start -or ($Event.time -eq $Process.start -and $Event.index -lt $Process.create_event.index)){return $false}
        $reuse=$Process.reuse_event
        if($reuse -and ($Event.time -gt $reuse.time -or ($Event.time -eq $reuse.time -and $Event.index -ge $reuse.index))){return $false}
        if($null -ne $Process.end -and ($Event.time -gt $Process.end -or ($Event.time -eq $Process.end -and $Event.index -gt $Process.end_index))){return $false}
        return $true
    }
    function Resolve-Pid($ProcessId,$Event) {
        $candidate=$null
        foreach($p in $pidHistory[[string]$ProcessId]) {
            if($p.start -lt $Event.time -or ($p.start -eq $Event.time -and $p.create_event.index -le $Event.index)){$candidate=$p}else{break}
        }
        if(Within-Process $candidate $Event){return $candidate};return $null
    }
    # The next creation is an exclusive boundary, not timestamp-minus-one.
    foreach($history in $pidHistory.Values) {
        for($n=0;$n -lt $history.Count-1;$n++){$history[$n].reuse_event=$history[$n+1].create_event}
    }
    function Resolve-Event($Event) {
        $guid=Guid-Key (Field $Event.data 'ProcessGuid')
        if($guid) {
            $p=$processes[$guid]
            if(Within-Process $p $Event){return $p}
            return $null # Explicit unknown GUID never falls back to an unrelated PID.
        }
        return Resolve-Pid (Parse-Pid (Field $Event.data 'ProcessId')) $Event
    }
    foreach($e in $ordered) {
        if($e.id -eq 5) {
            $p=Resolve-Event $e
            if($p -and ($null -eq $p.end -or $e.time -lt $p.end -or ($e.time -eq $p.end -and $e.index -lt $p.end_index))){$p.end=$e.time;$p.end_index=$e.index}
        }
    }
    foreach($p in $processes.Values) {
        $parent=$null
        if($p.parent_guid){$parent=$processes[$p.parent_guid]}
        elseif($p.ppid){$parent=Resolve-Pid $p.ppid $p.create_event}
        if($parent -and $parent.identity -ne $p.identity -and (Within-Process $parent $p.create_event)){$p.parent_identity=$parent.identity}
    }
    $launchPid=Parse-Pid (Field $Launch 'root_pid');$launchTime=Parse-Time (Field $Launch 'launch_time')
    $root=$null
    if($launchPid -and $launchTime) {
        $candidates=@($pidHistory[[string]$launchPid] | Where-Object { $_.start -ge $launchTime.AddMilliseconds(-250) -and $_.start -le $launchTime.AddSeconds(15) })
        # Fail closed rather than guessing when multiple lifetimes fit the launch.
        if($candidates.Count -eq 1){$root=$candidates[0]}
    }
    if(-not $root){$manifest.status='unavailable';$manifest.warnings+= 'root_process_identity_unavailable'}
    else {
        $manifest.root_process=Process-Metadata $root
        $root.related=$true
        $children=@{}
        foreach($p in $processes.Values) {
            if($p.parent_identity) {
                if(-not $children.ContainsKey($p.parent_identity)){$children[$p.parent_identity]=New-Object 'System.Collections.Generic.List[object]'}
                $children[$p.parent_identity].Add($p)
            }
        }
        $pending=New-Object 'System.Collections.Generic.Queue[object]';$pending.Enqueue($root)
        while($pending.Count) {
            $parent=$pending.Dequeue()
            foreach($p in $children[$parent.identity]){if(-not $p.related){$p.related=$true;$pending.Enqueue($p)}}
        }
    }
    $deletions=@{}; $uses=@{}
    foreach($e in $ordered) {
        $p=Resolve-Event $e
        if(-not $p -or -not $p.related){continue}
        if($e.id -in 23,26) {
            $target=[string](Field $e.data 'TargetFilename')
            if($target){$deletions[$target.ToLowerInvariant()]=$e}
        }
        if($e.id -in 1,7) {
            $target=if($e.id -eq 1){[string](Field $e.data 'Image')}else{[string](Field $e.data 'ImageLoaded')}
            if($target) {
                $key=$target.ToLowerInvariant()
                if(-not $uses.ContainsKey($key)){$uses[$key]=New-Object 'System.Collections.Generic.List[object]'}
                if($uses[$key].Count -lt 16){$uses[$key].Add(@{process=(Process-Metadata $p);event_ref=(Event-Ref $e);association=$(if($e.id -eq 1){'process_image'}else{'image_load'})})}
            }
        }
    }
    $seen=@{};$referenceComparisons=0
    foreach($e in $ordered) {
        if($e.id -ne 11){continue}
        $p=Resolve-Event $e
        if(-not $p -or -not $p.related){continue}
        $source=[string](Field $e.data 'TargetFilename')
        $ext=[regex]::Match($source,'\.[^\\./]+$').Value.ToLowerInvariant()
        if($ext -notin '.exe','.dll','.sys','.ps1','.bat','.cmd','.vbs','.js','.msi','.scr','.jar','.zip'){continue}
        $manifest.budgets.candidate_events++
        if($items.Count -ge $maxRecords){$manifest.truncated=$true;continue}
        $record=[ordered]@{index=$items.Count;artifact_index=$null;source_path=(Text $source 2048);source_process=(Process-Metadata $p);event_ref=(Event-Ref $e);sha256=$null;size=$null;status='unavailable';artifact_name=$null;flags=@('captured_at_finish','source_attribution_not_authenticity');detail='';observed_uses=@()}
        $items.Add($record)
        $key=$source.ToLowerInvariant()
        if($deletions.ContainsKey($key) -and $deletions[$key].time -ge $e.time){$record.flags+='delete_event_observed'}
        if($uses.ContainsKey($key)){$record.observed_uses=@($uses[$key].ToArray())}
        # Full-path command-line references, not a filename deny/allowlist. A
        # reference is explicitly not proof that this script was executed.
        foreach($child in $processes.Values) {
            if($record.observed_uses.Count -ge 16){$record.flags+='use_reference_cap';break}
            $referenceComparisons++
            if($referenceComparisons -gt 100000 -or $clock.Elapsed.TotalSeconds -ge $maxSeconds){$record.flags+='use_scan_budget';break}
            if($child.related -and $child.start -ge $e.time -and $source -and ([string]$child.command_line).IndexOf($source,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $record.observed_uses+=@{process=(Process-Metadata $child);event_ref=(Event-Ref $child.create_event);association='command_line_path_reference_not_execution_proof'}
            }
        }
        $reason=Path-Rejection $source
        if($reason){$record.status='rejected';$record.detail=$reason;$record.flags+=$reason;continue}
        if($seen.ContainsKey($key)){$record.status='unavailable';$record.detail='duplicate_target_already_considered';$record.flags+='duplicate_target';continue}
        $seen[$key]=$true
        if($clock.Elapsed.TotalSeconds -ge $maxSeconds){$record.status='over_limit';$record.detail='capture_time_budget';$record.flags+='time_budget';$manifest.truncated=$true;continue}
        $input=$null;$output=$null;$hasher=$null;$temp=$null
        try {
            $input=[SandboxPayload.SafeFile]::Open($source,$false,$false)
            $record.size=$input.Length
            $record.last_write_utc=$input.LastWriteUtc.ToString('o')
            if($input.Length -gt $maxFileBytes){$record.status='over_limit';$record.detail='per_file_byte_budget';$record.flags+='file_byte_budget';continue}
            if($manifest.budgets.collected_files -ge $maxFiles){$record.status='over_limit';$record.detail='file_count_budget';$record.flags+='file_count_budget';continue}
            if($manifest.budgets.bytes_read+$input.Length -gt $maxTotalBytes){$record.status='over_limit';$record.detail='total_byte_budget';$record.flags+='total_byte_budget';continue}
            $slot=$manifest.budgets.collected_files
            $temp=Join-Path $OutputDir ('payload-capture-'+$record.index.ToString('000')+'.tmp')
            $output=[SandboxPayload.SafeFile]::Open($temp,$true,$true)
            $hasher=[Security.Cryptography.SHA256]::Create()
            $buffer=New-Object byte[] 65536;$written=0L
            while(($count=$input.Stream.Read($buffer,0,$buffer.Length)) -gt 0) {
                $manifest.budgets.bytes_read+=$count
                if($written+$count -gt $maxFileBytes -or $manifest.budgets.bytes_read -gt $maxTotalBytes){throw 'stream_byte_budget'}
                if($clock.Elapsed.TotalSeconds -ge $maxSeconds){throw 'capture_time_budget'}
                $output.Stream.Write($buffer,0,$count)
                [void]$hasher.TransformBlock($buffer,0,$count,$buffer,0)
                $written+=$count
            }
            [void]$hasher.TransformFinalBlock((New-Object byte[] 0),0,0)
            if($written -ne $input.Length){throw 'source_size_changed'}
            $digest=([BitConverter]::ToString($hasher.Hash)).Replace('-','').ToLowerInvariant()
            $name='payload-'+$slot.ToString('000')+'-'+$digest+'.bin'
            $output.Stream.Flush($true)
            # Rename this exact handle while it and all ancestors remain pinned.
            $output.Rename($name)
            $temp=$null
            $record.status='collected';$record.sha256=$digest;$record.size=$written;$record.artifact_name=$name;$record.artifact_index=$slot
            $manifest.budgets.collected_files++;$manifest.budgets.collected_bytes+=$written
        } catch {
            $failure=$_.Exception
            while($failure.InnerException){$failure=$failure.InnerException}
            if($failure -is [ComponentModel.Win32Exception] -and $failure.NativeErrorCode -in 2,3) {
                $record.status=$(if($record.flags -contains 'delete_event_observed'){'deleted'}else{'missing'})
                $record.detail='source_unavailable_at_finish'
            } elseif($failure.Message -match 'reparse|redirected|directory_or_non_directory|hardlink') {
                $record.status='rejected';$record.detail=Text $failure.Message 256;$record.flags+='unsafe_filesystem_object'
            } elseif($failure.Message -match 'budget') {
                $record.status='over_limit';$record.detail=Text $failure.Message 256;$record.flags+='capture_budget';$manifest.truncated=$true
            } else {$record.status='unavailable';$record.detail=Text $failure.Message 256;$record.flags+='read_or_copy_failed'}
        } finally {
            if($hasher){$hasher.Dispose()}
            if($output){$output.Dispose()}
            if($input){$input.Dispose()}
            # Do not delete a potentially replaced path in a sample-writable dir.
            # Partial .tmp content is not published or pulled as an artifact.
        }
    }
    if($manifest.status -ne 'unavailable' -and ($manifest.truncated -or @($items | Where-Object {$_.status -ne 'collected'}).Count)){$manifest.status='partial'}
    $manifest.payloads=$items.ToArray();$manifest.budgets.metadata_records=$items.Count
    $json=$manifest | ConvertTo-Json -Depth 16 -Compress
    while($utf8.GetByteCount($json) -gt $maxManifestBytes -and $items.Count) {
        $manifest.truncated=$true;$manifest.status='partial'
        $items.RemoveAt($items.Count-1)
        $manifest.payloads=$items.ToArray();$manifest.budgets.metadata_records=$items.Count
        $json=$manifest | ConvertTo-Json -Depth 16 -Compress
    }
    if($utf8.GetByteCount($json) -gt $maxManifestBytes){throw 'Payload manifest byte budget exceeded'}
    $manifestFile=$null
    try {
        $manifestFile=[SandboxPayload.SafeFile]::Open((Join-Path $OutputDir 'payloads.json'),$true,$false)
        $bytes=$utf8.GetBytes($json);$manifestFile.Stream.Write($bytes,0,$bytes.Length);$manifestFile.Stream.Flush($true)
    } finally {if($manifestFile){$manifestFile.Dispose()}}
    return @{status=$manifest.status;manifest='payloads.json';budgets=$manifest.budgets;truncated=$manifest.truncated;detail='Private untrusted guest evidence; host must verify bytes and hashes'}
}
