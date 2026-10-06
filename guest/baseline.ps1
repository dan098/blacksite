# Dot-sourced by collect.ps1. Broad snapshots, with every coverage gap reported.
if (-not ('SandboxBaseline' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Win32;
public class SandboxSnapshot {
    public List<Dictionary<string,object>> items = new List<Dictionary<string,object>>();
    public List<string> errors = new List<string>();
    public bool truncated = false;
    public int inaccessible = 0;
    public int reparse_points = 0;
    public string scope;
    public string started_at = DateTime.UtcNow.ToString("o");
    public string finished_at;
    public long estimated_bytes = 0;
}
public static class SandboxBaseline {
    static bool Full(SandboxSnapshot s, Stopwatch clock, int cap, int seconds, long bytes) {
        bool full = s.items.Count >= cap || clock.Elapsed.TotalSeconds >= seconds || s.estimated_bytes >= bytes;
        if (full) s.truncated = true;
        return full;
    }
    static void Error(SandboxSnapshot s, string path, Exception e) {
        s.inaccessible++;
        if (s.errors.Count < 128) s.errors.Add(path + ": " + e.GetType().Name + ": " + e.Message);
    }
    public static SandboxSnapshot Files(string exclude, int cap, int seconds) {
        var s = new SandboxSnapshot();
        s.scope = "All ready fixed local drives; metadata only, no content hashes; no reparse traversal. Collector output alone excluded.";
        var clock = Stopwatch.StartNew();
        var stack = new Stack<string>();
        foreach (var drive in DriveInfo.GetDrives()) {
            try { if (drive.IsReady && drive.DriveType == DriveType.Fixed) stack.Push(drive.RootDirectory.FullName); }
            catch (Exception e) { Error(s,drive.Name,e); }
        }
        string excluded = Path.GetFullPath(exclude).TrimEnd('\\') + "\\";
        while (stack.Count > 0 && !Full(s,clock,cap,seconds,64L*1024*1024)) {
            string directory = stack.Pop();
            try {
                foreach (string path in Directory.EnumerateFileSystemEntries(directory)) {
                    if (Full(s,clock,cap,seconds,64L*1024*1024)) break;
                    if ((path.TrimEnd('\\') + "\\").StartsWith(excluded,StringComparison.OrdinalIgnoreCase)) continue;
                    try {
                        var attributes = File.GetAttributes(path);
                        bool dir = (attributes & FileAttributes.Directory) != 0;
                        bool link = (attributes & FileAttributes.ReparsePoint) != 0;
                        FileSystemInfo info = dir ? (FileSystemInfo)new DirectoryInfo(path) : new FileInfo(path);
                        var item = new Dictionary<string,object>();
                        item["path"] = path; item["kind"] = dir ? "directory" : "file";
                        item["size"] = dir ? 0L : ((FileInfo)info).Length;
                        item["mtime"] = info.LastWriteTimeUtc.ToString("o");
                        item["creation_time"] = info.CreationTimeUtc.ToString("o");
                        item["attributes"] = attributes.ToString();
                        s.items.Add(item); s.estimated_bytes += path.Length*2 + 256;
                        if (link) s.reparse_points++;
                        if (dir && !link) stack.Push(path);
                    } catch (Exception e) { Error(s,path,e); }
                }
            } catch (Exception e) { Error(s,directory,e); }
        }
        s.finished_at = DateTime.UtcNow.ToString("o"); return s;
    }
    static string Digest(byte[] bytes) {
        using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();
    }
    public static SandboxSnapshot Registry(int cap, int seconds) {
        var s = new SandboxSnapshot();
        s.scope = "All accessible HKLM and HKU keys/values in 64-bit and 32-bit views; includes loaded Quickemu hive. Protected/unloaded hives not claimed.";
        var clock = Stopwatch.StartNew();
        foreach (var view in new[]{RegistryView.Registry64, RegistryView.Registry32}) {
            foreach (var hive in new[]{RegistryHive.LocalMachine,RegistryHive.Users}) {
                if (Full(s,clock,cap,seconds,96L*1024*1024)) break;
                string rootName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKU";
                try {
                    using (var root = RegistryKey.OpenBaseKey(hive,view)) {
                        var stack = new Stack<string>(); stack.Push("");
                        while (stack.Count > 0 && !Full(s,clock,cap,seconds,96L*1024*1024)) {
                            string sub = stack.Pop();
                            string path = rootName + (sub.Length > 0 ? "\\" + sub : "");
                            try {
                                using (var key = root.OpenSubKey(sub,false)) {
                                    if (key == null) continue;
                                    var marker = new Dictionary<string,object>();
                                    marker["path"] = path; marker["name"] = null; marker["kind"] = "key"; marker["view"] = view.ToString();
                                    s.items.Add(marker); s.estimated_bytes += path.Length*2 + 128;
                                    foreach (string name in key.GetValueNames()) {
                                        if (Full(s,clock,cap,seconds,96L*1024*1024)) break;
                                        try {
                                            object value = key.GetValue(name,null,RegistryValueOptions.DoNotExpandEnvironmentNames);
                                            string kind = key.GetValueKind(name).ToString();
                                            byte[] binary = value as byte[];
                                            string text;
                                            if (binary != null) text = Convert.ToBase64String(binary,0,Math.Min(binary.Length,3072));
                                            else if (value is string[]) text = string.Join("\u0000",(string[])value);
                                            else text = Convert.ToString(value,System.Globalization.CultureInfo.InvariantCulture) ?? "";
                                            var bytes = binary ?? Encoding.UTF8.GetBytes(text);
                                            bool cut = (binary != null && binary.Length > 3072) || text.Length > 4096;
                                            var item = new Dictionary<string,object>();
                                            item["path"] = path; item["name"] = name; item["kind"] = kind; item["view"] = view.ToString();
                                            item["value"] = text.Substring(0,Math.Min(text.Length,4096));
                                            item["value_sha256"] = Digest(bytes); item["value_truncated"] = cut;
                                            s.items.Add(item); s.estimated_bytes += (path.Length + name.Length + Math.Min(text.Length,4096))*2 + 256;
                                        } catch (Exception e) { Error(s,path+"\\"+name,e); }
                                    }
                                    foreach (var child in key.GetSubKeyNames()) stack.Push(sub.Length == 0 ? child : sub+"\\"+child);
                                }
                            } catch (Exception e) { Error(s,path,e); }
                        }
                    }
                } catch (Exception e) { Error(s,rootName,e); }
            }
        }
        s.finished_at = DateTime.UtcNow.ToString("o"); return s;
    }
}
'@
}
function Get-Baseline([string]$OutputDir) {
    $snapshot = [ordered]@{time=[DateTime]::UtcNow.ToString('o');files=@();registry=@();services=@();tasks=@();coverage=@{}}
    $files = [SandboxBaseline]::Files($OutputDir,200000,45)
    $snapshot.files = @($files.items.ToArray())
    $snapshot.coverage.files = @{status=$(if($files.truncated -or $files.inaccessible){'partial'}else{'completed'});scope=$files.scope;truncated=$files.truncated;inaccessible=$files.inaccessible;reparse_points=$files.reparse_points;errors=$files.errors.ToArray();count=$files.items.Count;started_at=$files.started_at;finished_at=$files.finished_at;cap=200000;seconds=45}
    $registry = [SandboxBaseline]::Registry(250000,45)
    $snapshot.registry = @($registry.items.ToArray())
    $snapshot.coverage.registry = @{status=$(if($registry.truncated -or $registry.inaccessible){'partial'}else{'completed'});scope=$registry.scope;truncated=$registry.truncated;inaccessible=$registry.inaccessible;errors=$registry.errors.ToArray();count=$registry.items.Count;started_at=$registry.started_at;finished_at=$registry.finished_at;cap=250000;seconds=45}
    try {
        $services = @((Get-CimInstance Win32_Service -ErrorAction Stop) + (Get-CimInstance Win32_SystemDriver -ErrorAction Stop))
        $snapshot.services = @($services | Sort-Object Name | ForEach-Object {
            @{Name=$_.Name;DisplayName=$_.DisplayName;PathName=$_.PathName;StartMode=$_.StartMode;State=$_.State;ServiceType=$_.ServiceType;StartName=$_.StartName;ProcessId=$_.ProcessId}
        })
        $snapshot.coverage.services = @{status='completed';count=$snapshot.services.Count;scope='Win32_Service + Win32_SystemDriver'}
    } catch { $snapshot.coverage.services = @{status='error';detail=$_.Exception.Message} }
    try {
        $taskList = New-Object 'System.Collections.Generic.List[object]'
        $tasks = @(Get-ScheduledTask -ErrorAction Stop)
        foreach ($task in $tasks) {
            if ($taskList.Count -ge 20000) { break }
            try {
                $xml = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
                $taskList.Add(@{path=($task.TaskPath+$task.TaskName);xml=$xml.Substring(0,[Math]::Min($xml.Length,65536));truncated=($xml.Length -gt 65536)})
            } catch { $taskList.Add(@{path=($task.TaskPath+$task.TaskName);error=$_.Exception.Message}) }
        }
        $snapshot.tasks = $taskList.ToArray()
        $snapshot.coverage.tasks = @{status=$(if($tasks.Count -gt 20000 -or @($snapshot.tasks | Where-Object {$_.error -or $_.truncated}).Count){'partial'}else{'completed'});count=$taskList.Count;cap=20000;scope='All scheduled task paths and definitions'}
    } catch { $snapshot.coverage.tasks = @{status='error';detail=$_.Exception.Message} }
    return $snapshot
}
function Get-SnapshotKey($Item,[string]$Category) {
    switch ($Category) {
        'registry' { return ([string]$Item.view + '|' + [string]$Item.path + '|' + $(if($Item.kind -eq 'key'){'key'}else{'value'}) + '|' + [string]$Item.name).ToLowerInvariant() }
        'services' { return ([string]$Item.Name).ToLowerInvariant() }
        default { return ([string]$Item.path).ToLowerInvariant() }
    }
}
function Get-SnapshotComparable($Item,[string]$Category) {
    $fields = switch ($Category) {
        'files' { @('kind','size','mtime','creation_time','attributes') }
        'registry' { @('kind','value_sha256') }
        'services' { @('Name','DisplayName','PathName','StartMode','State','ServiceType','StartName','ProcessId') }
        'tasks' { @('xml','error','truncated') }
    }
    return (@($fields | ForEach-Object { [string]$Item.$_ }) | ConvertTo-Json -Compress)
}
function Get-BaselineDiff($Before,$After) {
    $result = [ordered]@{registry=@();files=@();services=@();tasks=@();coverage=@{}}
    foreach ($category in @('registry','files','services','tasks')) {
        $previous = @{}
        $current = @{}
        foreach ($item in $Before.$category) { $previous[(Get-SnapshotKey $item $category)] = $item }
        foreach ($item in $After.$category) { $current[(Get-SnapshotKey $item $category)] = $item }
        $changes = New-Object 'System.Collections.Generic.List[object]'
        $total = 0
        $incomplete = $Before.coverage.$category.status -ne 'completed' -or $After.coverage.$category.status -ne 'completed'
        foreach ($key in $current.Keys) {
            $action = $null
            if (-not $previous.ContainsKey($key)) { $action=$(if($Before.coverage.$category.status -eq 'completed'){'created'}else{'not_observed_before'}) }
            elseif ((Get-SnapshotComparable $previous[$key] $category) -cne (Get-SnapshotComparable $current[$key] $category)) { $action='modified' }
            if ($action) {
                $total++
                if ($changes.Count -lt 10000) { $changes.Add(@{id=('change:'+$category+':'+$total);action=$action;path=$current[$key].path;before=$previous[$key];after=$current[$key];related=$false;attribution='snapshot_delta_not_causality';coverage_partial=$incomplete}) }
            }
        }
        foreach ($key in $previous.Keys) {
            if (-not $current.ContainsKey($key)) {
                $total++
                # Missing in a partial snapshot is not proof of deletion.
                $action = $(if($incomplete){'not_observed_after'}else{'deleted'})
                if ($changes.Count -lt 10000) { $changes.Add(@{id=('change:'+$category+':'+$total);action=$action;path=$previous[$key].path;before=$previous[$key];after=$null;related=$false;attribution='snapshot_delta_not_causality';coverage_partial=$incomplete}) }
            }
        }
        $result.$category = $changes.ToArray()
        $result.coverage[$category] = @{total=$total;retained=$changes.Count;cap=10000;truncated=($total -gt 10000);baseline_partial=$incomplete}
    }
    return $result
}
