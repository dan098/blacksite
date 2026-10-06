// Windows x64 / .NET Framework 4.x. No driver, hooks, symbols, or security changes.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace SandboxKernel {
    public sealed class Decoder {
        // Native x64 SDK layouts: EVENT_TRACE_LOGFILEW = 448, EVENT_RECORD = 112.
        // Keeping unused native fields opaque avoids marshalling native pointer strings.
        [StructLayout(LayoutKind.Explicit, Size=448)]
        struct LogFile {
            [FieldOffset(0)] public IntPtr FileName;
            [FieldOffset(28)] public uint Mode;
            [FieldOffset(164)] public uint PointerSize;  // TRACE_LOGFILE_HEADER + 44
            [FieldOffset(168)] public uint EventsLost;
            [FieldOffset(376)] public long PerfFreq;
            [FieldOffset(384)] public long StartTime;
            [FieldOffset(392)] public uint ClockType;
            [FieldOffset(396)] public uint BuffersLost;
            [FieldOffset(400)] public IntPtr BufferCallback;
            [FieldOffset(424)] public IntPtr EventCallback;
        }
        [StructLayout(LayoutKind.Explicit, Size=112)]
        struct Record {
            [FieldOffset(4)] public ushort Flags;
            [FieldOffset(8)] public uint Tid;
            [FieldOffset(12)] public uint Pid;
            [FieldOffset(16)] public long Timestamp;
            [FieldOffset(24)] public Guid Provider;
            [FieldOffset(40)] public ushort Id;
            [FieldOffset(42)] public byte Version;
            [FieldOffset(45)] public byte Opcode;
            [FieldOffset(46)] public ushort Task;
            [FieldOffset(48)] public ulong Keywords;
            [FieldOffset(64)] public Guid Activity;
            [FieldOffset(80)] public byte Processor;
            [FieldOffset(84)] public ushort ExtendedCount;
            [FieldOffset(86)] public ushort UserLength;
            [FieldOffset(88)] public IntPtr ExtendedData;
            [FieldOffset(96)] public IntPtr UserData;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct PropertyDescriptor {
            public ulong Name;
            public uint ArrayIndex;
            public uint Reserved;
        }
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate void EventCallback(IntPtr record);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate uint BufferCallback(IntPtr logfile);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
        static extern ulong OpenTraceW(ref LogFile logfile);
        [DllImport("advapi32.dll")] static extern uint ProcessTrace([In] ulong[] handles, uint count, IntPtr start, IntPtr end);
        [DllImport("advapi32.dll")] static extern uint CloseTrace(ulong handle);
        [DllImport("tdh.dll")] static extern uint TdhGetEventInformation(IntPtr record, uint count, IntPtr context, IntPtr info, ref uint size);
        [DllImport("tdh.dll")] static extern uint TdhGetPropertySize(IntPtr record, uint count, IntPtr context, uint descriptorCount, [In] PropertyDescriptor[] descriptors, out uint size);
        [DllImport("tdh.dll")] static extern uint TdhGetProperty(IntPtr record, uint count, IntPtr context, uint descriptorCount, [In] PropertyDescriptor[] descriptors, uint size, [Out] byte[] data);

        const int MaxRecordBytes = 524288;
        const int MaxMetadataBytes = 1048576;
        readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength=MaxRecordBytes, RecursionLimit=20 };
        readonly SHA256 hasher = SHA256.Create();
        readonly Dictionary<string, Queue<long>> rawTimes = new Dictionary<string, Queue<long>>();
        readonly UTF8Encoding utf8 = new UTF8Encoding(false);
        readonly HashSet<uint> selectedPids = new HashSet<uint>();
        readonly HashSet<long> selectedTimes = new HashSet<long>();
        const int MaxScanEvents = 4000000;
        const int MaxSelectedTimestamps = 250000;
        int convertedSeen, backgroundKept, omittedBackground, selectedKept;
        int cap, seen, rawSeen, fieldErrors, missingSchemas, omittedFields, callbackErrors, timestampGaps;
        long byteCap, bytes;
        bool rawPass, halted, truncated, headerAvailable;
        string callbackError;
        LogFile header;
        StreamWriter writer;
        EventCallback eventCallback;
        BufferCallback bufferCallback;
        static readonly Guid PerfInfo = new Guid("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc");
        static readonly Guid StackWalk = new Guid("def2fe46-7bd6-4b80-bd94-f57fe20d0ce3");

        byte[] Payload(Record r) {
            byte[] value = new byte[r.UserLength];
            if (value.Length != 0) {
                if (r.UserData == IntPtr.Zero) throw new InvalidDataException("Null ETW payload pointer");
                Marshal.Copy(r.UserData, value, 0, value.Length);
            }
            return value;
        }
        string Fingerprint(Record r, byte[] payload) {
            // Matching both native headers and payload SHA-256 between raw and FILETIME
            // passes retains exact QPC timestamps without inventing a UTC conversion.
            return r.Provider.ToString("D") + ":" + r.Id + ":" + r.Version + ":" + r.Opcode + ":" + r.Task + ":" +
                r.Keywords + ":" + r.Flags + ":" + r.Pid + ":" + r.Tid + ":" + r.Activity.ToString("D") + ":" +
                r.Processor + ":" + Convert.ToBase64String(hasher.ComputeHash(payload));
        }
        string InfoString(IntPtr info, uint size, int offsetField) {
            uint offset = unchecked((uint)Marshal.ReadInt32(info, offsetField));
            if (offset == 0 || (offset & 1) != 0 || offset >= size) return "";
            int n = 0;
            int max = (int)Math.Min((size - offset) / 2, 4096);
            while (n < max && Marshal.ReadInt16(info, (int)offset + n * 2) != 0) n++;
            return Marshal.PtrToStringUni(IntPtr.Add(info, (int)offset), n) ?? "";
        }
        object Value(byte[] data, ushort type) {
            // Only exact TDH types are converted. Unknown binary/struct/array remains raw.
            if (type == 1) return Encoding.Unicode.GetString(data).TrimEnd('\0');
            if (type == 2) return Encoding.GetEncoding(1252).GetString(data).TrimEnd('\0');
            if (type == 3 && data.Length == 1) return (int)(sbyte)data[0];
            if (type == 4 && data.Length == 1) return (int)data[0];
            if (type == 5 && data.Length == 2) return BitConverter.ToInt16(data, 0);
            if (type == 6 && data.Length == 2) return BitConverter.ToUInt16(data, 0);
            if (type == 7 && data.Length == 4) return BitConverter.ToInt32(data, 0);
            if (type == 8 && data.Length == 4) return BitConverter.ToUInt32(data, 0);
            if (type == 9 && data.Length == 8) return BitConverter.ToInt64(data, 0).ToString(CultureInfo.InvariantCulture);
            if (type == 10 && data.Length == 8) return BitConverter.ToUInt64(data, 0).ToString(CultureInfo.InvariantCulture);
            if (type == 15 && data.Length == 16) return new Guid(data).ToString("D");
            if ((type == 16 || type == 20 || type == 21) && (data.Length == 4 || data.Length == 8))
                return "0x" + (data.Length == 8 ? BitConverter.ToUInt64(data,0) : BitConverter.ToUInt32(data,0)).ToString("x");
            return new Dictionary<string,object> { {"tdh_in_type",type}, {"bytes",data.Length}, {"base64",Convert.ToBase64String(data)} };
        }
        Dictionary<string,object> Tdh(IntPtr ptr, Dictionary<string,object> output) {
            Dictionary<string,object> values = new Dictionary<string,object>();
            uint size = 0;
            uint code = TdhGetEventInformation(ptr, 0, IntPtr.Zero, IntPtr.Zero, ref size);
            if (code != 122 || size < 112 || size > MaxMetadataBytes) {
                missingSchemas++; output["tdh_status"] = code; return values;
            }
            IntPtr info = Marshal.AllocHGlobal((int)size);
            try {
                code = TdhGetEventInformation(ptr, 0, IntPtr.Zero, info, ref size);
                output["tdh_status"] = code;
                if (code != 0) { missingSchemas++; return values; }
                output["provider_name"] = InfoString(info,size,52);
                output["task_name"] = InfoString(info,size,68);
                output["opcode_name"] = InfoString(info,size,72);
                output["tdh_decoding_source"] = Marshal.ReadInt32(info,48);
                uint total = unchecked((uint)Marshal.ReadInt32(info,100));
                uint top = unchecked((uint)Marshal.ReadInt32(info,104));
                if (total > 1024 || top > total || 112L + total * 24L > size) {
                    fieldErrors++; output["fields_partial"] = true; return values;
                }
                for (int i=0; i<Math.Min(top,64); i++) {
                    int pos = 112 + i*24;
                    uint flags = unchecked((uint)Marshal.ReadInt32(info,pos));
                    string name = InfoString(info,size,pos+4);
                    ushort type = unchecked((ushort)Marshal.ReadInt16(info,pos+8));
                    ushort count = unchecked((ushort)Marshal.ReadInt16(info,pos+16));
                    if (name.Length == 0 || (flags & (1U|4U|32U|128U)) != 0 || count > 1) {
                        omittedFields++; output["fields_partial"] = true; continue;
                    }
                    uint nameOffset = unchecked((uint)Marshal.ReadInt32(info,pos+4));
                    PropertyDescriptor[] descriptors = {new PropertyDescriptor {
                        Name=unchecked((ulong)IntPtr.Add(info,(int)nameOffset).ToInt64()), ArrayIndex=uint.MaxValue }};
                    uint len;
                    code = TdhGetPropertySize(ptr,0,IntPtr.Zero,1,descriptors,out len);
                    if (code != 0 || len > 32768) { fieldErrors++; output["fields_partial"] = true; continue; }
                    byte[] data = new byte[len];
                    code = TdhGetProperty(ptr,0,IntPtr.Zero,1,descriptors,len,data);
                    if (code != 0) { fieldErrors++; output["fields_partial"] = true; continue; }
                    values[name] = Value(data,type);
                }
                if (top > 64) { omittedFields++; output["fields_partial"] = true; }
                return values;
            } finally { Marshal.FreeHGlobal(info); }
        }
        int PointerSize(Record r) {
            if ((r.Flags & 0x20) != 0) return 4;
            if ((r.Flags & 0x40) != 0) return 8;
            return header.PointerSize == 4 ? 4 : header.PointerSize == 8 ? 8 : 0;
        }
        static string Address(byte[] payload, int offset, int width) {
            return "0x" + (width == 8 ? BitConverter.ToUInt64(payload,offset) : BitConverter.ToUInt32(payload,offset)).ToString("x");
        }
        void Classic(Record r, byte[] payload, Dictionary<string,object> values, Dictionary<string,object> output) {
            int width = PointerSize(r);
            output["pointer_size"] = width;
            // These provider/opcode/payload combinations are documented Microsoft MOF,
            // not user-mode Nt* hooks. Names come only from MOF/TDH, never address guesses.
            if (r.Provider == PerfInfo && r.Opcode == 51 && width != 0 && payload.Length == width) {
                values["SysCallAddress"] = Address(payload,0,width);
                output["event_name"] = "SysClEnter";
                output["decode_source"] = "microsoft_classic_mof";
            } else if (r.Provider == PerfInfo && r.Opcode == 52 && payload.Length == 4) {
                values["SysCallNtStatus"] = "0x" + BitConverter.ToUInt32(payload,0).ToString("x8");
                output["event_name"] = "SysClExit";
                output["decode_source"] = "microsoft_classic_mof";
            } else if (r.Provider == StackWalk && r.Opcode == 32 && width != 0 &&
                       payload.Length >= 16 && (payload.Length-16)%width == 0 && (payload.Length-16)/width <= 192) {
                values["EventTimeStamp"] = BitConverter.ToUInt64(payload,0).ToString(CultureInfo.InvariantCulture);
                values["StackProcess"] = BitConverter.ToUInt32(payload,8);
                values["StackThread"] = BitConverter.ToUInt32(payload,12);
                List<string> stack = new List<string>();
                for (int offset=16; offset<payload.Length; offset+=width) stack.Add(Address(payload,offset,width));
                values["Stack"] = stack;
                output["event_name"] = "Stack";
                output["decode_source"] = "microsoft_classic_mof";
            }
        }
        List<object> Extended(Record r, Dictionary<string,object> output) {
            List<object> result=new List<object>();
            int total=0;
            if (r.ExtendedCount>64 || (r.ExtendedCount>0 && r.ExtendedData==IntPtr.Zero)) {
                omittedFields++; output["extended_data_partial"]=true; return result;
            }
            for(int i=0; i<r.ExtendedCount; i++) {
                IntPtr item=IntPtr.Add(r.ExtendedData,i*16);
                ushort type=unchecked((ushort)Marshal.ReadInt16(item,2));
                ushort size=unchecked((ushort)Marshal.ReadInt16(item,6));
                long pointer=Marshal.ReadInt64(item,8);
                if (size>32768 || total+size>65536 || (size>0 && pointer==0)) {
                    omittedFields++; output["extended_data_partial"]=true; continue;
                }
                byte[] value=new byte[size];
                if(size>0) Marshal.Copy(new IntPtr(pointer),value,0,size);
                result.Add(new Dictionary<string,object> { {"type",type}, {"bytes",size},
                    {"base64",Convert.ToBase64String(value)} });
                total+=size;
            }
            return result;
        }
        void OnEvent(IntPtr ptr) {
            // No exception crosses the unmanaged callback boundary.
            try {
                if (halted) return;
                Record r = (Record)Marshal.PtrToStructure(ptr,typeof(Record));
                byte[] payload = Payload(r);
                string fingerprint = Fingerprint(r,payload);
                if (rawPass) {
                    if (rawSeen >= (selectedPids.Count == 0 ? cap : MaxScanEvents)) { halted=true; truncated=true; return; }
                    Queue<long> times;
                    if (!rawTimes.TryGetValue(fingerprint,out times)) {
                        times=new Queue<long>(); rawTimes.Add(fingerprint,times);
                    }
                    times.Enqueue(r.Timestamp); rawSeen++;
                    if (selectedPids.Count > 0 && r.Provider == StackWalk && r.Opcode == 32 &&
                        payload.Length >= 16 && selectedPids.Contains(BitConverter.ToUInt32(payload,8))) {
                        if (selectedTimes.Count >= MaxSelectedTimestamps) { halted=true; truncated=true; return; }
                        selectedTimes.Add(unchecked((long)BitConverter.ToUInt64(payload,0)));
                    }
                    return;
                }
                if (seen >= cap) { halted=true; truncated=true; return; }
                if (convertedSeen++ >= MaxScanEvents) { halted=true; truncated=true; return; }
                Queue<long> raw;
                long? original=null;
                if (rawTimes.TryGetValue(fingerprint,out raw) && raw.Count > 0) original=raw.Dequeue();
                bool selected=selectedPids.Contains(r.Pid) ||
                    (r.Provider == StackWalk && r.Opcode == 32 && payload.Length >= 16 &&
                     selectedPids.Contains(BitConverter.ToUInt32(payload,8))) ||
                    (original.HasValue && selectedTimes.Contains(original.Value));
                if (selectedPids.Count > 0 && !selected && backgroundKept >= Math.Min(10000,cap/5)) {
                    omittedBackground++; return;
                }
                Dictionary<string,object> output = new Dictionary<string,object> {
                    {"schema","sandbox.kernel.record.v1"}, {"source","kernel_etw"},
                    {"provider_guid",r.Provider.ToString("D")}, {"event_id",r.Id}, {"version",r.Version},
                    {"opcode",r.Opcode}, {"task",r.Task}, {"keywords",r.Keywords.ToString(CultureInfo.InvariantCulture)},
                    {"header_flags",r.Flags}, {"header_pid",r.Pid}, {"header_tid",r.Tid},
                    {"processor",r.Processor}, {"activity_id",r.Activity.ToString("D")},
                    {"timestamp_filetime",r.Timestamp.ToString(CultureInfo.InvariantCulture)},
                    {"payload_base64",Convert.ToBase64String(payload)}, {"payload_bytes",payload.Length}
                };
                try { output["time"] = DateTime.FromFileTimeUtc(r.Timestamp).ToString("o",CultureInfo.InvariantCulture); }
                catch { timestampGaps++; output["time"] = null; }
                if (original.HasValue) {
                    output["timestamp_raw"] = original.Value.ToString(CultureInfo.InvariantCulture);
                    output["timestamp_raw_basis"] = "ProcessTrace_raw_header_payload_sha256_matched";
                } else { timestampGaps++; output["timestamp_raw"] = null; }
                output["index_selection"] = selectedPids.Count == 0 ? "bounded_chronology" : selected ? "pid_or_exact_stack_timestamp_candidate_not_attribution" : "bounded_background_context";
                Dictionary<string,object> values = Tdh(ptr,output);
                Classic(r,payload,values,output);
                output["data"] = values;
                output["extended_data"] = Extended(r,output);
                string line = json.Serialize(output);
                int n = utf8.GetByteCount(line)+1;
                if (n > MaxRecordBytes || bytes+n > byteCap) { halted=true; truncated=true; return; }
                writer.Write(line); writer.Write('\n'); bytes+=n; seen++;
                if (selected) selectedKept++; else backgroundKept++;
            } catch (Exception e) {
                callbackErrors++; callbackError=e.GetType().Name+": "+e.Message;
                // Stop on decoder failure; the ETL is never changed/deleted.
                halted=true;
            }
        }
        uint OnBuffer(IntPtr ptr) { return halted ? 0U : 1U; }
        uint Pass(string etl, bool raw) {
            rawPass=raw; halted=false;
            IntPtr name=Marshal.StringToHGlobalUni(etl);
            ulong handle=ulong.MaxValue;
            try {
                LogFile logfile=new LogFile { FileName=name, Mode=0x10000000U | (raw ? 0x1000U : 0U),
                    EventCallback=Marshal.GetFunctionPointerForDelegate(eventCallback),
                    BufferCallback=Marshal.GetFunctionPointerForDelegate(bufferCallback) };
                handle=OpenTraceW(ref logfile);
                if (handle == ulong.MaxValue) {
                    int nativeError=Marshal.GetLastWin32Error();
                    throw new System.ComponentModel.Win32Exception(nativeError,"OpenTraceW error "+nativeError);
                }
                header=logfile;
                headerAvailable=true;
                uint code=ProcessTrace(new ulong[] {handle},1,IntPtr.Zero,IntPtr.Zero);
                // ERROR_CANCELLED (1223) is expected for an intentional bounded decode.
                if (code != 0 && !(code == 1223 && halted))
                    throw new System.ComponentModel.Win32Exception((int)code,"ProcessTrace error "+code);
                return code;
            } finally {
                if (handle != ulong.MaxValue) CloseTrace(handle);
                Marshal.FreeHGlobal(name);
                GC.KeepAlive(eventCallback); GC.KeepAlive(bufferCallback);
            }
        }
        public static string Export(string etl, string output, int maxEvents, long maxBytes) {
            return Export(etl,output,maxEvents,maxBytes,new uint[0]);
        }
        public static string Export(string etl, string output, int maxEvents, long maxBytes, uint[] selected) {
            if (IntPtr.Size != 8) throw new PlatformNotSupportedException("Decoder requires Windows x64");
            if (maxEvents < 1 || maxEvents > 100000 || maxBytes < 1 || maxBytes > 134217728)
                throw new ArgumentOutOfRangeException("Decode caps exceed safe ceiling");
            Decoder d=new Decoder { cap=maxEvents, byteCap=maxBytes };
            if (selected != null && selected.Length > 256) throw new ArgumentOutOfRangeException("PID selection cap");
            if (selected != null) foreach(uint pid in selected) if(pid != 0 && pid != uint.MaxValue) d.selectedPids.Add(pid);
            if (new FileInfo(etl).Length > 268435456L) throw new InvalidDataException("ETL exceeds 256 MiB");
            d.eventCallback=d.OnEvent; d.bufferCallback=d.OnBuffer;
            string error=null;
            uint rawCode=0,code=0;
            DateTime start=DateTime.UtcNow;
            try {
                rawCode=d.Pass(Path.GetFullPath(etl),true);
                using (d.writer=new StreamWriter(output,false,d.utf8,65536)) {
                    if (d.callbackErrors == 0) code=d.Pass(Path.GetFullPath(etl),false);
                }
            } catch (Exception e) { error=e.GetType().Name+": "+e.Message; }
            finally { d.hasher.Dispose(); }
            bool partial=d.truncated || d.callbackErrors>0 || d.missingSchemas>0 || d.fieldErrors>0 ||
                d.omittedFields>0 || d.timestampGaps>0 || d.omittedBackground>0 ||
                d.header.EventsLost>0 || d.header.BuffersLost>0 || error!=null;
            Dictionary<string,object> receipt=new Dictionary<string,object> {
                {"schema","sandbox.kernel.decode.v1"}, {"status",d.seen==0 ? "unavailable" : partial ? "partial" : "completed"},
                {"decoder","Windows ProcessTrace + TDH + documented classic MOF"},
                {"native_api",new string[] {"OpenTraceW", "ProcessTrace", "TdhGetEventInformation", "TdhGetPropertySize", "TdhGetProperty", "CloseTrace"}},
                {"etl",Path.GetFileName(etl)}, {"artifact",Path.GetFileName(output)}, {"etl_retained",File.Exists(etl)},
                {"started_utc",start.ToString("o")}, {"finished_utc",DateTime.UtcNow.ToString("o")},
                {"events",d.seen}, {"bytes",d.bytes}, {"max_events",maxEvents}, {"max_bytes",maxBytes},
                {"truncated",d.truncated}, {"raw_timestamp_records",d.rawSeen},
                {"scan_event_cap",MaxScanEvents}, {"converted_records_scanned",d.convertedSeen},
                {"index_selection",d.selectedPids.Count==0 ? "bounded_chronology" : "pid_and_exact_stack_timestamp_priority_not_attribution"},
                {"selection_pids",new List<uint>(d.selectedPids)}, {"selected_candidates",d.selectedKept},
                {"background_kept",d.backgroundKept}, {"omitted_background_records",d.omittedBackground},
                {"selection_timestamp_cap",MaxSelectedTimestamps},
                {"raw_process_trace_status",rawCode}, {"process_trace_status",code},
                {"missing_schemas",d.missingSchemas}, {"field_errors",d.fieldErrors}, {"omitted_fields",d.omittedFields},
                {"callback_errors",d.callbackErrors}, {"timestamp_gaps",d.timestampGaps},
                {"error",error ?? d.callbackError}, {"pointer_size",d.header.PointerSize},
                {"clock_type",d.header.ClockType}, {"perf_frequency",d.header.PerfFreq.ToString(CultureInfo.InvariantCulture)},
                {"loss",new Dictionary<string,object> { {"events_lost",d.headerAvailable ? (object)d.header.EventsLost : null},
                    {"buffers_lost",d.headerAvailable ? (object)d.header.BuffersLost : null},
                    {"counter_source",d.headerAvailable ? "OpenTraceW.TRACE_LOGFILE_HEADER" : "unknown"} }},
                {"full_coverage",false}, {"symbol_resolution","raw_addresses_only"}
            };
            return d.json.Serialize(receipt);
        }
    }
}
