import "pe"
import "math"

rule Lab_ProcessInjection_APIs : heuristic injection T1055
{
    meta:
        label = "API compatibili con iniezione di processo"
        severity = "medium"
        confidence = "heuristic"
        explanation = "Combinazione allocazione remota, scrittura e avvio remoto; può essere usata da software legittimo."
        technique = "T1055"
    strings:
        $alloc = "VirtualAllocEx" ascii wide fullword
        $write = "WriteProcessMemory" ascii wide fullword
        $thread1 = "CreateRemoteThread" ascii wide fullword
        $thread2 = "NtCreateThreadEx" ascii wide fullword
        $thread3 = "QueueUserAPC" ascii wide fullword
    condition:
        filesize <= 100MB and $alloc and $write and 1 of ($thread*)
}

rule Lab_EncodedPowerShell_Download : heuristic script T1059_001
{
    meta:
        label = "PowerShell codificato con indicatori di download"
        severity = "medium"
        confidence = "heuristic"
        explanation = "Stringhe PowerShell, codifica e download presenti insieme; nessun comando viene eseguito."
        technique = "T1059.001"
    strings:
        $ps = "powershell" ascii wide nocase
        $enc1 = "-encodedcommand" ascii wide nocase
        $enc2 = "FromBase64String" ascii wide nocase
        $enc3 = " -enc " ascii wide nocase
        $get1 = "DownloadString" ascii wide nocase
        $get2 = "DownloadFile" ascii wide nocase
        $get3 = "Invoke-WebRequest" ascii wide nocase
    condition:
        filesize <= 100MB and $ps and 1 of ($enc*) and 1 of ($get*)
}

rule Lab_CredentialDump_Indicators : heuristic credentials T1003_001
{
    meta:
        label = "Indicatori di accesso a credenziali LSASS"
        severity = "high"
        confidence = "heuristic"
        explanation = "Riferimento a LSASS con API di dump o stringhe di strumenti; presenza non dimostra esfiltrazione."
        technique = "T1003.001"
    strings:
        $target = "lsass.exe" ascii wide nocase
        $dump1 = "MiniDumpWriteDump" ascii wide fullword
        $dump2 = "comsvcs.dll" ascii wide nocase
        $dump3 = "sekurlsa::" ascii wide nocase
    condition:
        filesize <= 100MB and $target and 1 of ($dump*)
}

rule Lab_RecoveryDestruction_Encryption : heuristic ransomware T1490
{
    meta:
        label = "Cifratura e rimozione di opzioni di ripristino"
        severity = "high"
        confidence = "heuristic"
        explanation = "API di cifratura insieme a comandi di rimozione backup; richiede conferma dinamica."
        technique = "T1490"
    strings:
        $crypt1 = "CryptEncrypt" ascii wide fullword
        $crypt2 = "BCryptEncrypt" ascii wide fullword
        $recover1 = "vssadmin delete shadows" ascii wide nocase
        $recover2 = "wbadmin delete catalog" ascii wide nocase
        $recover3 = "recoveryenabled no" ascii wide nocase
    condition:
        filesize <= 100MB and 1 of ($crypt*) and 1 of ($recover*)
}

rule Lab_SecurityTampering_Strings : heuristic defense_evasion T1562_001
{
    meta:
        label = "Stringhe compatibili con alterazione della protezione"
        severity = "medium"
        confidence = "heuristic"
        explanation = "Indicatori testuali di alterazione Defender; il laboratorio non modifica né disabilita la protezione."
        technique = "T1562.001"
    strings:
        $command = "Set-MpPreference" ascii wide nocase
        $setting1 = "DisableRealtimeMonitoring" ascii wide nocase
        $setting2 = "DisableBehaviorMonitoring" ascii wide nocase
        $setting3 = "ExclusionPath" ascii wide nocase
    condition:
        filesize <= 100MB and $command and 1 of ($setting*)
}

rule Lab_Driver_SensitiveMemoryAPIs : heuristic driver byovd
{
    meta:
        label = "Driver con API di accesso a memoria sensibile"
        severity = "medium"
        confidence = "heuristic"
        explanation = "Importazioni kernel e API sensibili; non dimostra vulnerabilità, exploit IOCTL o BYOVD osservato."
    condition:
        filesize <= 100MB and uint16(0) == 0x5a4d and pe.is_pe and
        (pe.imports("ntoskrnl.exe", "IoCreateDevice") or pe.imports("ntoskrnl.exe", "IoCreateSymbolicLink")) and
        (pe.imports("ntoskrnl.exe", "MmMapIoSpace") or pe.imports("ntoskrnl.exe", "MmCopyMemory") or pe.imports("ntoskrnl.exe", "ZwTerminateProcess"))
}

rule Lab_PE_HighEntropyExecutableSection : heuristic packing
{
    meta:
        label = "Sezione PE eseguibile ad alta entropia"
        severity = "low"
        confidence = "heuristic"
        explanation = "Possibile packing, compressione o cifratura; frequente anche in programmi legittimi."
    condition:
        filesize <= 100MB and uint16(0) == 0x5a4d and pe.is_pe and pe.number_of_sections > 0 and pe.number_of_sections <= 96 and
        for any i in (0 .. pe.number_of_sections - 1):
            (pe.sections[i].raw_data_size >= 4096 and
             pe.sections[i].raw_data_offset < filesize and
             pe.sections[i].raw_data_size <= filesize - pe.sections[i].raw_data_offset and
             pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE and
             math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 7.3)
}

rule Lab_PE_WritableExecutableSection : heuristic memory_permissions
{
    meta:
        label = "Sezione PE scrivibile ed eseguibile"
        severity = "low"
        confidence = "heuristic"
        explanation = "Permessi RWX: indicatore strutturale, non verdetto di malware."
    condition:
        filesize <= 100MB and uint16(0) == 0x5a4d and pe.is_pe and pe.number_of_sections > 0 and pe.number_of_sections <= 96 and
        for any i in (0 .. pe.number_of_sections - 1):
            (pe.sections[i].characteristics & pe.SECTION_MEM_WRITE and
             pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE)
}

rule Lab_AutorunRegistry_APIs : heuristic persistence T1547_001
{
    meta:
        label = "Chiave di avvio automatico e API registro"
        severity = "medium"
        confidence = "heuristic"
        explanation = "Possibile persistenza Run/RunOnce; anche gli installer legittimi usano queste chiavi."
        technique = "T1547.001"
    strings:
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $api1 = "RegSetValueExA" ascii wide fullword
        $api2 = "RegSetValueExW" ascii wide fullword
        $api3 = "New-ItemProperty" ascii wide nocase
    condition:
        filesize <= 100MB and 1 of ($run*) and 1 of ($api*)
}

rule Lab_EICAR_TestMarker : test benign_test_signal
{
    meta:
        label = "Marcatore di test antivirus EICAR"
        severity = "test"
        confidence = "test_marker"
        explanation = "Segnale di test standard, non campione malware e non dimostrazione di copertura del motore."
        test_signal = true
    strings:
        $marker = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        filesize <= 1MB and $marker
}
