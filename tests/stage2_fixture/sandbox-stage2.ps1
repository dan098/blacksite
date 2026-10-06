$ErrorActionPreference = 'Stop'
Start-Sleep -Seconds 1
$key = 'HKCU:\Software\SandboxLabStage2'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name DownloadedStage -Value 'authored benign Internet stage2 proof' -Force | Out-Null
$marker = Join-Path $env:USERPROFILE 'Desktop\sandbox-stage2-marker.txt'
[IO.File]::WriteAllText($marker, 'authored benign Internet stage2 proof')
Start-Process 'cmd.exe' -ArgumentList '/d /c echo benign-stage2-child>%TEMP%\sandbox-stage2-child.txt' -WindowStyle Hidden -Wait
# Keep harmless activity observable through the analysis window. Kernel ETW's
# bounded memory ring is explicitly tail evidence, not proof of earlier history.
$until = [DateTime]::UtcNow.AddSeconds(90)
while ([DateTime]::UtcNow -lt $until) {
    [IO.File]::WriteAllText($marker, 'authored benign Internet stage2 proof')
    Start-Sleep -Milliseconds 50
}
