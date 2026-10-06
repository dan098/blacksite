# Innocuous laboratory fixture. Changes exist only in the disposable analysis VM.
$ErrorActionPreference = 'Continue'
Start-Sleep -Seconds 2
$key = 'HKCU:\Software\SandboxLabProbe'
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name Evidence -Value 'benign-registry-probe'
$desktop = [Environment]::GetFolderPath('Desktop')
Set-Content -LiteralPath (Join-Path $desktop 'sandbox-probe.txt') -Value 'benign-filesystem-probe'
Start-Process -FilePath "$env:WINDIR\System32\cmd.exe" -ArgumentList '/d /c echo benign-child-process> "%TEMP%\sandbox-child.txt"' -Wait
try { Invoke-WebRequest -Uri 'http://10.0.2.100/benign-probe' -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {}
try { Resolve-DnsName 'sandbox-probe.invalid' -QuickTimeout -ErrorAction Stop | Out-Null } catch {}
Start-Sleep -Seconds 3
