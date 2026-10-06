[CmdletBinding()]
param(
    [string]$ToolDir = 'C:\Sandbox\tools',
    [switch]$InstallPython,
    [switch]$InstallFrida
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'setup.ps1') @PSBoundParameters
exit $LASTEXITCODE
