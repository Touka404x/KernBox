#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [string]$Out = "dist",
    [string]$Version = "3.0.0-oss",
    [string[]]$Oems = @("hyperos", "aosp", "oplus", "oneui", "generic"),
    [string]$GoExe = "",
    [string]$JdkHome = "",
    [string]$AndroidSdkRoot = "",
    [string]$AndroidNdkHome = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $Py) { $Py = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
if (-not $Py) { throw "python / python3 not found in PATH." }

$argsList = @(
    (Join-Path $RepoRoot "tools\build_matrix.py"),
    "--out", $Out,
    "--version", $Version,
    "--oems"
) + $Oems

if ($GoExe -ne "") { $argsList += @("--go", $GoExe) }
if ($JdkHome -ne "") { $argsList += @("--jdk", $JdkHome) }
if ($AndroidSdkRoot -ne "") { $argsList += @("--sdk", $AndroidSdkRoot) }
if ($AndroidNdkHome -ne "") { $argsList += @("--ndk", $AndroidNdkHome) }

& $Py @argsList
exit $LASTEXITCODE
