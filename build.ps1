#!/usr/bin/env pwsh

#Requires -Version 7.4

# 1.1.0 Added Compress-PSResource
#Requires -Modules @{ ModuleName = "Microsoft.PowerShell.PSResourceGet"; ModuleVersion = "1.1.0" }

using namespace System.IO

<#
.SYNOPSIS
Builds a NuGet package (.nupkg) for the PublishTest module.

.DESCRIPTION
Creates a NuGet package by using a temporary local PSRepository.

.PARAMETER OutputPath
The directory where the .nupkg file will be created.
Defaults to './output'

.EXAMPLE
./build.ps1
Creates a nupkg with the current module version.
#>

[OutputType([string])]
[CmdletBinding()]
param(
    [Parameter()]
    [string]
    $OutputPath = './output'
)

$ErrorActionPreference = 'Stop'

$modulePath = [Path]::Combine($PSScriptRoot, 'PublishTest')
$manifest = Test-ModuleManifest -Path ([Path]::Combine($modulePath, 'PublishTest.psd1'))

$outputDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if (Test-Path -LiteralPath $outputDir) {
    Write-Host "Removing existing output directory '$outputDir'" -ForegroundColor Cyan
    Remove-Item -LiteralPath $outputDir -Force -Recurse
}
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

Write-Host "Publishing module nupkg to output repository..." -ForegroundColor Cyan
Compress-PSResource -Path $modulePath -DestinationPath $outputDir -SkipModuleManifestValidate

$nupkgPath = [Path]::Combine($outputDir, "PublishTest.$($manifest.Version).nupkg")
Write-Host "Successfully created; $nupkgPath" -ForegroundColor Green

$nupkgPath
