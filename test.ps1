#!/usr/bin/env pwsh

#Requires -Version 7.4

<#
.SYNOPSIS
Tests the PublishTest module.
#>

using namespace System.IO

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

Write-Host "Testing PublishTest module..." -ForegroundColor Cyan

# Import the module
$modulePath = [Path]::Combine($PSScriptRoot, 'PublishTest', 'PublishTest.psd1')
Import-Module -Name $modulePath -Force

# Test the function
$result = Get-PublishTest
Write-Host "Test result: $result" -ForegroundColor Green

if ($result -ne "This is a test value from PublishTest module") {
    throw "Module test failed - unexpected result: $result"
}

Write-Host "Module test completed successfully!" -ForegroundColor Green
