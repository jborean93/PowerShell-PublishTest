# PowerShell Module Publishing Test

[![GitHub Actions Status](https://github.com/jborean93/PowerShell-PublishTest/actions/workflows/publish.yml/badge.svg)](https://github.com/jborean93/PowerShell-PublishTest/actions/workflows/publish.yml)
[![Azure Pipelines Status](https://dev.azure.com/jborean93/PowerShell-PublishTest/_apis/build/status%2Fjborean93.PowerShell-PublishTest?branchName=main)](https://dev.azure.com/jborean93/PowerShell-PublishTest/_build/latest?definitionId=8&branchName=main)


This repository demonstrates and tests publishing a PowerShell module to multiple package repositories using CI/CD pipelines.

## What This Tests

This project validates the complete workflow for publishing PowerShell modules to different package registries:

| Registry Type | CI Platform | Easy to Publish | Easy to Install | Anonymous Access |
|--------------|-------------|-----------------|-----------------|------------------|
| GitHub Nuget | GitHub Actions | ✅ Built-in `dotnet nuget push` | ✅ PSResourceGet | ❌ Requires GitHub PAT¹ |
| GitHub OCI | GitHub Actions | ❌ Custom script required² | ❌ PSResourceGet bugs³ | ✅ Yes |
| Azure Artifacts | Azure Pipelines | ✅ Built-in `DotNetCoreCLI` task | ✅ PSResourceGet | ✅ Yes |

**Footnotes:**
1. GitHub Nuget requires authentication even for public packages - a GitHub Personal Access Token with `read:packages` scope is needed
2. GitHub OCI requires a custom `publish_oci.ps1` script due to PSResourceGet's Azure-specific OCI implementation
3. PSResourceGet has bugs preventing installation from GitHub OCI (token exchange and package prefix issues)

## Requirements

- **PowerShell 7.4+**
- **Microsoft.PowerShell.PSResourceGet 1.1.1+** - Used to create the module nupkg and publish to certain repositories

## The Module

The `PublishTest` module is a minimal PowerShell module containing a single function `Get-PublishTest` that returns a stub value. It's intentionally simple to focus on the publishing pipeline rather than module functionality.

## Publishing Workflow

Both pipelines use reusable PowerShell scripts:

- **`test.ps1`** - Tests the module by importing it and validating the output
- **`build.ps1`** - Creates a .nupkg file using PSResourceGet
- **`publish_oci.ps1`** - Publishes a .nupkg to an OCI registry using direct HTTP API calls

### GitHub Actions Pipeline

The GitHub Actions workflow (`.github/workflows/publish.yml`) has two jobs:

1. **test_build** (no special permissions)
    - Runs on all pushes and PRs
    - Executes `test.ps1` to validate the module
    - Executes `build.ps1` to create the .nupkg
    - Uploads the .nupkg as an artifact

2. **publish** (requires `contents: write` and `packages: write`)
    - Only runs on release events (when a release is published with a tag `v*`)
    - Uploads the .nupkg to the GitHub release asset
    - Publishes to GitHub Nuget Registry using `dotnet nuget push`
    - Publishes to GitHub Container Registry (OCI) using custom `publish_oci.ps1` script

### Azure Pipelines Workflow

The Azure Pipelines workflow (`azure-pipelines.yml`) has two stages:

1. **TestBuild**
    - Runs on all pushes to main, PRs, and tag pushes
    - Executes `test.ps1` to validate the module
    - Executes `build.ps1` to create the .nupkg
    - Uploads the .nupkg as a pipeline artifact

2. **Publish**
    - Runs publishing step only when `v*` tag is set
    - Sets up Nuget authentication
    - Uses `DotNetCoreCLI` to push the nupkg to the Azure Artifacts feed

## Installation Details

### GitHub Nuget Registry

```powershell
# The GitHub user/namespace the feed is registered under
$feedOwner = 'jborean93'

# The PAT must be a classic token with the 'read:packages' scope
$cred = Get-Credential -Message "Enter your GitHub username and PAT"

$repoParams = @{
    Name = 'GitHubNuget'
    Uri = "https://nuget.pkg.github.com/$feedOwner/index.json"
}
Register-PSResourceRepository @repoParams

Install-PSResource -Name PublishTest -Repository GitHubNuget -Credential $cred -TrustRepository
```

### GitHub Container Registry (OCI)

This is not possible due to bugs in PSResourceGet, it should be possible to do the following but it fails:

```powershell
Register-PSResourceRepository -Name GHCR -Uri https://ghcr.io/ -ApiVersion ContainerRegistry
Install-PSResource -Name jborean93/publishtest -Repository GHCR -TrustRepository
```

There are two issues that stop this from working.

+ The anonymous token logic is designed only for Azure rather than the OCI specifications
+ Packages under a prefix (like GitHub OCI packages) fail during the download due to incorrect logic in PSResourceGet.

Using [PSNetDetour](https://github.com/jborean93/PSNetDetour) we can hack in a fix to `PSResourceGet` but this is not recommended at all and will most likely fail on newer PSResourceGet versions as internal methods are changed.

```powershell
Import-Module ./Oci.psm1

Function Install-GhcrResource {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name
    )

    $ErrorActionPreference = 'Stop'

    $Name = $Name.ToLowerInvariant()
    $packagePrefix, $packageName = $Name -split '/', 2

    $psGetCmd = Get-Command -Name Install-PSResource -Module Microsoft.PowerShell.PSResourceGet
    $psGetType = $psGetCmd.ImplementingType.Assembly.GetType(
        'Microsoft.PowerShell.PSResourceGet.ContainerRegistryServerAPICalls')

    $getRegistryTokenMeth = $psGetType.GetMethod(
        'GetContainerRegistryAccessToken',
        [Reflection.BindingFlags]'Instance, NonPublic',
        [type[]]@([System.Management.Automation.ErrorRecord].MakeByRefType()))

    $prependPrefixMeth = $psGetType.GetMethod(
        'PrependMARPrefix',
        [Reflection.BindingFlags]'Instance, NonPublic',
        [type[]]@([string]))

    if (-not ($getRegistryTokenMeth -and $prependPrefixMeth)) {
        throw "Hook is only designed for PSResourceGet 1.1.1, internal methods have probably changed"
    }

    Use-NetDetourContext {
        # Updates the logic to retrieve the anonymous token to work with any OCI
        # compliant registry.
        New-NetDetourHook -Method $getRegistryTokenMeth -Hook {
            param ([ref]$ErrorRecord)

            try {
                # In Oci.psm1
                Get-OciBearerToken -Registry $Detour.Instance.Registry -PackageName $Detour.State.Name
            }
            catch {
                $_.ErrorDetails = "Failed to retrieve anonymous token: $_"
                $ErrorRecord.Value = $_
            }
        } -State @{ Name = $Name }

        # PSResourceGet is able to find the package metadata if you specify the
        # prefix under -Name like '-Name jborean93/publishtest' but unfortunately
        # it uses 'org.opencontainers.image.title' under the first layer
        # annotations to update the package name used internally. This causes the
        # next step to download the package layers to fail as it no longer has the
        # prefix when calling the REST APIs.
        New-NetDetourHook -Method $prependPrefixMeth -Hook {
            param ($packageName)

            "$($Detour.State.Prefix)/$packageName"
        } -State @{ Prefix = $packagePrefix }

        Install-PSResource -Name $packageName -Repository GHCR -TrustRepository
    }
}

$repoParams = @{
    Name = 'GHCR'
    Uri = 'https://ghcr.io/'
    ApiVersion = 'ContainerRegistry'
}
Register-PSResourceRepository @repoParams

Install-GhcrResource -Name jborean93/PublishTest
```

### Azure Artifacts

```powershell
# Feeds can be org scoped, the project is omitted from the Uri in that case.

$org = 'jborean93'  # The Azure DevOps Organisation
$project = 'PowerShell-PublishTest'  # The Azure DevOps Project
$feed = 'NugetTest'  # The name of the Azure Artifacts feed

$repoParams = @{
    Name = 'AzureArtifacts'
    Uri  = "https://pkgs.dev.azure.com/$org/$project/_packaging/$feed/nuget/v3/index.json"
}
Register-PSResourceRepository @repoParams

Install-PSResource -Name PublishTest -Repository AzureArtifacts -TrustRepository
```
