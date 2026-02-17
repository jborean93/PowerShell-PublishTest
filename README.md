# PowerShell Module Publishing Test

This repository demonstrates and tests publishing a PowerShell module to multiple package repositories using CI/CD pipelines.

## What This Tests

This project validates the complete workflow for publishing PowerShell modules to different package registries using the modern **PSResourceGet** module:

1. **GitHub Container Registry (OCI)** - Publishing to GitHub's OCI registry using PSResourceGet and GitHub Actions
2. **Azure Artifacts** - Publishing to Azure DevOps Artifacts using PSResourceGet and Azure Pipelines
4. **Release Automation** - Automatically creating GitHub releases with .nupkg assets

## Requirements

- **PowerShell 7.4+**
- **Microsoft.PowerShell.PSResourceGet 1.1.1+** - The modern replacement for PowerShellGet with OCI support

## The Module

The `PublishTest` module is a minimal PowerShell module containing a single function `Get-PublishTest` that returns a stub value. It's intentionally simple to focus on the publishing pipeline rather than module functionality.

## Publishing Workflow

Both pipelines use reusable PowerShell scripts:

- **`test.ps1`** - Tests the module by importing it and validating the output
- **`build.ps1`** - Creates a .nupkg file using PSResourceGet

### GitHub Actions Pipeline

The GitHub Actions workflow (`.github/workflows/publish.yml`) has two jobs:

1. **test_build** (no special permissions)
   - Runs on all pushes and PRs
   - Executes `test.ps1` to validate the module
   - Executes `build.ps1` to create the .nupkg
   - Uploads the .nupkg as an artifact

2. **publish** (requires `contents: write` and `packages: write`)
   - Only runs on release events (when a release is published)
   - Downloads the .nupkg artifact
   - Uploads the .nupkg to the GitHub release
   - Publishes to GitHub Container Registry (OCI) at `https://ghcr.io/OWNER`
   - Uses PSResourceGet for OCI publishing

## Testing Locally

Run the test script:

```powershell
./test.ps1
```

Build a .nupkg locally:

```powershell
./build.ps1
# Output will be in ./output/PublishTest.VERSION.nupkg
```

Or import the module directly:

```powershell
Import-Module ./PublishTest/PublishTest.psd1
Get-PublishTest
```
