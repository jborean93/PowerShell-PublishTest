@{
    RootModule = 'PublishTest.psm1'
    ModuleVersion = '0.1.2'
    GUID = 'c22c1b76-54fe-4e55-a0df-a5a9e2766af7'
    Author = 'Jordan Borean'
    CompanyName = 'Community'
    Copyright = '(c) 2026. All rights reserved.'
    Description = 'A simple test module for publishing to OCI and Azure Artifacts'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-PublishTest')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Test', 'Publishing')
            LicenseUri = 'https://github.com/jborean93/PowerShell-PublishTest/LICENSE'
            ProjectUri = 'https://github.com/jborean93/PowerShell-PublishTest'
            ReleaseNotes = 'Release notes here'
        }
        # Used in OCI image anotations
        SPDXLicense = 'MIT'
    }
}
