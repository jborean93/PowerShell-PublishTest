# Copyright: (c) 2026, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

#Requires -Version 7.4

using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.IO
using namespace System.IO.Compression
using namespace System.Management.Automation
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Text

Class NupkgMetadata {
    [OciLayer]$Layer
    [string]$ModuleName
    [string]$ModuleVersion
    [string]$Description
    [string]$Source
    [string]$License
}

Class OciLayer {
    [string]$MediaType
    [string]$Digest
    [long]$Size
    [IDictionary]$Annotations
}

Function Get-OciAccessToken {
    [OutputType([SecureString])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Registry,

        [Parameter(Mandatory)]
        [string]
        $PackageName,

        [Parameter(Mandatory)]
        [PSCredential]
        $Credential
    )

    try {
        $registryUri = "https://${Registry}/v2/"

        # We expect this to return 401 so we skip the status code.
        Write-Verbose -Message "Retrieving registry authentication information with GET => '$registryUri'"
        $registryInfo = Invoke-WebRequest -Uri $registryUri -Method GET -SkipHttpErrorCheck
        $bearerRealm = $registryInfo.Headers['WWW-Authenticate'] | Select-Object -First 1
        if (-not $bearerRealm) {
            throw "Failed to find OAuth bearer information from '$registryUri' - $($registryInfo.StatusCode) $($registryInfo.StatusDescription)"
        }

        Write-Verbose -Message "Parsing WWW-Authenticate bearer realm and service using '$bearerRealm'"
        if ($bearerRealm -match 'realm="([^"]+)"') {
            $realm = $matches[1]
        }
        else {
            throw "Could not extract realm from WWW-Authenticate header '$bearerRealm'"
        }

        if ($bearerRealm -match 'service="([^"]+)"') {
            $service = $matches[1]
        }
        else {
            throw "Could not extract service from WWW-Authenticate header '$bearerRealm'"
        }

        $tokenUri = "${realm}?service=${service}&scope=repository:${PackageName}:push,pull"

        Write-Verbose -Message "Retrieving access token for registry with GET => '$tokenUri'"
        $tokenResp = Invoke-WebRequest -Uri $tokenUri -Authentication Basic -Credential $Credential
        $tokenJson = $tokenResp.Content | ConvertFrom-Json

        ConvertTo-SecureString -AsPlainText -Force -String $tokenJson.token
    }
    catch {
        $PSCmdlet.WriteError($_)
    }
}

Function Get-NupkgMetadata {
    [OutputType([NupkgMetadata])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path
    )

    $nupkgStream = $nupkg = $psd1Stream = $null
    try {
        $nupkgStream = [File]::OpenRead($Path)
        $nupkgSize = $nupkgStream.Length

        $nupkg = [ZipArchive]::new($nupkgStream)

        $psd1Entry = $null
        $moduleName = $null
        foreach ($entry in $nupkg.Entries) {
            Write-Verbose -Message "Checking nupkg entry '$($entry.FullName)'"
            if ($entry.FullName -match "^([^/\\]*)\.psd1$") {
                $moduleName = $Matches[1]
                $psd1Entry = $entry
                break
            }
        }

        if (-not $psd1Entry) {
            throw  "Nupkg does not contain a root '*.psd1' file required to publish an OCI image."
        }

        $psd1Stream = $psd1Entry.Open()
        $psd1Content = [StreamReader]::new(
            $psd1Stream,
            [Encoding]::UTF8,
            <# detectEncodingFromByteOrderMarks #> $true,
            <# bufferSize #> 4096,
            <# leaveOpen #> $true).ReadToEnd()

        $psd1Script = [ScriptBlock]::Create($psd1Content)
        $psd1Script.CheckRestrictedLanguage(
            [string[]]@(),
            [string[]]@('PSEdition', 'PSScriptRoot'),
            $true)

        $metadata = $psd1Script.InvokeReturnAsIs()

        # PrivateData.PSData.Tags is 3 levels deep
        $metadataJson = $metadata | ConvertTo-Json -Depth 3
        Write-Verbose -Message "Nupkg metadata annotation is`n$metadataJson"

        $null = $nupkgStream.Seek(0, [SeekOrigin]::Begin)
        $sha256 = [SHA256]::Create()
        $digest = $sha256.ComputeHash($nupkgStream)
        $digestHash = [Convert]::ToHexString($digest).ToLowerInvariant()
        $sha256.Dispose()

        $layer = [OciLayer]@{
            MediaType = 'application/vnd.oci.image.layer.v1.tar+gzip'
            Digest = "sha256:$digestHash"
            Size = $nupkgSize
            Annotations = [Ordered]@{
                # These 4 annotations are expected in the nupkg layer.
                'org.opencontainers.image.title' = $moduleName
                'org.opencontainers.image.description' = [Path]::GetFileName($Path)
                'metadata' = $metadataJson
                'resourceType' = 'Nupkg'
            }
        }

        [NupkgMetadata]@{
            Layer = $layer
            ModuleName = $moduleName
            ModuleVersion = $metadata.ModuleVersion
            Description = $metadata.Description
            Source = $metadata.PrivateData.PSData.ProjectUri
            # Not part of any convention, just defined here to show how it
            # could be specified and passed onto the OCI metadata.
            License = $metadata.PrivateData.SPDXLicense
        }
    }
    catch {
        $PSCmdlet.WriteError($_)
    }
    finally {
        ${psd1Stream}?.Dispose()
        ${nupkg}?.Dispose()
        ${nupkgStream}?.Dispose()
    }
}

Function New-ManifestConfig {
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [OciLayer[]]
        $Layer,

        [Parameter()]
        [string]
        $Description,

        [Parameter()]
        [string]
        $Source,

        [Parameter()]
        [string]
        $License
    )

    begin {
        $layers = [List[ordered]]::new()
        $artifactType = $null
    }
    process {
        foreach ($l in $Layer) {
            try {
                if ([string]::IsNullOrWhiteSpace($l.MediaType)) {
                    throw "The layer's MediaType must have a valid string value"
                }
                if ([string]::IsNullOrWhiteSpace($l.Digest)) {
                    throw "The layers' Digest must have a valid string value"
                }

                if ($null -eq $artifactType) {
                    # artifactType is set to the first layers's mediaType.
                    $artifactType = $l.MediaType
                }

                $rawLayer = [Ordered]@{
                    mediaType = $l.MediaType
                    digest = $l.Digest
                    size = $l.Size
                    annotations = [Ordered]@{}
                }
                if ($null -ne $l.Annotations) {
                    foreach ($kvp in $l.Annotations.GetEnumerator()) {
                        $rawLayer.annotations.Add([string]$kvp.Key, [string]$kvp.Value)
                    }
                }

                $layers.Add($rawLayer)
            }
            catch {
                $PSCmdlet.WriteError($_)
            }
        }
    }
    end {
        if ($layers.Count -eq 0) {
            $err = [ErrorRecord]::new(
                [Exception]::new("No valid layers were specified, cannot create OCI manifest"),
                "NoValidLayers",
                [ErrorCategory]::InvalidData,
                $null)
            $PSCmdlet.ThrowTerminatingError($err)
        }

        $manifest = [Ordered]@{
            schemaVersion = 2
            mediaType = 'application/vnd.oci.image.manifest.v1+json'
            # Not set by PSResourceGet but the OCI spec says this should be
            # set to the mediaType of the artifact when the config is empty.
            # We just use the first layer's mediaType.
            artifactType = $artifactType
            config = [ordered]@{
                # PSResourceGet uses a 0 byte config with the mediaType of
                # 'application/vnd.oci.image.config.v1+json'. The OCI spec
                # says that it should use this empty JSON spec of '{}' so
                # we do that here. PSResourceGet doesn't do any client side
                # validation.
                mediaType = 'application/vnd.oci.empty.v1+json'
                digest = 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'
                size = 2
            }
            layers = @($layers)
            annotations = [Ordered]@{
                # Not needed but nice to see the exact time it was created.
                'org.opencontainers.image.created' = ([DateTime]::UtcNow).ToString("yyyy-MM-dd'T'HH:mm:ss.fffK")
            }
        }

        if ($Description) {
            # Shown in ghcr.io in the package version so nice to pass it along.
            $manifest.annotations['org.opencontainers.image.description'] = $Description
        }

        if ($Source) {
            # Allows GH to link the OCI package to a repo so that the
            # workflow token for that repo has admin access by default.
            $manifest.annotations['org.opencontainers.image.source'] = $Source
        }

        if ($License) {
            # GH can display this license with the package info.
            $manifest.annotations['org.opencontainers.image.licenses'] = $License
        }

        $manifest | ConvertTo-Json -Depth 3
    }
}

Function Publish-OciBlob {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Registry,

        [Parameter(Mandatory)]
        [SecureString]
        $AccessToken,

        [Parameter(Mandatory)]
        [string]
        $PackageName,

        [Parameter(Mandatory)]
        [string]
        $Digest,

        [Parameter(Mandatory)]
        [string]
        $Path
    )

    try {
        $webParams = @{
            Authentication = 'Bearer'
            Token = $AccessToken
            Headers = @{
                Accept = 'application/vnd.oci.image.manifest.v1+json'
            }
        }

        $testUri = "https://$Registry/v2/$PackageName/blobs/${Digest}"
        Write-Verbose -Message "Checking if OCI Blob for '$Path' already exists with HEAD => '$testUri'"
        $testResp = Invoke-WebRequest @webParams -Uri $testUri -Method HEAD -SkipHttpErrorCheck
        if ($testResp.BaseResponse.IsSuccessStatusCode) {
            Write-Verbose -Message "OCI Blob for '$Path' already exists"
            return
        }
        elseif ($testResp.StatusCode -ne 404) {
            # Throws the exception that we can catch
            $testResp.BaseResponse.EnsureSuccessStatusCode()
        }

        $startUri = "https://$Registry/v2/$PackageName/blobs/uploads/"
        Write-Verbose -Message "Starting OCI Blob upload request for '$Path' with POST => '$startUri'"
        $startResponse = Invoke-WebRequest @webParams -Uri $startUri -Method POST
        $location = $startResponse.Headers.Location[0]
        Write-Verbose -Message "Received blob upload location '$location'"

        # ghcr.io returns relative but RFC says it could be absolute or
        # relative so we check here.
        if (-not ([uri]$location).IsAbsoluteUri) {
            $location = "https://${Registry}$location"
        }

        $endUri = "${location}?digest=${Digest}"
        Write-Verbose -Message "Uploading OCI Blob with PUT => '$endUri'"
        $null = Invoke-WebRequest @webParams -Uri $endUri -Method PUT -InFile $Path -ContentType "application/octet-stream"
    }
    catch {
        $PSCmdlet.WriteError($_)
    }
}

Function Publish-OciManifest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Registry,

        [Parameter(Mandatory)]
        [SecureString]
        $AccessToken,

        [Parameter(Mandatory)]
        [string]
        $PackageName,

        [Parameter(Mandatory)]
        [string]
        $Version,

        [Parameter(Mandatory)]
        [string]
        $Manifest
    )

    try {
        $manifestData = [Encoding]::UTF8.GetBytes($Manifest)

        $putUri = "https://$Registry/v2/$PackageName/manifests/$Version"
        $webParams = @{
            Authentication = 'Bearer'
            Body = $manifestData
            ContentType = 'application/vnd.oci.image.manifest.v1+json'
            Headers = @{
                Accept = 'application/vnd.oci.image.manifest.v1+json'
            }
            Method = 'PUT'
            Token = $AccessToken
            Uri = $putUri
        }

        Write-Verbose -Message "Publishing manifest with PUT => '$putUri'"
        $null = Invoke-WebRequest @webParams
    }
    catch {
        $PSCmdlet.WriteError($_)
    }
}

Function Publish-NupkgToOci {
    <#
    .SYNOPSIS
    Publishes a PowerShell module .nupkg to an OCI-compliant container registry.

    .DESCRIPTION
    This script replicates the PushNupkgContainerRegistry functionality from
    PSResourceGet, uploading a .nupkg file to a container registry using the OCI
    Distribution Specification. This is used instead of PSResourceGet as their OCI
    publisher is written only for Azure ACR and cannot be used with custom access
    tokens due to the hardcoded Azure OAuth flow.

    .PARAMETER Registry
    The OCI registry to publish to, e.g. 'ghcr.io'

    .PARAMETER Path
    The path to nupkg to publish. The version and other metadata are parsed from
    this file. Relative paths are resolved relative to the current location in
    PowerShell.

    .PARAMETER Credential
    The access token to use for authentication.

    .PARAMETER PackageName
    The name of the package to publish as. This value is always lowercased to fit
    the OCI requirements. If not set this defaults to
    "$($Credential.UserName)/module_name" where module_name is the psd1 filename
    contained in the nupkg.

    .EXAMPLE
    $ghUser = 'username'
    $ghToken = (ConvertTo-SecureString -AsPlainText -Force $env:GITHUB_TOKEN)

    $publishArgs = @{
        Registry = 'ghcr.io'
        Path = './MyModule.nupkg'
        Credential = ([PSCredential]::new($ghUser, $ghToken))
    }
    ./publish_oci.ps1 @publishArgs
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $Registry,

        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter(Mandatory)]
        [PSCredential]
        $Credential,

        [Parameter()]
        [string]
        $PackageName
    )

    $ErrorActionPreference = 'Stop'

    try {
        $resolvedNupkgPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
        if (-not (Test-Path -LiteralPath $resolvedNupkgPath)) {
            throw "Nupkg path was not found at '$resolvedNupkgPath'"
        }

        $metadata = Get-NupkgMetadata -Path $resolvedNupkgPath

        $configParams = @{}
        foreach ($field in @('Description', 'Source', 'License')) {
            $value = $metadata.$field
            if ($value) {
                $configParams.$field = $value
            }
        }
        $manifestConfig = $metadata.Layer | New-ManifestConfig @configParams
        Write-Verbose -Message "OCI Manifest Config`n$manifestConfig"

        if (-not $PackageName) {
            $PackageName = "$($Credential.UserName)/$($metadata.ModuleName)"
        }

        # OCI requires the package name to be lowercase.
        $PackageName = $PackageName.ToLowerInvariant()
        Write-Verbose -Message "OCI PackageName for nupkg with be '$PackageName'"

        $accessToken = Get-OciAccessToken -Registry $Registry -PackageName $PackageName -Credential $Credential
        $commonPublish = @{
            Registry = $Registry
            AccessToken = $accessToken
            PackageName = $PackageName
        }

        Publish-OciBlob @commonPublish -Path $resolvedNupkgPath -Digest $metadata.Layer.Digest
        Publish-OciManifest @commonPublish -Version $metadata.ModuleVersion -Manifest $manifestConfig
    }
    catch {
        $PSCmdlet.WriteError($_)
    }
}
