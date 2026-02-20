# Copyright: (c) 2026, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

#Requires -Version 7.4

using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Diagnostics.CodeAnalysis
using namespace System.IO
using namespace System.IO.Compression
using namespace System.Management.Automation
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Text

# SHA256 digest of '{}'
$Script:EmptyJsonDigest = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

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

Enum CredentialType {
    Default
    AzureAccessToken
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
                digest = $Script:EmptyJsonDigest
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
    [CmdletBinding(DefaultParameterSetName = "Path")]
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

        [Parameter(Mandatory, ParameterSetName = "Path")]
        [string]
        $Path,

        [Parameter(Mandatory, ParameterSetName = "Body")]
        [string]
        $Name,

        [Parameter(Mandatory, ParameterSetName = "Body")]
        [string]
        $Body
    )

    try {
        $publishParams = @{
            Method = 'Put'
            ContentType = 'application/octet-stream'
        }
        if ($Path) {
            $publishParams.InFile = $Path
            $blobId = $Path
        }
        else {
            $publishParams.Body = [Encoding]::UTF8.GetBytes($Body)
            $blobId = $Name
        }

        $webParams = @{
            Authentication = 'Bearer'
            Token = $AccessToken
            Headers = @{
                Accept = 'application/vnd.oci.image.manifest.v1+json'
            }
        }

        $testUri = "https://$Registry/v2/$PackageName/blobs/${Digest}"
        Write-Verbose -Message "Checking if OCI Blob for '$blobId' already exists with HEAD => '$testUri'"
        $testResp = Invoke-WebRequest @webParams -Uri $testUri -Method Head -SkipHttpErrorCheck
        if ($testResp.BaseResponse.IsSuccessStatusCode) {
            Write-Verbose -Message "OCI Blob for '$blobId' already exists"
            return
        }
        elseif ($testResp.StatusCode -ne 404) {
            # Throws the exception that we can catch
            $testResp.BaseResponse.EnsureSuccessStatusCode()
        }

        $startUri = "https://$Registry/v2/$PackageName/blobs/uploads/"
        Write-Verbose -Message "Starting OCI Blob upload request for '$blobId' with POST => '$startUri'"
        $startResponse = Invoke-WebRequest @webParams -Uri $startUri -Method Post
        $location = $startResponse.Headers.Location[0]
        Write-Verbose -Message "Received blob upload location '$location'"

        # ghcr.io returns relative but RFC says it could be absolute or
        # relative so we check here.
        if (-not ([uri]$location).IsAbsoluteUri) {
            $location = "https://${Registry}$location"
        }

        # We need to append our digest as a query parameters but also need to
        # deal with the location already having query parameters or not.
        $locationBuilder = [UriBuilder]::new($location)
        if ($locationBuilder.Query) {
            $locationBuilder.Query += "&digest=${Digest}"
        }
        else {
            # UriBuilder adds ? for us.
            $locationBuilder.Query = "digest=$Digest"
        }

        $publishUri = $locationBuilder.Uri
        Write-Verbose -Message "Uploading OCI Blob with PUT => '$publishUri'"
        $null = Invoke-WebRequest @webParams @publishParams -Uri $publishUri
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

Function Get-OciBearerToken {
    <#
    .SYNOPSIS
    Gets the bearer token to use for the OCI registry.

    .PARAMETER Registry
    The registry to authenticate with.

    .PARAMETER Scope
    The scope/permissions to request, e.g. 'repository:package:pull,push'.
    Some registries allow wildcards for the package (ACR) while others do not
    (GHCR).

    .PARAMETER Credential
    The credentials to use with Basic authentication. The username/password
    to use is dependent on the registry and what it expects. If no Credential
    is provided then an anonymous token is requested.

    For ACR the username is the client_id, password is the client_secret. For
    GHCR the username is the GH username and password is the classic PAT with
    read:package (and write:package for push).

    .PARAMETER CredentialType
    Provide additional context to the function that can transform the provided
    Credential into what is needed by the Basic auth token exchange.

    The 'Default' type does nothing and will use the provided credential as is.

    The 'AzureAccessToken' will request an ACR refresh token using the
    /oauth2/exchange registry endpoint. The input credential username should
    be the Entra Tenant Id (GUID) and password the access token returned by
    functions like `(Get-AzAccessToken -AsSecureString).Token`.

    .PARAMETER ClientId
    An identifier for the bearer token request, this is used for auditing on
    registry side and doesn't impact the authentication itself.

    .NOTES
    The auth flow and details are documented under
    https://distribution.github.io/distribution/spec/auth/token/

    At least for azure this won't fail if the credentials are invalid. When
    inspecting the token it returns a acr_anon_pull that has been granted
    'repository:*:pull'. Future work could validate the JWT token returned
    but this seems registry specific.
    #>
    [SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword', '',
        Justification='CredentialType does not contain sensitive info, it is a switch like param'
    )]
    [OutputType([SecureString])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Registry,

        [Parameter(Mandatory)]
        [string]
        $Scope,

        [Parameter()]
        [PSCredential]
        $Credential,

        [Parameter()]
        [CredentialType]
        $CredentialType = [CredentialType]::Default,

        [Parameter()]
        [string]
        $ClientId = 'JboreanOciTest'
    )

    try {
        $registryUri = "https://$Registry/v2/"
        $resp = Invoke-WebRequest -Uri $registryUri -SkipHttpErrorCheck
        $bearer = $resp.Headers['WWW-Authenticate'] | Select-Object -First 1
        if (-not $bearer) {
            throw "No WWW-Authenticate found in response headers for '$registryUri'"
        }
        Write-Verbose -Message "Received registry WWW-Authenticate value '$bearer'"

        if ($bearer -match 'realm="([^"]+)"') {
            $realm = $matches[1]
        } else {
            throw "Could not extract realm from WWW-Authenticate header '$bearer'"
        }

        if ($bearer -match 'service="([^"]+)"') {
            $service = $matches[1]
        } else {
            throw "Could not extract service from WWW-Authenticate header '$bearer'"
        }

        if ($CredentialType -eq [CredentialType]::AzureAccessToken) {
            if (-not $Credential -or $Credential -eq [PSCredential]::Empty) {
                throw "-CredentialType AzureAccessToken can only be used with a valid credential"
            }

            # If we have an access token returned from something like
            # Get-AzAccessToken, we need to use an ACR specific API to exchange
            # that to an ACR refresh token.
            # https://azure.github.io/acr/AAD-OAuth.html#calling-post-oauth2-exchange-to-get-an-acr-refresh-token
            $exchangeParams = @{
                Body = @{
                    access_token = $Credential.GetNetworkCredential().Password
                    grant_type = 'access_token'
                    service = $service
                    tenant = $Credential.UserName
                }
                ContentType = 'application/x-www-form-urlencoded'
                Method = 'Post'
                Uri = "https://$Registry/oauth2/exchange"
            }
            Write-Verbose -Message "Getting ACR refresh token from '$($exchangeParams.Uri)' for tenant '$($Credential.UserName)' and service '$service'"
            $exchangeResp = Invoke-RestMethod @exchangeParams
            Write-Verbose -Message "Received ACR refresh token '$($exchangeResp.refresh_token)'"

            # This refresh token can then be used with an empty GUID in the
            # normal Basic auth exchange.
            # https://azure.github.io/acr/AAD-OAuth.html#authenticating-docker-with-an-acr-refresh-token
            $Credential = [PSCredential]::new(
                [Guid]::Empty,
                (ConvertTo-SecureString -AsPlainText -Force -String $exchangeResp.refresh_token))
        }

        $tokenUri = "${realm}?service=${service}&client_id=${ClientId}&scope=${Scope}"

        $webCredentials = @{}
        if ($Credential -and $Credential -ne [PSCredential]::Empty) {
            $webCredentials.Authentication = 'Basic'
            $webCredentials.Credential = $Credential
        }

        Write-Verbose -Message "Requesting bearer token from '$tokenUri'"
        $tokenResponse = Invoke-WebRequest -Uri $tokenUri -Method Get @webCredentials
        Write-Verbose -Message "Received bearer token JSON response '$($tokenResponse.Content)'"
        $tokenJson = $tokenResponse.Content | ConvertFrom-Json

        # Either token or access_token can be returned. In the wild I've seen
        # ghcr.io return token whereas ACR returns access_token
        $tokenValue = if ($tokenJson.token) {
            $tokenJson.token
        }
        elseif ($tokenJson.access_token) {
            $tokenJson.access_token
        }
        else {
            throw "Failed to get anonymous token, did not find the expected 'token' or 'access_token' in the response"
        }

        ConvertTo-SecureString -AsPlainText -Force -String $tokenValue
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
    The access token to use for authentication. See Get-OciBearerToken for more
    information.

    .PARAMETER CredentialType
    The type of credential that is being used. See Get-OciBearerToken for more
    information.

    .PARAMETER PackageName
    The name of the package to publish as. If not set this defaults to the
    filename of the .psd1 contained in the nupkg.

    The package name and prefix are always lower cased to fit OCI requirements.

    .PARAMETER PackagePrefix
    A prefix to prepend with '/' to the -PackageName. This can be used to add a
    prefix to the default -PackageName value derived from the .nupkg. Some
    registries require a package to be namespaced, e.g. ghcr.io should have
    '-PackagePrefix $ghUsername' to ensure the package is published as
    'username/modulename'.

    The package name and prefix are always lower cased to fit OCI requirements.

    .EXAMPLE
    Publish 'username/mymodule' to GitHub OCI

        $ghUser = 'username'
        $ghToken = ConvertTo-SecureString -AsPlainText -Force $env:GITHUB_TOKEN

        $publishParams = @{
            Registry = 'ghcr.io'
            Path = './MyModule.nupkg'
            PackagePrefix = $ghUser
            Credential = ([PSCredential]::new($ghUser, $ghToken))
        }
        Publish-NupkgToOci @publishParams

    .EXAMPLE
    Publish 'mymodule' to Azure Container Registry using a app id and secret

        $clientId = '...'
        $clientSecret = ConvertTo-SecureString -AsPlainText -Force $env:AZURE_CLIENT_SECRET

        $publishParams = @{
            Registry = 'acrname.azurecr.io'
            Path = './MyModule.nupkg'
            Credential = ([PSCredential]::new($clientId, $clientSecret))
        }
        Publish-NupkgToOci @publishParams

    .EXAMPLE
    Publish 'mymodule' to Azure Container Registry using the Azure credential from Connect-AzAccount

        # Connect in whatever way is best for your scenario
        Connect-AzAccount ...

        # Retrieve the Azure Access Token for the connection.
        $azToken = Get-AzAccessToken -AsSecureString
        $cred = [PSCredential]::new($azToken.TenantId, $azToken.Token)

        $publishParams = @{
            Registry = 'acrname.azurecr.io'
            Path = './MyModule.nupkg'
            Credential = $cred
            # Tell the publisher this is an AzureAccessToken so it can use it
            # properly.
            CredentialType = 'AzureAccessToken'
        }
        Publish-NupkgToOci @publishParams
    #>
    [SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword', '',
        Justification='CredentialType does not contain sensitive info, it is a switch like param'
    )]
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
        [CredentialType]
        $CredentialType = [CredentialType]::Default,

        [Parameter()]
        [string]
        $PackageName,

        [Parameter()]
        [string]
        $PackagePrefix
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

        $nameToPublish = if ($PackageName) {
            $PackageName
        }
        else {
            $metadata.ModuleName
        }
        if ($PackagePrefix) {
            $nameToPublish = "$PackagePrefix/$nameToPublish"
        }

        # OCI requires the package name to be lowercase.
        $nameToPublish = $nameToPublish.ToLowerInvariant()
        if ($nameToPublish -cnotmatch '[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*') {
            throw "Package name '$nameToPublish' does not conform to OCI specification"
        }
        Write-Verbose -Message "OCI PackageName for nupkg with be '$nameToPublish'"

        $bearerParams = @{
            Registry = $Registry
            Scope = "repository:${nameToPublish}:pull,push"
            Credential = $Credential
            CredentialType = $CredentialType
        }
        $accessToken = Get-OciBearerToken @bearerParams
        $commonPublish = @{
            Registry = $Registry
            AccessToken = $accessToken
            PackageName = $nameToPublish
        }

        Publish-OciBlob @commonPublish -Path $resolvedNupkgPath -Digest $metadata.Layer.Digest

        # Not all OCI registries support the empty json config mediaType. For
        # example ACR fails when publishing the manifest with the below if we
        # don't ensure a blob with the empty digest exists.
        # {"code": "MANIFEST_BLOB_UNKNOWN", "message": "blob unknown to registry", "detail": "sha256:..."}
        #
        # While registries like ghcr.io don't need this it doesn't break
        # anything to publish this blob and the operation will be a no-op if
        # already done in the past for this package in a previous version.
        Publish-OciBlob @commonPublish -Name EmptyConfig.json -Body "{}" -Digest $Script:EmptyJsonDigest

        Publish-OciManifest @commonPublish -Version $metadata.ModuleVersion -Manifest $manifestConfig
    }
    catch {
        $PSCmdlet.WriteError($_)
    }
}

Export-ModuleMember -Function Get-OciBearerToken, Publish-NupkgToOci
