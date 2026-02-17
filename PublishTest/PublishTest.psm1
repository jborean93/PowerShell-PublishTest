function Get-PublishTest {
    <#
    .SYNOPSIS
    Returns a stub test value.

    .DESCRIPTION
    A simple placeholder function that returns a test string.
    #>
    [CmdletBinding()]
    param()

    "This is a test value from PublishTest module"
}

Export-ModuleMember -Function Get-PublishTest
