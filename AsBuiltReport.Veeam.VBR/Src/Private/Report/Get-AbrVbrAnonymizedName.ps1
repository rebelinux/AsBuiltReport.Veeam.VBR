function Get-AbrVbrAnonymizedName {
    <#
    .SYNOPSIS
        Anonymizes hostnames, server names, FQDNs, and IP addresses in report data.
    .DESCRIPTION
        Replaces identifiable network identifiers (hostnames, FQDNs, IPv4/IPv6 addresses)
        with consistent anonymized placeholders so that the same real value always maps to
        the same placeholder within a single report run. Values that do not look like network
        identifiers (descriptions, status strings, paths, GUIDs, hashes, etc.) are returned
        unchanged.

        Anonymization is only active when Options.Anonymize is set to $true in the report
        configuration. When disabled, the original value is returned unmodified.
    .PARAMETER Value
        The string value to evaluate for anonymization. Accepts pipeline input.
    .NOTES
        Version:        1.0.0
        Author:         Jonathan Colon

    .EXAMPLE
        'server01.company.com' | Get-AbrVbrAnonymizedName
        # Returns 'server-001.example.com' (with Anonymize enabled)

    .EXAMPLE
        '192.168.10.5' | Get-AbrVbrAnonymizedName
        # Returns '10.0.1.1' (with Anonymize enabled)

    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.Veeam.VBR
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [Parameter(Position = 0, ValueFromPipeline)]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Value
    )

    process {
        if (-not $script:Options.Anonymize -or [string]::IsNullOrWhiteSpace($Value)) {
            return $Value
        }

        # Lazily initialize the per-run cache (reset at report start in Invoke-AsBuiltReport.Veeam.VBR)
        if ($null -eq $script:AnonymizedNamesCache) {
            $script:AnonymizedNamesCache = @{}
            $script:AnonymizedHostCounter = 0
            $script:AnonymizedIPCounter = 0
        }

        if ($script:AnonymizedNamesCache.ContainsKey($Value)) {
            return $script:AnonymizedNamesCache[$Value]
        }

        # --- Exclusions: return value unchanged for known non-sensitive patterns ---

        # Multi-word strings (descriptions, labels, status values with spaces)
        if ($Value -match '\s') { return $Value }

        # GUIDs
        if ($Value -match '^[{(]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[)}]?$') { return $Value }

        # Certificate thumbprints and hex hashes (20+ contiguous hex characters)
        if ($Value -match '^[0-9a-fA-F]{20,}$') { return $Value }

        # File system paths and UNC paths
        if ($Value -match '^([A-Za-z]:\\|\\\\|/)') { return $Value }

        # URLs
        if ($Value -match '^https?://|^ftp://') { return $Value }

        # Email addresses
        if ($Value -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return $Value }

        # Pure numeric values (ports, counts)
        if ($Value -match '^\d+$') { return $Value }

        # --- Detection and anonymization ---

        # IPv4 address (optionally with port suffix, e.g., 192.168.1.100:9392)
        # Must be checked before version strings as IPs also match digit.digit patterns
        if ($Value -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$') {
            $script:AnonymizedIPCounter++
            $third = [Math]::Floor(($script:AnonymizedIPCounter - 1) / 254) + 1
            $fourth = (($script:AnonymizedIPCounter - 1) % 254) + 1
            $anonymized = "10.0.$third.$fourth"
            $script:AnonymizedNamesCache[$Value] = $anonymized
            return $anonymized
        }

        # IPv6 address
        if ($Value -match '^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$' -or $Value -eq '::1') {
            $script:AnonymizedIPCounter++
            $anonymized = 'fd00::{0:x4}' -f $script:AnonymizedIPCounter
            $script:AnonymizedNamesCache[$Value] = $anonymized
            return $anonymized
        }

        # Pure version strings (e.g., 12.1.0.2, 6.0) - checked after IP addresses
        if ($Value -match '^\d+(\.\d+){1,5}$') { return $Value }

        # FQDN: dot-separated segments where every segment contains at least one letter
        # e.g., server01.domain.local, veeam.contoso.com
        if ($Value -match '^[A-Za-z0-9][A-Za-z0-9\-]*(\.[A-Za-z0-9][A-Za-z0-9\-]*)+$') {
            $segments = $Value -split '\.'
            $segmentsWithoutLetter = @($segments | Where-Object { $_ -notmatch '[A-Za-z]' })
            if ($segmentsWithoutLetter.Count -eq 0) {
                $script:AnonymizedHostCounter++
                $anonymized = "server-$('{0:D3}' -f $script:AnonymizedHostCounter).example.com"
                $script:AnonymizedNamesCache[$Value] = $anonymized
                return $anonymized
            }
        }

        # Hyphenated hostname (e.g., VEEAM-SERVER, backup-proxy-01)
        if ($Value -match '^[A-Za-z0-9]+(-[A-Za-z0-9]+)+$') {
            $script:AnonymizedHostCounter++
            $anonymized = "Server-$('{0:D3}' -f $script:AnonymizedHostCounter)"
            $script:AnonymizedNamesCache[$Value] = $anonymized
            return $anonymized
        }

        # Mixed alphanumeric hostname: contains both letters and digits, no separators
        # e.g., server01, backup1, VeeamProxy02
        if ($Value -match '^[A-Za-z0-9]+$' -and $Value -match '[A-Za-z]' -and $Value -match '\d') {
            $script:AnonymizedHostCounter++
            $anonymized = "Server-$('{0:D3}' -f $script:AnonymizedHostCounter)"
            $script:AnonymizedNamesCache[$Value] = $anonymized
            return $anonymized
        }

        # No pattern matched - return original value
        return $Value
    }
}
