
function Get-AbrVbrTapejob {
    <#
    .SYNOPSIS
        Used by As Built Report to returns tape backup jobs created in Veeam Backup & Replication.
    .DESCRIPTION
        Documents the configuration of Veeam VBR in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        0.5.3
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
        Credits:        Iain Brighton (@iainbrighton) - PScribo module

    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.Veeam.VBR
    #>
    [CmdletBinding()]
    param (

    )

    begin {
        Write-PscriboMessage "Discovering Veeam VBR Tape Backup jobs information from $System."
    }

    process {
        try {
            if ((Get-VBRTapeJob).count -gt 0) {
                Section -Style Heading3 'Tape Backup Jobs' {
                    Paragraph "The following section list tape backup jobs created in Veeam Backup & Replication."
                    BlankLine
                    $OutObj = @()
                    $TBkjobs = Get-VBRTapeJob
                    foreach ($TBkjob in $TBkjobs) {
                        try {
                            Write-PscriboMessage "Discovered $($TBkjob.Name) location."
                            $inObj = [ordered] @{
                                'Name' = $TBkjob.Name
                                'Type' = ($TBkjob.Type -creplace  '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim()
                                'Latest Status' = $TBkjob.LastResult
                                'Target Repository' = $TBkjob.Target
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                    }

                    $TableParams = @{
                        Name = "Backup Jobs - $VeeamBackupServer"
                        List = $false
                        ColumnWidths = 30, 25, 15, 30
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $_.Exception.Message
        }
    }
    end {}

}
