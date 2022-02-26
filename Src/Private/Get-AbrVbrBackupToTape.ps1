
function Get-AbrVbrBackupToTape {
    <#
    .SYNOPSIS
        Used by As Built Report to returns tape backup jobs configuration created in Veeam Backup & Replication.
    .DESCRIPTION
        Documents the configuration of Veeam VBR in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        0.4.0
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
        Write-PscriboMessage "Discovering Veeam VBR Tape Backup jobs configuration information from $System."
    }

    process {
        try {
            if ((Get-VBRTapeJob).count -gt 0) {
                Section -Style Heading3 'Backup To Tape Job Configuration' {
                    Paragraph "The following section details backup to tape jobs configuration."
                    BlankLine
                    $OutObj = @()
                    $TBkjobs = Get-VBRTapeJob | Where-Object {$_.Type -eq 'BackupToTape'}
                    if ($TBkjobs) {
                        foreach ($TBkjob in $TBkjobs) {
                            Section -Style Heading4 "$($TBkjob.Name) Configuration" {
                                Section -Style Heading5 'Backups Information' {
                                    $OutObj = @()
                                    try {
                                        Write-PscriboMessage "Discovered $($TBkjob.Name) common information."
                                        if ($TBkjob.Object.Group -eq 'BackupRepository') {
                                            $RepoSize = $TBkjob.Object | Where-Object {$_.Group -eq 'BackupRepository'}
                                            $TotalBackupSize = (($TBkjob.Object.info.IncludedSize | Measure-Object -Sum ).Sum) + ($RepoSize.GetContainer().CachedTotalSpace.InBytes - $RepoSize.GetContainer().CachedFreeSpace.InBytes)
                                        } else {$TotalBackupSize = ($TBkjob.Object.info.IncludedSize | Measure-Object -Sum).Sum}

                                        $inObj = [ordered] @{
                                            'Name' = $TBkjob.Name
                                            'Type' = $TBkjob.Type
                                            'Total Backup Size' = ConvertTo-FileSizeString $TotalBackupSize
                                            'Next Run' = Switch ($TBkjob.Enabled) {
                                                'False' {'Disabled'}
                                                default {$TBkjob.NextRun}
                                            }
                                            'Description' = $TBkjob.Description
                                        }
                                        $OutObj = [pscustomobject]$inobj

                                        $TableParams = @{
                                            Name = "Common Information - $($TBkjob.Name)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $OutObj | Table @TableParams
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning $_.Exception.Message
                                    }
                                }
                                if ($TBkjob.Object) {
                                    try {
                                        Section -Style Heading5 'Object to Process' {
                                            $OutObj = @()
                                            foreach ($LinkedBkJob in $TBkjob.Object) {
                                                try {
                                                    Write-PscriboMessage "Discovered $($LinkedBkJob.Name) object to process."
                                                    if ($LinkedBkJob.Type) {
                                                        $Repository = $LinkedBkJob.Name
                                                        $Type = 'Repository'
                                                    } else {
                                                        $Repository = $LinkedBkJob.GetTargetRepository().Name
                                                        $Type = 'Backup Job'
                                                    }
                                                    if ($LinkedBkJob.Group -eq 'BackupRepository') {
                                                        $TotalBackupSize = ConvertTo-FileSizeString ($LinkedBkJob.GetContainer().CachedTotalSpace.InBytes - $LinkedBkJob.GetContainer().CachedFreeSpace.InBytes)
                                                    } else {$TotalBackupSize = ConvertTo-FileSizeString $LinkedBkJob.Info.IncludedSize}

                                                    $inObj = [ordered] @{
                                                        'Name' = $LinkedBkJob.Name
                                                        'Type' = $Type
                                                        'Size' = $TotalBackupSize
                                                        'Repository' = $Repository
                                                    }
                                                    $OutObj += [pscustomobject]$inobj
                                                }
                                                catch {
                                                    Write-PscriboMessage -IsWarning $_.Exception.Message
                                                }
                                            }

                                            $TableParams = @{
                                                Name = "Objects - $($TBkjob.Name)"
                                                List = $false
                                                ColumnWidths = 35, 25, 15, 25
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                                        }
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning $_.Exception.Message
                                    }
                                }
                                if ($TBkjob.FullBackupMediaPool) {
                                    try {
                                        Section -Style Heading5 'Media Pool' {
                                            $OutObj = @()
                                            foreach ($BackupMediaPool in $TBkjob.FullBackupMediaPool) {
                                                try {
                                                    Write-PscriboMessage "Discovered $($TBkjob.Name) media pool."
                                                    #Todo Fix this mess!
                                                    if ($BackupMediaPool.Type -eq "Gfs") {
                                                        if ($BackupMediaPool.DailyMediaSetOptions.MediaSetPolicy.MoveFromMediaPoolAutomatically) {
                                                            $MoveFromMediaPoolAutomatically = 'Use any available media'
                                                        } else {$MoveFromMediaPoolAutomatically = "Use $(($BackupMediaPool.DailyMediaSetOptions.MediaSetPolicy.Medium).count) selected"}
                                                        if ($BackupMediaPool.DailyMediaSetOptions.MediaSetPolicy.AppendToCurrentTape) {
                                                            $AppendToCurrentTape = 'append'
                                                        } else {$AppendToCurrentTape = "do not append"}
                                                        if ($BackupMediaPool.DailyMediaSetOptions.MediaSetPolicy.MoveOfflineToVault) {
                                                            $MoveOfflineToVault = "export to vault $($BackupMediaPool.DailyMediaSetOptions.MediaSetPolicy.Vault.Name)"
                                                        } else {$MoveOfflineToVault = "do not export"}

                                                        if ($BackupMediaPool.WeeklyMediaSetOptions.MediaSetPolicy.MoveFromMediaPoolAutomatically) {
                                                            $WeeklyMoveFromMediaPoolAutomatically = 'Use any available media'
                                                        } else {$WeeklyMoveFromMediaPoolAutomatically = "Use $(($BackupMediaPool.WeeklyMediaSetOptions.MediaSetPolicy.Medium).count) selected"}
                                                        if ($BackupMediaPool.WeeklyMediaSetOptions.MediaSetPolicy.AppendToCurrentTape) {
                                                            $WeeklyAppendToCurrentTape = 'append'
                                                        } else {$WeeklyAppendToCurrentTape = "do not append"}
                                                        if ($BackupMediaPool.WeeklyMediaSetOptions.MediaSetPolicy.MoveOfflineToVault) {
                                                            $WeeklyMoveOfflineToVault = "export to vault $($BackupMediaPool.WeeklyMediaSetOptions.MediaSetPolicy.Vault.Name)"
                                                        } else {$WeeklyMoveOfflineToVault = "do not export"}

                                                        if ($BackupMediaPool.MonthlyMediaSetOptions.MediaSetPolicy.MoveFromMediaPoolAutomatically) {
                                                            $MonthlyMoveFromMediaPoolAutomatically = 'Use any available media'
                                                        } else {$MonthlyMoveFromMediaPoolAutomatically = "Use $(($BackupMediaPool.MonthlyMediaSetOptions.MediaSetPolicy.Medium).count) selected"}
                                                        if ($BackupMediaPool.MonthlyMediaSetOptions.MediaSetPolicy.AppendToCurrentTape) {
                                                            $MonthlyAppendToCurrentTape = 'append'
                                                        } else {$MonthlyAppendToCurrentTape = "do not append"}
                                                        if ($BackupMediaPool.MonthlyMediaSetOptions.MediaSetPolicy.MoveOfflineToVault) {
                                                            $MonthlyMoveOfflineToVault = "export to vault $($BackupMediaPool.MonthlyMediaSetOptions.MediaSetPolicy.Vault.Name)"
                                                        } else {$MonthlyMoveOfflineToVault = "do not export"}

                                                        if ($BackupMediaPool.QuarterlyMediaSetOptions.MediaSetPolicy.MoveFromMediaPoolAutomatically) {
                                                            $QuarterlyMoveFromMediaPoolAutomatically = 'Use any available media'
                                                        } else {$QuarterlyMoveFromMediaPoolAutomatically = "Use $(($BackupMediaPool.QuarterlyMediaSetOptions.MediaSetPolicy.Medium).count) selected"}
                                                        if ($BackupMediaPool.QuarterlyMediaSetOptions.MediaSetPolicy.AppendToCurrentTape) {
                                                            $QuarterlyAppendToCurrentTape = 'append'
                                                        } else {$QuarterlyAppendToCurrentTape = "do not append"}
                                                        if ($BackupMediaPool.QuarterlyMediaSetOptions.MediaSetPolicy.MoveOfflineToVault) {
                                                            $QuarterlyMoveOfflineToVault = "export to vault $($BackupMediaPool.QuarterlyMediaSetOptions.MediaSetPolicy.Vault.Name)"
                                                        } else {$QuarterlyMoveOfflineToVault = "do not export"}

                                                        if ($BackupMediaPool.YearlyMediaSetOptions.MediaSetPolicy.MoveFromMediaPoolAutomatically) {
                                                            $YearlyMoveFromMediaPoolAutomatically = 'Use any available media'
                                                        } else {$YearlyMoveFromMediaPoolAutomatically = "Use $(($BackupMediaPool.YearlyMediaSetOptions.MediaSetPolicy.Medium).count) selected"}
                                                        if ($BackupMediaPool.YearlyMediaSetOptions.MediaSetPolicy.AppendToCurrentTape) {
                                                            $YearlyAppendToCurrentTape = 'append'
                                                        } else {$YearlyAppendToCurrentTape = "do not append"}
                                                        if ($BackupMediaPool.YearlyMediaSetOptions.MediaSetPolicy.MoveOfflineToVault) {
                                                            $YearlyMoveOfflineToVault = "export to vault $($BackupMediaPool.YearlyMediaSetOptions.MediaSetPolicy.Vault.Name)"
                                                        } else {$YearlyMoveOfflineToVault = "do not export"}
                                                    }

                                                    $inObj = [ordered] @{
                                                        'Name' = $BackupMediaPool.Name
                                                        'Pool Type' = $BackupMediaPool.Type
                                                        'Tape Count' = (Get-VBRTapeMedium -MediaPool $BackupMediaPool.Name).count
                                                        'Free Space' = ConvertTo-FileSizeString ((Get-VBRTapeMedium -MediaPool $BackupMediaPool.Name).Free | Measure-Object -Sum).Sum
                                                        'Encryption Enabled' = ConvertTo-TextYN $BackupMediaPool.EncryptionOptions.Enabled
                                                        'Encryption Key' = Switch ($BackupMediaPool.EncryptionOptions.Enabled) {
                                                            'True' {(Get-VBREncryptionKey | Where-Object {$_.Id -eq $BackupMediaPool.EncryptionOptions.Key.Id}).Description}
                                                            'False' {'Disabled'}
                                                            default {$BackupMediaPool.EncryptionOptions.Key.Id}
                                                        }
                                                        'Parallel Processing' = "$(ConvertTo-TextYN $BackupMediaPool.MultiStreamingOptions.NumberOfStreams) drives; Multiple Backup Chains: $(ConvertTo-TextYN $BackupMediaPool.MultiStreamingOptions.SplitJobFilesBetweenDrives)"
                                                        'Is WORM' = ConvertTo-TextYN $BackupMediaPool.Worm
                                                    }
                                                    if ($BackupMediaPool.Type -eq "Gfs") {
                                                        $inObj.add('Daily', ("$($TBkjob.FullBackupMediaPool.DailyMediaSetOptions.OverwritePeriod) days; $MoveFromMediaPoolAutomatically; $AppendToCurrentTape; $MoveOfflineToVault"))
                                                        $inObj.add('Weekly', ("$($TBkjob.FullBackupMediaPool.WeeklyMediaSetOptions.OverwritePeriod) days; $WeeklyMoveFromMediaPoolAutomatically; $WeeklyAppendToCurrentTape; $WeeklyMoveOfflineToVault"))
                                                        $inObj.add('Monthly', ("$($TBkjob.FullBackupMediaPool.MonthlyMediaSetOptions.OverwritePeriod) days; $MonthlyMoveFromMediaPoolAutomatically; $MonthlyAppendToCurrentTape; $MonthlyMoveOfflineToVault"))
                                                        $inObj.add('Quarterly', ("$($TBkjob.FullBackupMediaPool.QuarterlyMediaSetOptions.OverwritePeriod) days; $QuarterlyMoveFromMediaPoolAutomatically; $QuarterlyAppendToCurrentTape; $QuarterlyMoveOfflineToVault"))
                                                        $inObj.add('Yearly', ("$($TBkjob.FullBackupMediaPool.YearlyMediaSetOptions.OverwritePeriod) days; $YearlyMoveFromMediaPoolAutomatically; $YearlyAppendToCurrentTape; $YearlyMoveOfflineToVault"))
                                                    }
                                                    if ($BackupMediaPool.Type -eq "Custom") {
                                                        $Vault = Switch (($TBkjob.FullBackupMediaPool.Vault).count) {
                                                            0 {"Disabled"}
                                                            default {$TBkjob.FullBackupMediaPool.Vault}
                                                        }
                                                        $Retention = Switch ($TBkjob.FullBackupMediaPool.RetentionPolicy.Type) {
                                                            $Null {"Disabled"}
                                                            'Period' {"Protect data for $($TBkjob.FullBackupMediaPool.RetentionPolicy.Value) $($TBkjob.FullBackupMediaPool.RetentionPolicy.Period)"}
                                                            'Cyclic' {'Do not protect data (cyclically overwrite tape as required)'}
                                                            'Never' {'Never Overwrite Data'}
                                                        }
                                                        $MediaSetPolicy = Switch ($TBkjob.FullBackupMediaPool.MediaSetCreationPolicy.Type) {
                                                            $Null {"Disabled"}
                                                            'Always' {"Create new media set for every backup session"}
                                                            'Daily' {"Daily at $($TBkjob.FullBackupMediaPool.MediaSetCreationPolicy.DailyOptions.Period), $($TBkjob.FullBackupMediaPool.MediaSetCreationPolicy.DailyOptions.Type)"}
                                                            'Never' {'Do not create, always continue using current media set'}
                                                        }
                                                        $inObj.add('Retention', ($Retention))
                                                        $inObj.add('Export to Vault', (ConvertTo-TextYN $TBkjob.FullBackupMediaPool.MoveOfflineToVault))
                                                        $inObj.add('Vault', ($Vault))
                                                        $inObj.add('Media Set Name', ($TBkjob.FullBackupMediaPool.MediaSetName))
                                                        $inObj.add('Automatically create new media set', ($MediaSetPolicy))
                                                        if ($TBkjob.FullBackupMediaPool.MediaSetCreationPolicy.Type -eq 'Daily') {
                                                            $inObj.add('On these days', ($TBkjob.FullBackupMediaPool.MediaSetCreationPolicy.DailyOptions.DayOfWeek -join ", "))
                                                        }
                                                        if ($TBkjob.FullBackupPolicy.Type  -eq 'WeeklyOnDays') {
                                                            $DayOfWeek = Switch (($TBkjob.FullBackupPolicy.WeeklyOnDays).count) {
                                                                7 {'Everyday'}
                                                                default {$TBkjob.FullBackupPolicy.WeeklyOnDays -join ", "}
                                                            }
                                                            $inObj.add('Full Backup Schedule', ("Weekly on selected days: $DayOfWeek"))
                                                        } else {
                                                            $Months = Switch (($TBkjob.FullBackupPolicy.MonthlyOptions.Months).count) {
                                                                12 {'Every Month'}
                                                                default {$TBkjob.FullBackupPolicy.MonthlyOptions.Months -join ", "}
                                                            }
                                                            $inObj.add('Full Backup Schedule', ("Monthly on: $($TBkjob.FullBackupPolicy.MonthlyOptions.DayNumberInMonth), $($TBkjob.FullBackupPolicy.MonthlyOptions.DayOfWeek) of $Months"))
                                                        }
                                                    }
                                                    $OutObj += [pscustomobject]$inobj
                                                }
                                                catch {
                                                    Write-PscriboMessage -IsWarning $_.Exception.Message
                                                }
                                            }

                                            $TableParams = @{
                                                Name = "Media Pool - $($TBkjob.Name)"
                                                List = $True
                                                ColumnWidths = 40, 60
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                                        }
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning $_.Exception.Message
                                    }
                                }
                                if ($TBkjob.ProcessIncrementalBackup -and $TBkjob.FullBackupMediaPool.Type -eq 'Custom') {
                                    try {
                                        Section -Style Heading5 'Incremental Backup' {
                                            $OutObj = @()
                                            foreach ($BackupMediaPool in $TBkjob.IncrementalBackupMediaPool) {
                                                try {
                                                    Write-PscriboMessage "Discovered $($TBkjob.Name) incremental backup."
                                                    #Todo Fix this mess!
                                                    if ($BackupMediaPool.Type -eq "Gfs") {
                                                        if ($BackupMediaPool.DailyMediaSetOptions.MediaSetPolicy.MoveFromMediaPoolAutomatically) {
                                                            $MoveFromMediaPoolAutomatically = 'Use any available media'
                                                        } else {$MoveFromMediaPoolAutomatically = "Use $(($BackupMediaPool.DailyMediaSetOptions.MediaSetPolicy.Medium).count) selected"}
                                                        if ($BackupMediaPool.DailyMediaSetOptions.MediaSetPolicy.AppendToCurrentTape) {
                                                            $AppendToCurrentTape = 'append'
                                                        } else {$AppendToCurrentTape = "do not append"}
                                                        if ($BackupMediaPool.DailyMediaSetOptions.MediaSetPolicy.MoveOfflineToVault) {
                                                            $MoveOfflineToVault = "export to vault $($BackupMediaPool.DailyMediaSetOptions.MediaSetPolicy.Vault.Name)"
                                                        } else {$MoveOfflineToVault = "do not export"}

                                                        if ($BackupMediaPool.WeeklyMediaSetOptions.MediaSetPolicy.MoveFromMediaPoolAutomatically) {
                                                            $WeeklyMoveFromMediaPoolAutomatically = 'Use any available media'
                                                        } else {$WeeklyMoveFromMediaPoolAutomatically = "Use $(($BackupMediaPool.WeeklyMediaSetOptions.MediaSetPolicy.Medium).count) selected"}
                                                        if ($BackupMediaPool.WeeklyMediaSetOptions.MediaSetPolicy.AppendToCurrentTape) {
                                                            $WeeklyAppendToCurrentTape = 'append'
                                                        } else {$WeeklyAppendToCurrentTape = "do not append"}
                                                        if ($BackupMediaPool.WeeklyMediaSetOptions.MediaSetPolicy.MoveOfflineToVault) {
                                                            $WeeklyMoveOfflineToVault = "export to vault $($BackupMediaPool.WeeklyMediaSetOptions.MediaSetPolicy.Vault.Name)"
                                                        } else {$WeeklyMoveOfflineToVault = "do not export"}

                                                        if ($BackupMediaPool.MonthlyMediaSetOptions.MediaSetPolicy.MoveFromMediaPoolAutomatically) {
                                                            $MonthlyMoveFromMediaPoolAutomatically = 'Use any available media'
                                                        } else {$MonthlyMoveFromMediaPoolAutomatically = "Use $(($BackupMediaPool.MonthlyMediaSetOptions.MediaSetPolicy.Medium).count) selected"}
                                                        if ($BackupMediaPool.MonthlyMediaSetOptions.MediaSetPolicy.AppendToCurrentTape) {
                                                            $MonthlyAppendToCurrentTape = 'append'
                                                        } else {$MonthlyAppendToCurrentTape = "do not append"}
                                                        if ($BackupMediaPool.MonthlyMediaSetOptions.MediaSetPolicy.MoveOfflineToVault) {
                                                            $MonthlyMoveOfflineToVault = "export to vault $($BackupMediaPool.MonthlyMediaSetOptions.MediaSetPolicy.Vault.Name)"
                                                        } else {$MonthlyMoveOfflineToVault = "do not export"}

                                                        if ($BackupMediaPool.QuarterlyMediaSetOptions.MediaSetPolicy.MoveFromMediaPoolAutomatically) {
                                                            $QuarterlyMoveFromMediaPoolAutomatically = 'Use any available media'
                                                        } else {$QuarterlyMoveFromMediaPoolAutomatically = "Use $(($BackupMediaPool.QuarterlyMediaSetOptions.MediaSetPolicy.Medium).count) selected"}
                                                        if ($BackupMediaPool.QuarterlyMediaSetOptions.MediaSetPolicy.AppendToCurrentTape) {
                                                            $QuarterlyAppendToCurrentTape = 'append'
                                                        } else {$QuarterlyAppendToCurrentTape = "do not append"}
                                                        if ($BackupMediaPool.QuarterlyMediaSetOptions.MediaSetPolicy.MoveOfflineToVault) {
                                                            $QuarterlyMoveOfflineToVault = "export to vault $($BackupMediaPool.QuarterlyMediaSetOptions.MediaSetPolicy.Vault.Name)"
                                                        } else {$QuarterlyMoveOfflineToVault = "do not export"}

                                                        if ($BackupMediaPool.YearlyMediaSetOptions.MediaSetPolicy.MoveFromMediaPoolAutomatically) {
                                                            $YearlyMoveFromMediaPoolAutomatically = 'Use any available media'
                                                        } else {$YearlyMoveFromMediaPoolAutomatically = "Use $(($BackupMediaPool.YearlyMediaSetOptions.MediaSetPolicy.Medium).count) selected"}
                                                        if ($BackupMediaPool.YearlyMediaSetOptions.MediaSetPolicy.AppendToCurrentTape) {
                                                            $YearlyAppendToCurrentTape = 'append'
                                                        } else {$YearlyAppendToCurrentTape = "do not append"}
                                                        if ($BackupMediaPool.YearlyMediaSetOptions.MediaSetPolicy.MoveOfflineToVault) {
                                                            $YearlyMoveOfflineToVault = "export to vault $($BackupMediaPool.YearlyMediaSetOptions.MediaSetPolicy.Vault.Name)"
                                                        } else {$YearlyMoveOfflineToVault = "do not export"}
                                                    }

                                                    $inObj = [ordered] @{
                                                        'Media Pool' = $BackupMediaPool.Name
                                                        'Pool Type' = $BackupMediaPool.Type
                                                        'Tape Count' = (Get-VBRTapeMedium -MediaPool $BackupMediaPool.Name).count
                                                        'Free Space' = ConvertTo-FileSizeString ((Get-VBRTapeMedium -MediaPool $BackupMediaPool.Name).Free | Measure-Object -Sum).Sum
                                                        'Encryption Enabled' = ConvertTo-TextYN $BackupMediaPool.EncryptionOptions.Enabled
                                                        'Encryption Key' = Switch ($BackupMediaPool.EncryptionOptions.Enabled) {
                                                            'True' {(Get-VBREncryptionKey | Where-Object {$_.Id -eq $BackupMediaPool.EncryptionOptions.Key.Id}).Description}
                                                            'False' {'Disabled'}
                                                            default {$BackupMediaPool.EncryptionOptions.Key.Id}
                                                        }
                                                        'Parallel Processing' = "$(ConvertTo-TextYN $BackupMediaPool.MultiStreamingOptions.NumberOfStreams) drives; Multiple Backup Chains: $(ConvertTo-TextYN $BackupMediaPool.MultiStreamingOptions.SplitJobFilesBetweenDrives)"
                                                        'Is WORM' = ConvertTo-TextYN $BackupMediaPool.Worm
                                                    }
                                                    if ($BackupMediaPool.Type -eq "Gfs") {
                                                        $inObj.add('Daily', ("$($TBkjob.IncrementalBackupMediaPool.DailyMediaSetOptions.OverwritePeriod) days; $MoveFromMediaPoolAutomatically; $AppendToCurrentTape; $MoveOfflineToVault"))
                                                        $inObj.add('Weekly', ("$($TBkjob.IncrementalBackupMediaPool.WeeklyMediaSetOptions.OverwritePeriod) days; $WeeklyMoveFromMediaPoolAutomatically; $WeeklyAppendToCurrentTape; $WeeklyMoveOfflineToVault"))
                                                        $inObj.add('Monthly', ("$($TBkjob.IncrementalBackupMediaPool.MonthlyMediaSetOptions.OverwritePeriod) days; $MonthlyMoveFromMediaPoolAutomatically; $MonthlyAppendToCurrentTape; $MonthlyMoveOfflineToVault"))
                                                        $inObj.add('Quarterly', ("$($TBkjob.IncrementalBackupMediaPool.QuarterlyMediaSetOptions.OverwritePeriod) days; $QuarterlyMoveFromMediaPoolAutomatically; $QuarterlyAppendToCurrentTape; $QuarterlyMoveOfflineToVault"))
                                                        $inObj.add('Yearly', ("$($TBkjob.IncrementalBackupMediaPool.YearlyMediaSetOptions.OverwritePeriod) days; $YearlyMoveFromMediaPoolAutomatically; $YearlyAppendToCurrentTape; $YearlyMoveOfflineToVault"))
                                                    }
                                                    if ($BackupMediaPool.Type -eq "Custom") {
                                                        $Vault = Switch (($TBkjob.IncrementalBackupMediaPool.Vault).count) {
                                                            0 {"Disabled"}
                                                            default {$TBkjob.IncrementalBackupMediaPool.Vault}
                                                        }
                                                        $Retention = Switch ($TBkjob.IncrementalBackupMediaPool.RetentionPolicy.Type) {
                                                            $Null {"Disabled"}
                                                            'Period' {"Protect data for $($TBkjob.IncrementalBackupMediaPool.RetentionPolicy.Value) $($TBkjob.IncrementalBackupMediaPool.RetentionPolicy.Period)"}
                                                            'Cyclic' {'Do not protect data (cyclically overwrite tape as required)'}
                                                            'Never' {'Never Overwrite Data'}
                                                        }
                                                        $MediaSetPolicy = Switch ($TBkjob.IncrementalBackupMediaPool.MediaSetCreationPolicy.Type) {
                                                            $Null {"Disabled"}
                                                            'Always' {"Create new media set for every backup session"}
                                                            'Daily' {"Daily at $($TBkjob.IncrementalBackupMediaPool.MediaSetCreationPolicy.DailyOptions.Period), $($TBkjob.IncrementalBackupMediaPool.MediaSetCreationPolicy.DailyOptions.Type)"}
                                                            'Never' {'Do not create, always continue using current media set'}
                                                        }
                                                        $inObj.add('Retention', ($Retention))
                                                        $inObj.add('Export to Vault', (ConvertTo-TextYN $TBkjob.IncrementalBackupMediaPool.MoveOfflineToVault))
                                                        $inObj.add('Vault', ($Vault))
                                                        $inObj.add('Media Set Name', ($TBkjob.IncrementalBackupMediaPool.MediaSetName))
                                                        $inObj.add('Automatically create new media set', ($MediaSetPolicy))
                                                        if ($TBkjob.IncrementalBackupMediaPool.MediaSetCreationPolicy.Type -eq 'Daily') {
                                                            $inObj.add('On these days', ($TBkjob.IncrementalBackupMediaPool.MediaSetCreationPolicy.DailyOptions.DayOfWeek -join ", "))
                                                        }
                                                    }
                                                    $OutObj += [pscustomobject]$inobj
                                                }
                                                catch {
                                                    Write-PscriboMessage -IsWarning $_.Exception.Message
                                                }
                                            }

                                            $TableParams = @{
                                                Name = "Incremental Backup - $($TBkjob.Name)"
                                                List = $True
                                                ColumnWidths = 40, 60
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                                        }
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning $_.Exception.Message
                                    }
                                }
                                try {
                                    Section -Style Heading5 'Options' {
                                        $OutObj = @()
                                        try {
                                            Write-PscriboMessage "Discovered $($TBkjob.Name) options."
                                            $inObj = [ordered] @{
                                                'Eject Tape Media Upon Job Completion' = ConvertTo-TextYN $TBkjob.EjectCurrentMedium
                                                'Export the following MediaSet Upon Job Completion' = ConvertTo-TextYN $TBkjob.ExportCurrentMediaSet
                                                'Limit the number of drives this job can use' = "Enabled: $(ConvertTo-TextYN $TBkjob.ParallelDriveOptions.IsEnabled); Tape Drives Limit: $($TBkjob.ParallelDriveOptions.DrivesLimit)"

                                            }
                                            $OutObj += [pscustomobject]$inobj
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning $_.Exception.Message
                                        }

                                        $TableParams = @{
                                            Name = "Options - $($TBkjob.Name)"
                                            List = $True
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                                        if ($InfoLevel.Jobs.Tape -ge 2 -and $TBkjob.NotificationOptions.EnableAdditionalNotification) {
                                            try {
                                                Section -Style Heading5 'Advanced Settings (Notifications)' {
                                                    $OutObj = @()
                                                    try {
                                                        Write-PscriboMessage "Discovered $($TBkjob.Name) notification options."
                                                        $inObj = [ordered] @{
                                                            'Send Email Notification' = ConvertTo-TextYN $TBkjob.NotificationOptions.EnableAdditionalNotification
                                                            'Email Notification Additional Recipients' = $TBkjob.NotificationOptions.AdditionalAddress -join ","
                                                        }
                                                        if (!$TBkjob.NotificationOptions.UseNotificationOptions) {
                                                            $inObj.add('Use Global Notification Settings', (ConvertTo-TextYN $TBkjob.NotificationOptions.UseNotificationOptions))
                                                        }
                                                        elseif ($TBkjob.NotificationOptions.UseNotificationOptions) {
                                                            $inObj.add('Use Custom Notification Settings', ('Yes'))
                                                            $inObj.add('Subject', ($TBkjob.NotificationOptions.NotificationSubject))
                                                            $inObj.add('Notify On Success', (ConvertTo-TextYN $TBkjob.NotificationOptions.NotifyOnSuccess))
                                                            $inObj.add('Notify On Warning', (ConvertTo-TextYN $TBkjob.NotificationOptions.NotifyOnWarning))
                                                            $inObj.add('Notify On Error', (ConvertTo-TextYN $TBkjob.NotificationOptions.NotifyOnError))
                                                            $inObj.add('Notify On Last Retry Only', (ConvertTo-TextYN $TBkjob.NotificationOptions.NotifyOnLastRetryOnly))
                                                            $inObj.add('Notify When Waiting For Tape', (ConvertTo-TextYN $TBkjob.NotificationOptions.NotifyWhenWaitingForTape))
                                                        }
                                                        $OutObj += [pscustomobject]$inobj
                                                    }
                                                    catch {
                                                        Write-PscriboMessage -IsWarning $_.Exception.Message
                                                    }

                                                    $TableParams = @{
                                                        Name = "Advanced Settings (Notifications) - $($TBkjob.Name)"
                                                        List = $True
                                                        ColumnWidths = 40, 60
                                                    }
                                                    if ($Report.ShowTableCaptions) {
                                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                                    }
                                                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                                                }
                                            }
                                            catch {
                                                Write-PscriboMessage -IsWarning $_.Exception.Message
                                            }
                                        }
                                        if ($InfoLevel.Jobs.Tape -ge 2 -and $TBkjob.NotificationOptions.EnableAdditionalNotification) {
                                            try {
                                                Section -Style Heading5 'Advanced Settings (Advanced)' {
                                                    $OutObj = @()
                                                    try {
                                                        Write-PscriboMessage "Discovered $($TBkjob.Name) advanced options."
                                                        $inObj = [ordered] @{
                                                            'Process the most recent Restore Point instead of waiting' = ConvertTo-TextYN $TBkjob.AlwaysCopyFromLatestFull
                                                            'Use Hardware Compression when available' = ConvertTo-TextYN $TBkjob.UseHardwareCompression
                                                        }
                                                        if (!$TBkjob.JobScriptOptions.PreScriptEnabled) {
                                                            $inObj.add('Pre Job Script Enabled', (ConvertTo-TextYN $TBkjob.JobScriptOptions.PreScriptEnabled))
                                                        }
                                                        elseif ($TBkjob.JobScriptOptions.PreScriptEnabled) {
                                                            $inObj.add('Run the following script before job', ($TBkjob.JobScriptOptions.PreCommand))
                                                        }
                                                        if (!$TBkjob.JobScriptOptions.PostScriptEnabled) {
                                                            $inObj.add('Post Job Script Enabled', (ConvertTo-TextYN $TBkjob.JobScriptOptions.PostScriptEnabled))
                                                        }
                                                        elseif ($TBkjob.JobScriptOptions.PostScriptEnabled) {
                                                            $inObj.add('Run the following script after job', ($TBkjob.JobScriptOptions.PostCommand))
                                                        }
                                                        if ($TBkjob.JobScriptOptions.PreScriptEnabled -or $TBkjob.JobScriptOptions.PostScriptEnabled) {
                                                            if ($TBkjob.JobScriptOptions.Periodicity -eq 'Days') {
                                                                $FrequencyValue = $TBkjob.JobScriptOptions.Day -join ", "
                                                                $FrequencyText = 'Run Script on the Selected Days'
                                                            }
                                                            elseif ($TBkjob.JobScriptOptions.Periodicity -eq 'Cycles') {
                                                                $FrequencyValue = "Every $($TBkjob.JobScriptOptions.Frequency) backup session"
                                                                $FrequencyText = 'Run Script Every Backup Session'
                                                            }
                                                            $inObj.add($FrequencyText, ($FrequencyValue))
                                                        }
                                                        $OutObj += [pscustomobject]$inobj
                                                    }
                                                    catch {
                                                        Write-PscriboMessage -IsWarning $_.Exception.Message
                                                    }

                                                    $TableParams = @{
                                                        Name = "Advanced Settings (Advanced) - $($TBkjob.Name)"
                                                        List = $True
                                                        ColumnWidths = 40, 60
                                                    }
                                                    if ($Report.ShowTableCaptions) {
                                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                                    }
                                                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                                                }
                                            }
                                            catch {
                                                Write-PscriboMessage -IsWarning $_.Exception.Message
                                            }
                                        }
                                    }
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning $_.Exception.Message
                                }
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $_.Exception.Message
        }
    }
    end {}

}