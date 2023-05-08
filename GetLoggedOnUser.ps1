
#region Function Write-FunctionHeaderOrFooter
Function Write-FunctionHeaderOrFooter {

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]$CmdletName,
        [Parameter(Mandatory = $true, ParameterSetName = 'Header')]
        [AllowEmptyCollection()]
        [Hashtable]$CmdletBoundParameters,
        [Parameter(Mandatory = $true, ParameterSetName = 'Header')]
        [Switch]$Header,
        [Parameter(Mandatory = $true, ParameterSetName = 'Footer')]
        [Switch]$Footer
    )

    If ($Header) {
        Write-Log -Message 'Function Start' -Source ${CmdletName} -DebugMessage

        ## Get the parameters that the calling function was invoked with
        [String]$CmdletBoundParameters = $CmdletBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' }, @{ Label = 'Type'; Expression = { $_.Value.GetType().Name }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        If ($CmdletBoundParameters) {
            Write-Log -Message "Function invoked with bound parameter(s): `r`n$CmdletBoundParameters" -Source ${CmdletName} -DebugMessage
        }
        Else {
            Write-Log -Message 'Function invoked without any bound parameters.' -Source ${CmdletName} -DebugMessage
        }
    }
    ElseIf ($Footer) {
        Write-Log -Message 'Function End' -Source ${CmdletName} -DebugMessage
    }
}
#endregion

#region Function Write-Log
Function Write-Log {

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [Alias('Text')]
        [String[]]$Message,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateRange(1, 3)]
        [Int16]$Severity = 1,
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [String]$Source = $([String]$parentFunctionName = [IO.Path]::GetFileNameWithoutExtension((Get-Variable -Name 'MyInvocation' -Scope 1 -ErrorAction 'SilentlyContinue').Value.MyCommand.Name); If ($parentFunctionName) {
                $parentFunctionName
            }
            Else {
                'Unknown'
            }),
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNullorEmpty()]
        [String]$ScriptSection = $script:installPhase,
        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateSet('CMTrace', 'Legacy')]
        [String]$LogType = $configToolkitLogStyle,
        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNullorEmpty()]
        [String]$LogFileDirectory = "C:\Users\jmore\AppData\Local\Temp\nada_Installation",
        # $(If ($configToolkitCompressLogs) {
        #         $logTempFolder
        #     }
        #     Else {
        #         $configToolkitLogDir
        #     }),
        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNullorEmpty()]
        [String]$LogFileName = $logName,
        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNullorEmpty()]
        [Decimal]$MaxLogFileSizeMB = $configToolkitLogMaxSize,
        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateNotNullorEmpty()]
        [Boolean]$WriteHost = $true, #$configToolkitLogWriteToHost,
        [Parameter(Mandatory = $false, Position = 9)]
        [ValidateNotNullorEmpty()]
        [Boolean]$ContinueOnError = $true,
        [Parameter(Mandatory = $false, Position = 10)]
        [Switch]$PassThru = $false,
        [Parameter(Mandatory = $false, Position = 11)]
        [Switch]$DebugMessage = $false,
        [Parameter(Mandatory = $false, Position = 12)]
        [Boolean]$LogDebugMessage = $true #$configToolkitLogDebugMessage
    )

    Begin {
        ## Get the name of this function
        [String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

        ## Logging Variables
        #  Log file date/time
        [DateTime]$DateTimeNow = Get-Date
        [String]$LogTime = $DateTimeNow.ToString('HH\:mm\:ss.fff')
        [String]$LogDate = $DateTimeNow.ToString('MM-dd-yyyy')
        If (-not (Test-Path -LiteralPath 'variable:LogTimeZoneBias')) {
            [Int32]$script:LogTimeZoneBias = [TimeZone]::CurrentTimeZone.GetUtcOffset($DateTimeNow).TotalMinutes
        }
        [String]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias
        #  Initialize variables
        [Boolean]$ExitLoggingFunction = $false
        If (-not (Test-Path -LiteralPath 'variable:DisableLogging')) {
            $DisableLogging = $false
        }
        #  Check if the script section is defined
        [Boolean]$ScriptSectionDefined = [Boolean](-not [String]::IsNullOrEmpty($ScriptSection))
        #  Get the file name of the source script
        Try {
            If ($script:MyInvocation.Value.ScriptName) {
                [String]$ScriptSource = Split-Path -Path $script:MyInvocation.Value.ScriptName -Leaf -ErrorAction 'Stop'
            }
            Else {
                [String]$ScriptSource = Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction 'Stop'
            }
        }
        Catch {
            $ScriptSource = ''
        }

        ## Create script block for generating CMTrace.exe compatible log entry
        [ScriptBlock]$CMTraceLogString = {
            Param (
                [String]$lMessage,
                [String]$lSource,
                [Int16]$lSeverity
            )
            "<![LOG[$lMessage]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$lSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$lSeverity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
        }

        ## Create script block for writing log entry to the console
        [ScriptBlock]$WriteLogLineToHost = {
            Param (
                [String]$lTextLogLine,
                [Int16]$lSeverity
            )
            If ($WriteHost) {
                #  Only output using color options if running in a host which supports colors.
                If ($Host.UI.RawUI.ForegroundColor) {
                    Switch ($lSeverity) {
                        3 {
                            Write-Host -Object $lTextLogLine -ForegroundColor 'Red' -BackgroundColor 'Black'
                        }
                        2 {
                            Write-Host -Object $lTextLogLine -ForegroundColor 'Yellow' -BackgroundColor 'Black'
                        }
                        1 {
                            Write-Host -Object $lTextLogLine
                        }
                    }
                }
                #  If executing "powershell.exe -File <filename>.ps1 > log.txt", then all the Write-Host calls are converted to Write-Output calls so that they are included in the text log.
                Else {
                    Write-Output -InputObject ($lTextLogLine)
                }
            }
        }

        ## Exit function if it is a debug message and logging debug messages is not enabled in the config XML file
        If (($DebugMessage) -and (-not $LogDebugMessage)) {
            [Boolean]$ExitLoggingFunction = $true; Return
        }
        ## Exit function if logging to file is disabled and logging to console host is disabled
        If (($DisableLogging) -and (-not $WriteHost)) {
            [Boolean]$ExitLoggingFunction = $true; Return
        }
        ## Exit Begin block if logging is disabled
        If ($DisableLogging) {
            Return
        }
        ## Exit function function if it is an [Initialization] message and the toolkit has been relaunched
        If (($AsyncToolkitLaunch) -and ($ScriptSection -eq 'Initialization')) {
            [Boolean]$ExitLoggingFunction = $true; Return
        }

        ## Create the directory where the log file will be saved
        If (-not (Test-Path -LiteralPath $LogFileDirectory -PathType 'Container')) {
            Try {
                $null = New-Item -Path $LogFileDirectory -Type 'Directory' -Force -ErrorAction 'Stop'
            }
            Catch {
                [Boolean]$ExitLoggingFunction = $true
                #  If error creating directory, write message to console
                If (-not $ContinueOnError) {
                    Write-Host -Object "[$LogDate $LogTime] [${CmdletName}] $ScriptSection :: Failed to create the log directory [$LogFileDirectory]. `r`n$(Resolve-Error)" -ForegroundColor 'Red'
                }
                Return
            }
        }

        ## Assemble the fully qualified path to the log file
        [String]$LogFilePath = Join-Path -Path $LogFileDirectory -ChildPath $LogFileName
    }
    Process {
        ## Exit function if logging is disabled
        If ($ExitLoggingFunction) {
            Return
        }

        ForEach ($Msg in $Message) {
            ## If the message is not $null or empty, create the log entry for the different logging methods
            [String]$CMTraceMsg = ''
            [String]$ConsoleLogLine = ''
            [String]$LegacyTextLogLine = ''
            If ($Msg) {
                #  Create the CMTrace log message
                If ($ScriptSectionDefined) {
                    [String]$CMTraceMsg = "[$ScriptSection] :: $Msg"
                }

                #  Create a Console and Legacy "text" log entry
                [String]$LegacyMsg = "[$LogDate $LogTime]"
                If ($ScriptSectionDefined) {
                    [String]$LegacyMsg += " [$ScriptSection]"
                }
                If ($Source) {
                    [String]$ConsoleLogLine = "$LegacyMsg [$Source] :: $Msg"
                    Switch ($Severity) {
                        3 {
                            [String]$LegacyTextLogLine = "$LegacyMsg [$Source] [Error] :: $Msg"
                        }
                        2 {
                            [String]$LegacyTextLogLine = "$LegacyMsg [$Source] [Warning] :: $Msg"
                        }
                        1 {
                            [String]$LegacyTextLogLine = "$LegacyMsg [$Source] [Info] :: $Msg"
                        }
                    }
                }
                Else {
                    [String]$ConsoleLogLine = "$LegacyMsg :: $Msg"
                    Switch ($Severity) {
                        3 {
                            [String]$LegacyTextLogLine = "$LegacyMsg [Error] :: $Msg"
                        }
                        2 {
                            [String]$LegacyTextLogLine = "$LegacyMsg [Warning] :: $Msg"
                        }
                        1 {
                            [String]$LegacyTextLogLine = "$LegacyMsg [Info] :: $Msg"
                        }
                    }
                }
            }

            ## Execute script block to create the CMTrace.exe compatible log entry
            [String]$CMTraceLogLine = & $CMTraceLogString -lMessage $CMTraceMsg -lSource $Source -lSeverity $Severity

            ## Choose which log type to write to file
            If ($LogType -ieq 'CMTrace') {
                [String]$LogLine = $CMTraceLogLine
            }
            Else {
                [String]$LogLine = $LegacyTextLogLine
            }

            ## Write the log entry to the log file if logging is not currently disabled
            If (-not $DisableLogging) {
                Try {
                    $LogLine | Out-File -FilePath $LogFilePath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop'
                }
                Catch {
                    If (-not $ContinueOnError) {
                        Write-Host -Object "[$LogDate $LogTime] [$ScriptSection] [${CmdletName}] :: Failed to write message [$Msg] to the log file [$LogFilePath]. `r`n$(Resolve-Error)" -ForegroundColor 'Red'
                    }
                }
            }

            ## Execute script block to write the log entry to the console if $WriteHost is $true
            & $WriteLogLineToHost -lTextLogLine $ConsoleLogLine -lSeverity $Severity
        }
    }
    End {
        ## Archive log file if size is greater than $MaxLogFileSizeMB and $MaxLogFileSizeMB > 0
        Try {
            If ((-not $ExitLoggingFunction) -and (-not $DisableLogging)) {
                [IO.FileInfo]$LogFile = Get-ChildItem -LiteralPath $LogFilePath -ErrorAction 'Stop'
                [Decimal]$LogFileSizeMB = $LogFile.Length / 1MB
                If (($LogFileSizeMB -gt $MaxLogFileSizeMB) -and ($MaxLogFileSizeMB -gt 0)) {
                    ## Change the file extension to "lo_"
                    [String]$ArchivedOutLogFile = [IO.Path]::ChangeExtension($LogFilePath, 'lo_')
                    [Hashtable]$ArchiveLogParams = @{ ScriptSection = $ScriptSection; Source = ${CmdletName}; Severity = 2; LogFileDirectory = $LogFileDirectory; LogFileName = $LogFileName; LogType = $LogType; MaxLogFileSizeMB = 0; WriteHost = $WriteHost; ContinueOnError = $ContinueOnError; PassThru = $false }

                    ## Log message about archiving the log file
                    $ArchiveLogMessage = "Maximum log file size [$MaxLogFileSizeMB MB] reached. Rename log file to [$ArchivedOutLogFile]."
                    Write-Log -Message $ArchiveLogMessage @ArchiveLogParams

                    ## Archive existing log file from <filename>.log to <filename>.lo_. Overwrites any existing <filename>.lo_ file. This is the same method SCCM uses for log files.
                    Move-Item -LiteralPath $LogFilePath -Destination $ArchivedOutLogFile -Force -ErrorAction 'Stop'

                    ## Start new log file and Log message about archiving the old log file
                    $NewLogMessage = "Previous log file was renamed to [$ArchivedOutLogFile] because maximum log file size of [$MaxLogFileSizeMB MB] was reached."
                    Write-Log -Message $NewLogMessage @ArchiveLogParams
                }
            }
        }
        Catch {
            ## If renaming of file fails, script will continue writing to log file even if size goes over the max file size
        }
        Finally {
            If ($PassThru) {
                Write-Output -InputObject ($Message)
            }
        }
    }
}
#endregion

#region Function Resolve-Error
Function Resolve-Error {

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [Array]$ErrorRecord,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullorEmpty()]
        [String[]]$Property = ('Message', 'InnerException', 'FullyQualifiedErrorId', 'ScriptStackTrace', 'PositionMessage'),
        [Parameter(Mandatory = $false, Position = 2)]
        [Switch]$GetErrorRecord = $true,
        [Parameter(Mandatory = $false, Position = 3)]
        [Switch]$GetErrorInvocation = $true,
        [Parameter(Mandatory = $false, Position = 4)]
        [Switch]$GetErrorException = $true,
        [Parameter(Mandatory = $false, Position = 5)]
        [Switch]$GetErrorInnerException = $true
    )

    Begin {
        ## If function was called without specifying an error record, then choose the latest error that occurred
        If (-not $ErrorRecord) {
            If ($global:Error.Count -eq 0) {
                #Write-Warning -Message "The `$Error collection is empty"
                Return
            }
            Else {
                [Array]$ErrorRecord = $global:Error[0]
            }
        }

        ## Allows selecting and filtering the properties on the error object if they exist
        [ScriptBlock]$SelectProperty = {
            Param (
                [Parameter(Mandatory = $true)]
                [ValidateNotNullorEmpty()]
                $InputObject,
                [Parameter(Mandatory = $true)]
                [ValidateNotNullorEmpty()]
                [String[]]$Property
            )

            [String[]]$ObjectProperty = $InputObject | Get-Member -MemberType '*Property' | Select-Object -ExpandProperty 'Name'
            ForEach ($Prop in $Property) {
                If ($Prop -eq '*') {
                    [String[]]$PropertySelection = $ObjectProperty
                    Break
                }
                ElseIf ($ObjectProperty -contains $Prop) {
                    [String[]]$PropertySelection += $Prop
                }
            }
            Write-Output -InputObject ($PropertySelection)
        }

        #  Initialize variables to avoid error if 'Set-StrictMode' is set
        $LogErrorRecordMsg = $null
        $LogErrorInvocationMsg = $null
        $LogErrorExceptionMsg = $null
        $LogErrorMessageTmp = $null
        $LogInnerMessage = $null
    }
    Process {
        If (-not $ErrorRecord) {
            Return
        }
        ForEach ($ErrRecord in $ErrorRecord) {
            ## Capture Error Record
            If ($GetErrorRecord) {
                [String[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord -Property $Property
                $LogErrorRecordMsg = $ErrRecord | Select-Object -Property $SelectedProperties
            }

            ## Error Invocation Information
            If ($GetErrorInvocation) {
                If ($ErrRecord.InvocationInfo) {
                    [String[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord.InvocationInfo -Property $Property
                    $LogErrorInvocationMsg = $ErrRecord.InvocationInfo | Select-Object -Property $SelectedProperties
                }
            }

            ## Capture Error Exception
            If ($GetErrorException) {
                If ($ErrRecord.Exception) {
                    [String[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord.Exception -Property $Property
                    $LogErrorExceptionMsg = $ErrRecord.Exception | Select-Object -Property $SelectedProperties
                }
            }

            ## Display properties in the correct order
            If ($Property -eq '*') {
                #  If all properties were chosen for display, then arrange them in the order the error object displays them by default.
                If ($LogErrorRecordMsg) {
                    [Array]$LogErrorMessageTmp += $LogErrorRecordMsg
                }
                If ($LogErrorInvocationMsg) {
                    [Array]$LogErrorMessageTmp += $LogErrorInvocationMsg
                }
                If ($LogErrorExceptionMsg) {
                    [Array]$LogErrorMessageTmp += $LogErrorExceptionMsg
                }
            }
            Else {
                #  Display selected properties in our custom order
                If ($LogErrorExceptionMsg) {
                    [Array]$LogErrorMessageTmp += $LogErrorExceptionMsg
                }
                If ($LogErrorRecordMsg) {
                    [Array]$LogErrorMessageTmp += $LogErrorRecordMsg
                }
                If ($LogErrorInvocationMsg) {
                    [Array]$LogErrorMessageTmp += $LogErrorInvocationMsg
                }
            }

            If ($LogErrorMessageTmp) {
                $LogErrorMessage = 'Error Record:'
                $LogErrorMessage += "`n-------------"
                $LogErrorMsg = $LogErrorMessageTmp | Format-List | Out-String
                $LogErrorMessage += $LogErrorMsg
            }

            ## Capture Error Inner Exception(s)
            If ($GetErrorInnerException) {
                If ($ErrRecord.Exception -and $ErrRecord.Exception.InnerException) {
                    $LogInnerMessage = 'Error Inner Exception(s):'
                    $LogInnerMessage += "`n-------------------------"

                    $ErrorInnerException = $ErrRecord.Exception.InnerException
                    $Count = 0

                    While ($ErrorInnerException) {
                        [String]$InnerExceptionSeperator = '~' * 40

                        [String[]]$SelectedProperties = & $SelectProperty -InputObject $ErrorInnerException -Property $Property
                        $LogErrorInnerExceptionMsg = $ErrorInnerException | Select-Object -Property $SelectedProperties | Format-List | Out-String

                        If ($Count -gt 0) {
                            $LogInnerMessage += $InnerExceptionSeperator
                        }
                        $LogInnerMessage += $LogErrorInnerExceptionMsg

                        $Count++
                        $ErrorInnerException = $ErrorInnerException.InnerException
                    }
                }
            }

            If ($LogErrorMessage) {
                $Output = $LogErrorMessage
            }
            If ($LogInnerMessage) {
                $Output += $LogInnerMessage
            }

            Write-Output -InputObject $Output

            If (Test-Path -LiteralPath 'variable:Output') {
                Clear-Variable -Name 'Output'
            }
            If (Test-Path -LiteralPath 'variable:LogErrorMessage') {
                Clear-Variable -Name 'LogErrorMessage'
            }
            If (Test-Path -LiteralPath 'variable:LogInnerMessage') {
                Clear-Variable -Name 'LogInnerMessage'
            }
            If (Test-Path -LiteralPath 'variable:LogErrorMessageTmp') {
                Clear-Variable -Name 'LogErrorMessageTmp'
            }
        }
    }
    End {
    }
}
#endregion


#region Function Get-LoggedOnUser
Function Get-LoggedOnUser {

    [CmdletBinding()]
    Param (
    )

    Begin {
        ## Get the name of this function and write header
        [String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        Try {
            Write-Log -Message 'Getting session information for all logged on users.' -Source ${CmdletName}
            Write-Output -InputObject ([PSADT.QueryUser]::GetUserSessionInfo("$env:ComputerName"))
        }
        Catch {
            Write-Log -Message "Failed to get session information for all logged on users. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion


#region Function Execute-ProcessAsUser
Function Execute-ProcessAsUser {
    <#
.SYNOPSIS

Execute a process with a logged in user account, by using a scheduled task, to provide interaction with user in the SYSTEM context.

.DESCRIPTION

Execute a process with a logged in user account, by using a scheduled task, to provide interaction with user in the SYSTEM context.

.PARAMETER UserName

Logged in Username under which to run the process from. Default is: The active console user. If no console user exists but users are logged in, such as on terminal servers, then the first logged-in non-console user.

.PARAMETER Path

Path to the file being executed.

.PARAMETER TempPath

Path to the temporary directory used to store the script to be executed as user. If using a user writable directory, ensure you select -RunLevel 'LeastPrivilege'.

.PARAMETER Parameters

Arguments to be passed to the file being executed.

.PARAMETER SecureParameters

Hides all parameters passed to the executable from the Toolkit log file.

.PARAMETER RunLevel

Specifies the level of user rights that Task Scheduler uses to run the task. The acceptable values for this parameter are:

- HighestAvailable: Tasks run by using the highest available privileges (Admin privileges for Administrators). Default Value.

- LeastPrivilege: Tasks run by using the least-privileged user account (LUA) privileges.

.PARAMETER Wait

Wait for the process, launched by the scheduled task, to complete execution before accepting more input. Default is $false.

.PARAMETER PassThru

Returns the exit code from this function or the process launched by the scheduled task.

.PARAMETER WorkingDirectory

Set working directory for the process.

.PARAMETER ContinueOnError

Continue if an error is encountered. Default is $true.

.INPUTS

None

You cannot pipe objects to this function.

.OUTPUTS

System.Int32.

Returns the exit code from this function or the process launched by the scheduled task.

.EXAMPLE

Execute-ProcessAsUser -UserName 'CONTOSO\User' -Path "$PSHOME\powershell.exe" -Parameters "-Command & { & `"C:\Test\Script.ps1`"; Exit `$LastExitCode }" -Wait

Execute process under a user account by specifying a username under which to execute it.

.EXAMPLE

Execute-ProcessAsUser -Path "$PSHOME\powershell.exe" -Parameters "-Command & { & `"C:\Test\Script.ps1`"; Exit `$LastExitCode }" -Wait

Execute process under a user account by using the default active logged in user that was detected when the toolkit was launched.

.NOTES

.LINK

https://psappdeploytoolkit.com
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]$UserName = $RunAsActiveUser.NTAccount,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]$Path,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]$TempPath,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]$Parameters = '',
        [Parameter(Mandatory = $false)]
        [Switch]$SecureParameters = $false,
        [Parameter(Mandatory = $false)]
        [ValidateSet('HighestAvailable', 'LeastPrivilege')]
        [String]$RunLevel = 'HighestAvailable',
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Switch]$Wait = $false,
        [Parameter(Mandatory = $false)]
        [Switch]$PassThru = $false,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]$WorkingDirectory,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]$ContinueOnError = $true
    )

    Begin {
        ## Get the name of this function and write header
        [String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header

        If ((![string]::IsNullOrEmpty($tempPath))) {
            $executeAsUserTempPath = $tempPath
            If (($tempPath -eq $loggedOnUserTempPath) -and ($RunLevel -eq "HighestPrivilege")) {
                Write-Log -Message "WARNING: Using [${CmdletName}] with a user writable directory using the HighestPrivilege creates a security vulnerability. Please use -RunLevel 'LeastPrivilege' when using a user writable directoy." -Severity 'Warning'
            }
        }
        Else {
            [String]$executeAsUserTempPath = Join-Path -Path $dirAppDeployTemp -ChildPath 'ExecuteAsUser'
        }
    }
    Process {
        ## Initialize exit code variable
        [Int32]$executeProcessAsUserExitCode = 0

        ## Confirm that the username field is not empty
        If (-not $UserName) {
            [Int32]$executeProcessAsUserExitCode = 60009
            Write-Log -Message "The function [${CmdletName}] has a -UserName parameter that has an empty default value because no logged in users were detected when the toolkit was launched." -Severity 3 -Source ${CmdletName}
            If (-not $ContinueOnError) {
                Throw "The function [${CmdletName}] has a -UserName parameter that has an empty default value because no logged in users were detected when the toolkit was launched."
            }
            Return
        }

        ## Confirm if the toolkit is running with administrator privileges
        If (($RunLevel -eq 'HighestAvailable') -and (-not $IsAdmin)) {
            [Int32]$executeProcessAsUserExitCode = 60003
            Write-Log -Message "The function [${CmdletName}] requires the toolkit to be running with Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'." -Severity 3 -Source ${CmdletName}
            If (-not $ContinueOnError) {
                Throw "The function [${CmdletName}] requires the toolkit to be running with Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'."
            }
            Return
        }

        ## Check whether the specified Working Directory exists
        If ($WorkingDirectory -and (-not (Test-Path -LiteralPath $WorkingDirectory -PathType 'Container'))) {
            Write-Log -Message 'The specified working directory does not exist or is not a directory. The scheduled task might not work as expected.' -Severity 2 -Source ${CmdletName}
        }

        ## Build the scheduled task XML name
        [String]$schTaskName = (("$appDeployToolkitName-ExecuteAsUser" -replace ' ', '').Trim('_') -replace '[_]+', '_')

        ##  Remove and recreate the temporary folder
        If (Test-Path -LiteralPath $executeAsUserTempPath -PathType 'Container') {
            Write-Log -Message "Previous [$executeAsUserTempPath] found. Attempting removal." -Source ${CmdletName}
            Remove-Folder -Path $executeAsUserTempPath
        }
        Write-Log -Message "Creating [$executeAsUserTempPath]." -Source ${CmdletName}
        Try {
            $null = New-Item -Path $executeAsUserTempPath -ItemType 'Directory' -ErrorAction 'Stop'
        }
        Catch {
            Write-Log -Message "Unable to create [$executeAsUserTempPath]. Possible attempt to gain elevated rights." -Source ${CmdletName} -Severity 2
        }

        ## Escape XML characters
        $EscapedPath = [System.Security.SecurityElement]::Escape($Path)
        $EscapedParameters = [System.Security.SecurityElement]::Escape($Parameters)

        ## If PowerShell.exe is being launched, then create a VBScript to launch PowerShell so that we can suppress the console window that flashes otherwise
        If (((Split-Path -Path $Path -Leaf) -like 'PowerShell*') -or ((Split-Path -Path $Path -Leaf) -like 'cmd*')) {
            If ($SecureParameters) {
                Write-Log -Message "Preparing a VBScript that will start [$Path] (Parameters Hidden) as the logged-on user [$userName] and suppress the console window..." -Source ${CmdletName}
            }
            Else {
                Write-Log -Message "Preparing a VBScript that will start [$Path $Parameters] as the logged-on user [$userName] and suppress the console window..." -Source ${CmdletName}
            }

            # Permit inclusion of double quotes in parameters
            $QuotesIndex = $Parameters.Length - 1
            If ($QuotesIndex -lt 0) {
                $QuotesIndex = 0
            }

            If ($($Parameters.Substring($QuotesIndex)) -eq '"') {
                [String]$executeProcessAsUserParametersVBS = 'chr(34) & ' + "`"$($Path)`"" + ' & chr(34) & ' + '" ' + ($Parameters -replace "`r`r`n", ';' -replace "`r`n", ';' -replace '"', "`" & chr(34) & `"" -replace ' & chr\(34\) & "$', '') + ' & chr(34)'
            }
            Else {
                [String]$executeProcessAsUserParametersVBS = 'chr(34) & ' + "`"$($Path)`"" + ' & chr(34) & ' + '" ' + ($Parameters -replace "`r`r`n", ';' -replace "`r`n", ';' -replace '"', "`" & chr(34) & `"" -replace ' & chr\(34\) & "$', '') + '"'
            }

            [String[]]$executeProcessAsUserScript = "strCommand = $executeProcessAsUserParametersVBS"
            $executeProcessAsUserScript += 'set oWShell = CreateObject("WScript.Shell")'
            $executeProcessAsUserScript += 'intReturn = oWShell.Run(strCommand, 0, true)'
            $executeProcessAsUserScript += 'WScript.Quit intReturn'
            $executeProcessAsUserScript | Out-File -FilePath "$executeAsUserTempPath\$($schTaskName).vbs" -Force -Encoding 'Default' -ErrorAction 'SilentlyContinue'
            $Path = "$envWinDir\System32\wscript.exe"
            $Parameters = "/e:vbscript `"$executeAsUserTempPath\$($schTaskName).vbs`""
            $EscapedPath = [System.Security.SecurityElement]::Escape($Path)
            $EscapedParameters = [System.Security.SecurityElement]::Escape($Parameters)

            Try {
                Set-ItemPermission -Path "$executeAsUserTempPath\$schTaskName.vbs" -User $UserName -Permission 'Read'
            }
            Catch {
                Write-Log -Message "Failed to set read permissions on path [$executeAsUserTempPath\$schTaskName.vbs]. The function might not be able to work correctly." -Source ${CmdletName} -Severity 2
            }
        }

        ## Prepare working directory insert
        [String]$WorkingDirectoryInsert = ''
        If ($WorkingDirectory) {
            $WorkingDirectoryInsert = "`r`n   <WorkingDirectory>$WorkingDirectory</WorkingDirectory>"
        }

        ## Specify the scheduled task configuration in XML format
        [String]$xmlSchTask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo />
  <Triggers />
  <Settings>
    <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$EscapedPath</Command>
      <Arguments>$EscapedParameters</Arguments>$WorkingDirectoryInsert
    </Exec>
  </Actions>
  <Principals>
    <Principal id="Author">
      <UserId>$UserName</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>$RunLevel</RunLevel>
    </Principal>
  </Principals>
</Task>
"@
        ## Export the XML to file
        Try {
            #  Specify the filename to export the XML to
            [String]$xmlSchTaskFilePath = "$dirAppDeployTemp\$schTaskName.xml"
            [String]$xmlSchTask | Out-File -FilePath $xmlSchTaskFilePath -Force -ErrorAction 'Stop'
            Set-ItemPermission -Path $xmlSchTaskFilePath -User $UserName -Permission 'Read'
        }
        Catch {
            [Int32]$executeProcessAsUserExitCode = 60007
            Write-Log -Message "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
            If (-not $ContinueOnError) {
                Throw "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]: $($_.Exception.Message)"
            }
            Return
        }

        ## Create Scheduled Task to run the process with a logged-on user account
        If ($Parameters) {
            If ($SecureParameters) {
                Write-Log -Message "Creating scheduled task to run the process [$Path] (Parameters Hidden) as the logged-on user [$userName]..." -Source ${CmdletName}
            }
            Else {
                Write-Log -Message "Creating scheduled task to run the process [$Path $Parameters] as the logged-on user [$userName]..." -Source ${CmdletName}
            }
        }
        Else {
            Write-Log -Message "Creating scheduled task to run the process [$Path] as the logged-on user [$userName]..." -Source ${CmdletName}
        }
        [PSObject]$schTaskResult = Execute-Process -Path $exeSchTasks -Parameters "/create /f /tn $schTaskName /xml `"$xmlSchTaskFilePath`"" -WindowStyle 'Hidden' -CreateNoWindow -PassThru -ExitOnProcessFailure $false
        If ($schTaskResult.ExitCode -ne 0) {
            [Int32]$executeProcessAsUserExitCode = $schTaskResult.ExitCode
            Write-Log -Message "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]." -Severity 3 -Source ${CmdletName}
            If (-not $ContinueOnError) {
                Throw "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]."
            }
            Return
        }

        ## Trigger the Scheduled Task
        If ($Parameters) {
            If ($SecureParameters) {
                Write-Log -Message "Triggering execution of scheduled task with command [$Path] (Parameters Hidden) as the logged-on user [$userName]..." -Source ${CmdletName}
            }
            Else {
                Write-Log -Message "Triggering execution of scheduled task with command [$Path $Parameters] as the logged-on user [$userName]..." -Source ${CmdletName}
            }
        }
        Else {
            Write-Log -Message "Triggering execution of scheduled task with command [$Path] as the logged-on user [$userName]..." -Source ${CmdletName}
        }
        [PSObject]$schTaskResult = Execute-Process -Path $exeSchTasks -Parameters "/run /i /tn $schTaskName" -WindowStyle 'Hidden' -CreateNoWindow -Passthru -ExitOnProcessFailure $false
        If ($schTaskResult.ExitCode -ne 0) {
            [Int32]$executeProcessAsUserExitCode = $schTaskResult.ExitCode
            Write-Log -Message "Failed to trigger scheduled task [$schTaskName]." -Severity 3 -Source ${CmdletName}
            #  Delete Scheduled Task
            Write-Log -Message 'Deleting the scheduled task which did not trigger.' -Source ${CmdletName}
            Execute-Process -Path $exeSchTasks -Parameters "/delete /tn $schTaskName /f" -WindowStyle 'Hidden' -CreateNoWindow -ExitOnProcessFailure $false
            If (-not $ContinueOnError) {
                Throw "Failed to trigger scheduled task [$schTaskName]."
            }
            Return
        }

        ## Wait for the process launched by the scheduled task to complete execution
        If ($Wait) {
            Write-Log -Message "Waiting for the process launched by the scheduled task [$schTaskName] to complete execution (this may take some time)..." -Source ${CmdletName}
            Start-Sleep -Seconds 1
            #If on Windows Vista or higer, Windows Task Scheduler 2.0 is supported. 'Schedule.Service' ComObject output is UI language independent
            If (([Version]$envOSVersion).Major -gt 5) {
                Try {
                    [__ComObject]$ScheduleService = New-Object -ComObject 'Schedule.Service' -ErrorAction 'Stop'
                    $ScheduleService.Connect()
                    $RootFolder = $ScheduleService.GetFolder('\')
                    $Task = $RootFolder.GetTask("$schTaskName")
                    # Task State(Status) 4 = 'Running'
                    While ($Task.State -eq 4) {
                        Start-Sleep -Seconds 5
                    }
                    #  Get the exit code from the process launched by the scheduled task
                    [Int32]$executeProcessAsUserExitCode = $Task.LastTaskResult
                }
                Catch {
                    Write-Log -Message "Failed to retrieve information from Task Scheduler. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                }
                Finally {
                    Try {
                        $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($ScheduleService)
                    }
                    Catch {
                    }
                }
            }
            #Windows Task Scheduler 1.0
            Else {
                While ((($exeSchTasksResult = & $exeSchTasks /query /TN $schTaskName /V /FO CSV) | ConvertFrom-Csv | Select-Object -ExpandProperty 'Status' -First 1) -eq 'Running') {
                    Start-Sleep -Seconds 5
                }
                #  Get the exit code from the process launched by the scheduled task
                [Int32]$executeProcessAsUserExitCode = ($exeSchTasksResult = & $exeSchTasks /query /TN $schTaskName /V /FO CSV) | ConvertFrom-Csv | Select-Object -ExpandProperty 'Last Result' -First 1
            }
            Write-Log -Message "Exit code from process launched by scheduled task [$executeProcessAsUserExitCode]." -Source ${CmdletName}
        }
        Else {
            Start-Sleep -Seconds 1
        }

        ## Delete scheduled task
        Try {
            Write-Log -Message "Deleting scheduled task [$schTaskName]." -Source ${CmdletName}
            Execute-Process -Path $exeSchTasks -Parameters "/delete /tn $schTaskName /f" -WindowStyle 'Hidden' -CreateNoWindow -ErrorAction 'Stop'
        }
        Catch {
            Write-Log -Message "Failed to delete scheduled task [$schTaskName]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
        }

        ## Remove the XML scheduled task file
        If (Test-Path -LiteralPath $xmlSchTaskFilePath -PathType 'Leaf') {
            Remove-File -Path $xmlSchTaskFilePath
        }

        ##  Remove the temporary folder
        If (Test-Path -LiteralPath $executeAsUserTempPath -PathType 'Container') {
            Remove-Folder -Path $executeAsUserTempPath
        }
    }
    End {
        If ($PassThru) {
            Write-Output -InputObject ($executeProcessAsUserExitCode)
        }

        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion


## If the script was invoked by the Help Console, exit the script now
If ($invokingScript) {
    If ((Split-Path -Path $invokingScript -Leaf) -eq 'AppDeployToolkitHelp.ps1') {
        Return
    }
}



## Variables: Script Name and Script Paths
[String]$scriptPath = "C:\Users\jmore\Documents\GitHub\PowerShell\GetLoggedOnUser.ps1" #$MyInvocation.MyCommand.Definition
[String]$scriptName = [IO.Path]::GetFileNameWithoutExtension($scriptPath)
# [String]$scriptFileName = Split-Path -Path $scriptPath -Leaf
[String]$scriptRoot = Split-Path -Path $scriptPath -Parent
[String]$invokingScript = (Get-Variable -Name 'MyInvocation').Value.ScriptName
#  Get the invoking script directory
If ($invokingScript) {
    #  If this script was invoked by another script
    [String]$scriptParentPath = Split-Path -Path $invokingScript -Parent
}
Else {
    #  If this script was not invoked by another script, fall back to the directory one level above this script
    [String]$scriptParentPath = (Get-Item -LiteralPath $scriptRoot).Parent.FullName
}

[String]$appDeployToolkitName = 'PSAppDeployToolkit'
## Variables: Script Directories
[String]$dirFiles = Join-Path -Path $scriptParentPath -ChildPath 'Files'
[String]$dirSupportFiles = Join-Path -Path $scriptParentPath -ChildPath 'SupportFiles'
[String]$dirAppDeployTemp = Join-Path -Path $env:TEMP -ChildPath $appDeployToolkitName

If (-not (Test-Path -LiteralPath $dirAppDeployTemp -PathType 'Container' -ErrorAction 'SilentlyContinue')) {
    $null = New-Item -Path $dirAppDeployTemp -ItemType 'Directory' -Force -ErrorAction 'SilentlyContinue'
}



## Variables: App Deploy Script Dependency Files
#[String]$appDeployConfigFile = Join-Path -Path $scriptRoot -ChildPath 'AppDeployToolkitConfig.xml'
[String]$appDeployCustomTypesSourceCode = Join-Path -Path $scriptRoot -ChildPath 'AppDeployToolkitMain.cs'
# If (-not (Test-Path -LiteralPath $appDeployConfigFile -PathType 'Leaf')) {
#     Throw 'App Deploy XML configuration file not found.'
# }
If (-not (Test-Path -LiteralPath $appDeployCustomTypesSourceCode -PathType 'Leaf')) {
    Throw 'App Deploy custom types source code file not found.'
}

If (-not ([Management.Automation.PSTypeName]'PSADT.UiAutomation').Type) {
    [String[]]$ReferencedAssemblies = 'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
    Add-Type -Path $appDeployCustomTypesSourceCode -ReferencedAssemblies $ReferencedAssemblies -IgnoreWarnings -ErrorAction 'Stop'
}

## Define ScriptBlock for getting details for all logged on users
[ScriptBlock]$GetLoggedOnUserDetails = {
    [PSObject[]]$LoggedOnUserSessions = Get-LoggedOnUser
    [String[]]$usersLoggedOn = $LoggedOnUserSessions | ForEach-Object { $_.NTAccount }

    If ($usersLoggedOn) {
        #  Get account and session details for the logged on user session that the current process is running under. Note that the account used to execute the current process may be different than the account that is logged into the session (i.e. you can use "RunAs" to launch with different credentials when logged into an account).
        [PSObject]$CurrentLoggedOnUserSession = $LoggedOnUserSessions | Where-Object { $_.IsCurrentSession }

        #  Get account and session details for the account running as the console user (user with control of the physical monitor, keyboard, and mouse)
        [PSObject]$CurrentConsoleUserSession = $LoggedOnUserSessions | Where-Object { $_.IsConsoleSession }

        ## Determine the account that will be used to execute commands in the user session when toolkit is running under the SYSTEM account
        #  If a console user exists, then that will be the active user session.
        #  If no console user exists but users are logged in, such as on terminal servers, then the first logged-in non-console user that is either 'Active' or 'Connected' is the active user.
        [PSObject]$RunAsActiveUser = $LoggedOnUserSessions | Where-Object { $_.IsActiveUserSession }
    }
}

Env:\PUBLIC

[ScriptBlock]$GetLoggedOnUserTempPath = {
    # When running in system context we can derive the native "C:\Users" base path from the Public environment variable
    [String]$dirUserProfile = Split-path $Env:\PUBLIC -ErrorAction 'SilentlyContinue'
    If ($null -ne $RunAsActiveUser.NTAccount) {
        [String]$userProfileName = $RunAsActiveUser.UserName
        If (Test-Path (Join-Path -Path $dirUserProfile -ChildPath $userProfileName -ErrorAction 'SilentlyContinue')) {
            [String]$runasUserProfile = Join-Path -Path $dirUserProfile -ChildPath $userProfileName -ErrorAction 'SilentlyContinue'
            [String]$loggedOnUserTempPath = Join-Path -Path $runasUserProfile -ChildPath (Join-Path -Path $appDeployToolkitName -ChildPath 'ExecuteAsUser')
            If (-not (Test-Path -LiteralPath $loggedOnUserTempPath -PathType 'Container' -ErrorAction 'SilentlyContinue')) {
                $null = New-Item -Path $loggedOnUserTempPath -ItemType 'Directory' -Force -ErrorAction 'SilentlyContinue'
            }
        }
    }
    Else {
        [String]$loggedOnUserTempPath = Join-Path -Path $dirAppDeployTemp -ChildPath 'ExecuteAsUser'
    }
}

. $GetLoggedOnUserDetails
. $GetLoggedOnUserTempPath

#$RunAsActiveUser.NTAccount
Execute-ProcessAsUser  -Path "C:\Temp\Popup.exe" -Wait -RunLevel HighestAvailable

# Get-LoggedOnUser 

