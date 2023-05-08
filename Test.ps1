
Function Get-LoggedOnUser {

    [CmdletBinding()]
    Param (
    )

    Begin {
        ## Get the name of this function and write header
        #[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        Try {
        
            Write-Output -InputObject ([PSADT.QueryUser]::GetUserSessionInfo("$env:ComputerName"))
        }
        Catch {
            Write-Error -Message "Failed to get session information for all logged on users.  "
        }
    }
    End {
       # Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}


Function Execute-ProcessAsUser {
 
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
        # [Parameter(Mandatory = $false)]
        # [ValidateSet('HighestAvailable', 'LeastPrivilege')]
        # [String]$RunLevel = 'HighestAvailable',
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
        #[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header

        #If ((![string]::IsNullOrEmpty($tempPath))) {
            #$executeAsUserTempPath = $tempPath
            #If (($tempPath -eq $loggedOnUserTempPath) -and ($RunLevel -eq "HighestPrivilege")) {
                #\Write-Log -Message "WARNING: Using [${CmdletName}] with a user writable directory using the HighestPrivilege creates a security vulnerability. Please use -RunLevel 'LeastPrivilege' when using a user writable directoy." -Severity 'Warning'
            #}
        #}
        #Else {
            #[String]$executeAsUserTempPath = Join-Path -Path $dirAppDeployTemp -ChildPath 'ExecuteAsUser'
        #}
    }
    Process {
        ## Initialize exit code variable
        [Int32]$executeProcessAsUserExitCode = 0

        ## Confirm that the username field is not empty
        If (-not $UserName) {
            [Int32]$executeProcessAsUserExitCode = 60009
            #Write-Log -Message "The function [${CmdletName}] has a -UserName parameter that has an empty default value because no logged in users were detected when the toolkit was launched." -Severity 3 -Source ${CmdletName}
            #If (-not $ContinueOnError) {
                #Throw "The function [${CmdletName}] has a -UserName parameter that has an empty default value because no logged in users were detected when the toolkit was launched."
            #}
            Return
        }

        ## Confirm if the toolkit is running with administrator privileges
        If (($RunLevel -eq 'HighestAvailable') -and (-not $IsAdmin)) {
            [Int32]$executeProcessAsUserExitCode = 60003
            #Write-Log -Message "The function [${CmdletName}] requires the toolkit to be running with Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'." -Severity 3 -Source ${CmdletName}
            # If (-not $ContinueOnError) {
            #     Throw "The function [${CmdletName}] requires the toolkit to be running with Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'."
            # }
            Return
        }

        ## Check whether the specified Working Directory exists
        If ($WorkingDirectory -and (-not (Test-Path -LiteralPath $WorkingDirectory -PathType 'Container'))) {
            #Write-Log -Message 'The specified working directory does not exist or is not a directory. The scheduled task might not work as expected.' -Severity 2 -Source ${CmdletName}
        }

        ## Build the scheduled task XML name
        [String]$schTaskName = (("$appDeployToolkitName-ExecuteAsUser" -replace ' ', '').Trim('_') -replace '[_]+', '_')

        ##  Remove and recreate the temporary folder
        If (Test-Path -LiteralPath $executeAsUserTempPath -PathType 'Container') {
            #Write-Log -Message "Previous [$executeAsUserTempPath] found. Attempting removal." -Source ${CmdletName}
            Remove-Folder -Path $executeAsUserTempPath
        }
        #Write-Log -Message "Creating [$executeAsUserTempPath]." -Source ${CmdletName}
        Try {
            $null = New-Item -Path $executeAsUserTempPath -ItemType 'Directory' -ErrorAction 'Stop'
        }
        Catch {
            #Write-Log -Message "Unable to create [$executeAsUserTempPath]. Possible attempt to gain elevated rights." -Source ${CmdletName} -Severity 2
        }

        ## Escape XML characters
        $EscapedPath = [System.Security.SecurityElement]::Escape($Path)
        $EscapedParameters = [System.Security.SecurityElement]::Escape($Parameters)

        ## If PowerShell.exe is being launched, then create a VBScript to launch PowerShell so that we can suppress the console window that flashes otherwise
        If (((Split-Path -Path $Path -Leaf) -like 'PowerShell*') -or ((Split-Path -Path $Path -Leaf) -like 'cmd*')) {
            If ($SecureParameters) {
                #Write-Log -Message "Preparing a VBScript that will start [$Path] (Parameters Hidden) as the logged-on user [$userName] and suppress the console window..." -Source ${CmdletName}
            }
            Else {
                #Write-Log -Message "Preparing a VBScript that will start [$Path $Parameters] as the logged-on user [$userName] and suppress the console window..." -Source ${CmdletName}
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
            $Path = "$env:windir\System32\wscript.exe"
            $Parameters = "/e:vbscript `"$executeAsUserTempPath\$($schTaskName).vbs`""
            $EscapedPath = [System.Security.SecurityElement]::Escape($Path)
            $EscapedParameters = [System.Security.SecurityElement]::Escape($Parameters)

            Try {
                Set-ItemPermission -Path "$executeAsUserTempPath\$schTaskName.vbs" -User $UserName -Permission 'Read'
            }
            Catch {
                #Write-Log -Message "Failed to set read permissions on path [$executeAsUserTempPath\$schTaskName.vbs]. The function might not be able to work correctly." -Source ${CmdletName} -Severity 2
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
            #Write-Log -Message "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
            # If (-not $ContinueOnError) {
            #     Throw "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]: $($_.Exception.Message)"
            # }
            Return
        }

        ## Create Scheduled Task to run the process with a logged-on user account
        # If ($Parameters) {
        #     If ($SecureParameters) {
        #         Write-Log -Message "Creating scheduled task to run the process [$Path] (Parameters Hidden) as the logged-on user [$userName]..." -Source ${CmdletName}
        #     }
        #     Else {
        #         Write-Log -Message "Creating scheduled task to run the process [$Path $Parameters] as the logged-on user [$userName]..." -Source ${CmdletName}
        #     }
        # }
        # Else {
        #     Write-Log -Message "Creating scheduled task to run the process [$Path] as the logged-on user [$userName]..." -Source ${CmdletName}
        # }
        [PSObject]$schTaskResult = Execute-Process -Path $exeSchTasks -Parameters "/create /f /tn $schTaskName /xml `"$xmlSchTaskFilePath`"" -WindowStyle 'Hidden' -CreateNoWindow -PassThru -ExitOnProcessFailure $false
        If ($schTaskResult.ExitCode -ne 0) {
            [Int32]$executeProcessAsUserExitCode = $schTaskResult.ExitCode
            #Write-Log -Message "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]." -Severity 3 -Source ${CmdletName}
            # If (-not $ContinueOnError) {
            #     Throw "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]."
            # }
            Return
        }

        ## Trigger the Scheduled Task
        # If ($Parameters) {
        #     If ($SecureParameters) {
        #         Write-Log -Message "Triggering execution of scheduled task with command [$Path] (Parameters Hidden) as the logged-on user [$userName]..." -Source ${CmdletName}
        #     }
        #     Else {
        #         Write-Log -Message "Triggering execution of scheduled task with command [$Path $Parameters] as the logged-on user [$userName]..." -Source ${CmdletName}
        #     }
        # }
        # Else {
        #     Write-Log -Message "Triggering execution of scheduled task with command [$Path] as the logged-on user [$userName]..." -Source ${CmdletName}
        # }
        [PSObject]$schTaskResult = Execute-Process -Path $exeSchTasks -Parameters "/run /i /tn $schTaskName" -WindowStyle 'Hidden' -CreateNoWindow -Passthru -ExitOnProcessFailure $false
        If ($schTaskResult.ExitCode -ne 0) {
            [Int32]$executeProcessAsUserExitCode = $schTaskResult.ExitCode
            #Write-Log -Message "Failed to trigger scheduled task [$schTaskName]." -Severity 3 -Source ${CmdletName}
            #  Delete Scheduled Task
            #Write-Log -Message 'Deleting the scheduled task which did not trigger.' -Source ${CmdletName}
            Execute-Process -Path $exeSchTasks -Parameters "/delete /tn $schTaskName /f" -WindowStyle 'Hidden' -CreateNoWindow -ExitOnProcessFailure $false
            # If (-not $ContinueOnError) {
            #     Throw "Failed to trigger scheduled task [$schTaskName]."
            # }
            Return
        }

        ## Wait for the process launched by the scheduled task to complete execution
        If ($Wait) {
            #Write-Log -Message "Waiting for the process launched by the scheduled task [$schTaskName] to complete execution (this may take some time)..." -Source ${CmdletName}
            Start-Sleep -Seconds 1
            #If on Windows Vista or higer, Windows Task Scheduler 2.0 is supported. 'Schedule.Service' ComObject output is UI language independent
            #If (([Version]$envOSVersion).Major -gt 5) {
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
                    #Write-Log -Message "Failed to retrieve information from Task Scheduler. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                }
                Finally {
                    Try {
                        $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($ScheduleService)
                    }
                    Catch {
                    }
                }
            #}
            #Windows Task Scheduler 1.0
            #Else {
                # While ((($exeSchTasksResult = & $exeSchTasks /query /TN $schTaskName /V /FO CSV) | ConvertFrom-Csv | Select-Object -ExpandProperty 'Status' -First 1) -eq 'Running') {
                #     Start-Sleep -Seconds 5
                # }
                # #  Get the exit code from the process launched by the scheduled task
                # [Int32]$executeProcessAsUserExitCode = ($exeSchTasksResult = & $exeSchTasks /query /TN $schTaskName /V /FO CSV) | ConvertFrom-Csv | Select-Object -ExpandProperty 'Last Result' -First 1
            #}
            # Write-Log -Message "Exit code from process launched by scheduled task [$executeProcessAsUserExitCode]." -Source ${CmdletName}
        }
        Else {
            Start-Sleep -Seconds 1
        }

        ## Delete scheduled task
        Try {
            #Write-Log -Message "Deleting scheduled task [$schTaskName]." -Source ${CmdletName}
            Execute-Process -Path $exeSchTasks -Parameters "/delete /tn $schTaskName /f" -WindowStyle 'Hidden' -CreateNoWindow -ErrorAction 'Stop'
        }
        Catch {
            #Write-Log -Message "Failed to delete scheduled task [$schTaskName]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
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

       
    }
}
 


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

. $GetLoggedOnUserDetails

If (-not ([Management.Automation.PSTypeName]'PSADT.UiAutomation').Type) {
    [String[]]$ReferencedAssemblies = 'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
    Add-Type -Path "C:\Users\jmore\Documents\GitHub\PowerShell\AppDeployToolkitMain.cs" -ReferencedAssemblies $ReferencedAssemblies -IgnoreWarnings -ErrorAction 'Stop'
}


