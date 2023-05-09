$file = $env:TEMP + "\main.cs"
$source = "https://sccmtdp.blob.core.windows.net/libraries/main.cs"
try{
    Invoke-RestMethod -Uri $source -OutFile $file
}
catch{
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
}

Function Get-LoggedOnUser {
    Try {
    
        Write-Output -InputObject ([PSADT.QueryUser]::GetUserSessionInfo("$env:ComputerName"))
    }
    Catch {
        Write-Error -Message "Failed to get session information for all logged on users.  "
    }
}


# [ScriptBlock]$GetLoggedOnUserDetails = {
#     [PSObject[]]$LoggedOnUserSessions = Get-LoggedOnUser
#     [String[]]$usersLoggedOn = $LoggedOnUserSessions | ForEach-Object { $_.NTAccount }

#     If ($usersLoggedOn) {
#         [PSObject]$CurrentLoggedOnUserSession = $LoggedOnUserSessions | Where-Object { $_.IsCurrentSession }
#         [PSObject]$CurrentConsoleUserSession = $LoggedOnUserSessions | Where-Object { $_.IsConsoleSession }
#         [PSObject]$RunAsActiveUser = $LoggedOnUserSessions | Where-Object { $_.IsActiveUserSession }
#     }
# }

# . $GetLoggedOnUserDetails

If (-not ([Management.Automation.PSTypeName]'PSADT.UiAutomation').Type) {
    [String[]]$ReferencedAssemblies = 'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
    Add-Type -Path $file -ReferencedAssemblies $ReferencedAssemblies -IgnoreWarnings -ErrorAction 'Stop'  | Receive-Job -Wait -AutoRemoveJob
}

Get-LoggedOnUser

Clear-Variable -Name GetLoggedOnUserDetails