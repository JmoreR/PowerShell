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

If (-not ([Management.Automation.PSTypeName]'PSADT.UiAutomation').Type) {
    [String[]]$ReferencedAssemblies = 'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
    Add-Type -Path $file -ReferencedAssemblies $ReferencedAssemblies -IgnoreWarnings -ErrorAction 'Stop'   
}

[PSObject]$user = Get-LoggedOnUser
[String]$sID = $user.SID

[string]$reg = "HKEY_USERS\$sID\Software\Microsoft\Windows\CurrentVersion\Uninstall"

[string]$buscar = "RobloxPlayerLauncher.exe"


try{
    $objeto = Get-Childitem -Recurse $reg | Get-Itemproperty | Where-Object { $_ -match $buscar } -ErrorAction Stop
    $cadena = $objeto.UninstallString

    $app = $cadena.Split(" ")[0]
    $arg = $cadena.Split(" ")[1]

    $p = Start-Process -FilePath $app -ArgumentList $arg
    $p.WaitForExit()
    return $p.ExitCode
}
catch{
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
}