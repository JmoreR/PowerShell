Param
(
    [Parameter(Mandatory = $true)]
    [String]$app = "roblox"
)


Get-Process  | Where-Object  {$_.ProcessName -like "$app*"} | Stop-Process -Force 

function RemoveItem {
    param (
        [psobject]$user,
        [string]$path
    )
    $var = "$($user.fullname)$path"

    If (Test-Path $var) {
         Remove-Item -Path "$var" -Force -Recurse -ErrorAction SilentlyContinue 
    }
}

$Users = Get-ChildItem C:\Users
foreach ($user in $Users){
 
    RemoveItem -user $user -path "\AppData\Local\$app"
    RemoveItem -user $user -path "\AppData\Roaming\$app"
    RemoveItem -user $user -path "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\$app"
    RemoveItem -user $user -path "\Desktop\$app*.lnk"
   # RemoveItem -user $user -path "\Desktop\Roblox Studio.lnk"

}

[PSObject]$objeto = (Get-Childitem -Recurse "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"  | Where-Object { $_.Name -match "S-1-5-21" } | Get-Itemproperty | Where-Object { $_.PSChildName -match "S-1-5-21" }) 

$objeto.PSChildName | ForEach-Object {"Registry::HKEY_USERS\" +  $_ + "\Software\Microsoft\Windows\CurrentVersion\Uninstall\$app*"} | Remove-Item -Recurse -ErrorAction SilentlyContinue


 