function Test-ElevatedPrivileges {
    [CmdletBinding()]
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    If (-Not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Not running with elevated privileges"
    }
}

function Register-DefaultPSRepository {
    If ($null -eq (Get-PSRepository -Name "PSGallery")) {
        If (((Get-Host).Version).Major -gt 5) {
            Register-PSRepository -Default -InstallationPolicy Trusted
        }
        Else {
            Register-PSRepository -Name PSGallery -SourceLocation https://www.powershellgallery.com/api/v2/ -InstallationPolicy Trusted
        }
    }
    If ((Get-PSRepository -Name "PSGallery").InstallationPolicy -ne "Trusted") {
        Set-PSRepository -Name "PSGallery" -InstallationPolicy "Trusted"
    }
}

function Remove-WindowsHelloPin {
    CheckForAdmin
    takeown /f C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc /r /d y >nul
    $acl = Get-Acl -Path "C:\Users"
    $sysRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
    $admRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")
    
    $acl.SetAccessRule($sysRule)
    $acl.AddAccessRule($admRule)
    
    Get-ChildItem -Path "C:\WINDOWS\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" -Recurse -Force | Set-Acl ($acl)
    
    Remove-Item -Path "C:\WINDOWS\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" -Recurse -Force
}

function Set-LAPSPassword {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$PCName
    )

    $password = get-adcomputer $PCName -properties * | Select-Object ms-mcs-a*
    $ExpirationTime = w32tm -ntte $password.'ms-Mcs-AdmPwdExpirationTime'
    Write-Host "Password:" $password.'ms-Mcs-AdmPwd'
    Write-host "Expiration:" $ExpirationTime
}

function Install-WinGet {
    $WingetUrl = "https://github.com/microsoft/winget-cli/releases/"
    If (($null -eq (Get-AppxPackage "Microsoft.UI.Xaml.2.7*" -AllUsers)) -and ($null -eq (Get-AppxPackage "Microsoft.UI.Xaml.2.8*" -AllUsers))) {
        Write-Host "Downloading Microsoft UI XAML..."
        Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml" -OutFile ($env:TEMP + "xaml.zip")
        Expand-Archive -LiteralPath ($AdminPath + "xaml.zip") -DestinationPath ($env:TEMP + "xaml")
        Add-AppxPackage ($env:TEMP + "xaml\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.8.appx") -AllUsers
    }
    Write-Host "Downloading Package Manager..."
    $WingetVersion = [System.Net.WebRequest]::Create($WingetUrl + "latest").GetResponse().ResponseUri.OriginalString.split('/')[-1].Trim('v')
    Invoke-WebRequest -Uri ($WingetUrl + "download/v" + $WingetVersion + "/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle") -OutFile ($env:TEMP + "winget.msixbundle")
    Add-AppxPackage ($env:TEMP + "winget.msixbundle")
}

function Install-AdminTools {
    Register-DefaultPSRepository
    Install-WinGet
}