Function Get-InstalledApp {
#requires -version 5.1

<#
.SYNOPSIS
    Search for a specific installed application version with wmi, registry keys and filepath.
.DESCRIPTION
    Find a specific application with fileversion by using wmi, reg key search and by filepath.
.PARAMETER <AppName>
    Specify the Application's name (ARPDisplayName) to be found. If using, the Appversion parameter is mandatory.
.PARAMETER <AppVersion>
    Specify the version number (DisplayVersion) of the file to be found. If using, the AppName parameter is mandatory.
.PARAMETER <FilePath>
    Specify the file's full path for the application to check if it exists. If using, the FileVersion parameter is mandatory.
.PARAMETER <FileVersion>
    Specify the version to the application file to check if it exists. If using, the FilePath parameter is mandatory.
  
.EXAMPLE
    $ApplicationName        = 'Notepad++'
    $ApplicationVersion     = '6.9.2'
    $ApplicationFilePath    = 'C:\Program Files (x86)\Notepad++\notepad++.exe'
    $ApplicationFileVersion = '6.92'

    Get-InstalledApp -AppName $ApplicationName -AppVersion $ApplicationVersion
    Get-InstalledApp -FilePath $ApplicationFilePath -FileVersion $ApplicationFileVersion
    Get-InstalledApp -AppName $ApplicationName -AppVersion $ApplicationVersion -FilePath $ApplicationFilePath -FileVersion $ApplicationFileVersion

OUTPUT EXAMPLE:

    Name          : Notepad++
    Version       : 6.9.2
    FilePath      : C:\Program Files (x86)\Notepad++\notepad++.exe
    FileVersion   : 6.92
    Found         : True
    WMI           : True
    Regx64        : False
    Regx32        : True
    FilePathFound : True

.NOTES
    Version:        1.0
    Authors:        Erick Sevilla & John Murillo
    Creation Date:  March/09/2021
    Purpose/Change: Initial script development

#>

        [CmdletBinding()]
        param(  [ValidateNotNullOrEmpty()]$AppName,
                [ValidateNotNullOrEmpty()]$AppVersion, 
                $FilePath = $null,
                $FileVersion = $null               
                )

# Parameter error handling
$ExceptionMessage1  = "Please provide values for both -AppName and -AppVersion parameters"
$ExceptionMessage2  = "Please provide values for both -FilePath and -FileVersion parameters"
if ($AppName     -and ($AppVersion  -eq $null) ) {Write-Error $ExceptionMessage1; return}
if ($AppVersion  -and ($AppName     -eq $null) ) {Write-Error $ExceptionMessage1; return}
if ($FileVersion -and ($FilePath    -eq $null) ) {Write-Error $ExceptionMessage2; return}
if ($FilePath    -and ($FileVersion -eq $null) ) {Write-Error $ExceptionMessage2; return}

# Registry key paths and search
$X64UninstallRegKey =  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$X32UninstallRegKey =  'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
$x64IntallerRegKeys =   Get-ChildItem -Path $X64UninstallRegKey
$x32IntallerRegKeys =   Get-ChildItem -Path $X32UninstallRegKey

# WMI search 
$WMI_Installed      =   Get-WmiObject -Namespace 'root\cimv2\sms' -Class SMS_InstalledSoftware | 
                        Where {($_.ARPDisplayName -eq "$AppName") -and ($_.ProductVersion -eq "$AppVersion") }
$Regx64_Installed   =   $x64IntallerRegKeys | 
                        Where { ($_.GetValue('DisplayName') -eq "$AppName") -and ($_.GetValue('DisplayVersion') -eq "$AppVersion")}
$Regx32_Installed   =   $x32IntallerRegKeys | 
                        Where { ($_.GetValue('DisplayName') -eq "$AppName") -and ($_.GetValue('DisplayVersion') -eq "$AppVersion")}
# Filepath search
if ($FilePath)  {
                        $FoundFile      = try {Get-ItemProperty $FilePath -ErrorAction Stop} catch {$FoundFile = $null}
                        $FoundVersion   = $FoundFile.VersionInfo.FileVersion
                        if ($FoundFile -and ($FileVersion -eq $FoundVersion) ) 
                        {$File = $true} else {$File = $false}  } else {$File = $null} # end filepath search logic

# Result values conditional logic
        if ($WMI_Installed)                         {$WMI    = $true} else {$WMI    = $false}
        if ($Regx64_Installed)                      {$Regx64 = $true} else {$Regx64 = $false}
        if ($Regx32_Installed)                      {$Regx32 = $true} else {$Regx32 = $false}
        if ($WMI -or $Regx64 -or $Regx32 -or $File) {$Found  = $true} else {$Found  = $false}

# Hashtable object properties for output
[pscustomobject] @{
            Name             = $AppName
            Version          = $AppVersion
            FilePath         = $FilePath
            FileVersion      = $FileVersion
            Found            = $Found
            WMI              = $WMI
            Regx64           = $Regx64
            Regx32           = $Regx32
            FilePathFound    = $File 

    } # End Hashtable
   

}
