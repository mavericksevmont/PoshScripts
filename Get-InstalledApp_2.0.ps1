# Work in progress
function Get-InstalledApp {
[CmdletBinding()]
Param (
        [switch]$WMI,
        [switch]$Registry,
        [switch]$File )

 DynamicParam {

if ($WMI -or $Registry) {
    $SubAttribute = New-Object System.Management.Automation.ParameterAttribute
    #$SubAttribute.Mandatory = $false ; $SubAttribute.Position = 1
    $SubAttribute1 = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute

    $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    $attributeCollection = new-object System.Collections.ObjectModel.Collection[System.Attribute]
    $attributeCollection.Add($SubAttribute) ; $attributeCollection.Add($SubAttribute1)
    $PAC1 = New-Object System.Management.Automation.RuntimeDefinedParameter('AppName',    [string], $attributeCollection)
    $PAC2 = New-Object System.Management.Automation.RuntimeDefinedParameter('AppVersion', [string], $attributeCollection)
    $paramDictionary.Add('AppName', $PAC1)
    $paramDictionary.Add('AppVersion', $PAC2)
    }


if ($File) {
    $SubAttribute = New-Object System.Management.Automation.ParameterAttribute
    $SubAttribute1 = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute
    $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    $attributeCollection = new-object System.Collections.ObjectModel.Collection[System.Attribute]
    $attributeCollection.Add($SubAttribute) ; $attributeCollection.Add($SubAttribute1)
    $PAC3 = New-Object System.Management.Automation.RuntimeDefinedParameter('FilePath',    [string], $attributeCollection)
    $PAC4 = New-Object System.Management.Automation.RuntimeDefinedParameter('FileVersion', [string], $attributeCollection)
    $paramDictionary.Add('FilePath', $PAC3)
    $paramDictionary.Add('FileVersion', $PAC4)
    } 

    return $paramDictionary 

}

process {

$AppName     = $PSBoundParameters.AppName
$AppVersion  = $PSBoundParameters.AppVersion
$FilePath    = $PSBoundParameters.FilePath
$FileVersion = $PSBoundParameters.FileVersion

# Parameter error handling
$ExceptionMessage1  = "Please provide values for both -AppName and -AppVersion parameters"
$ExceptionMessage2  = "Please provide values for both -FilePath and -FileVersion parameters"
if ($AppName     -and ($AppVersion  -eq $null) ) {Write-Error $ExceptionMessage1; return}
if ($AppVersion  -and ($AppName     -eq $null) ) {Write-Error $ExceptionMessage1; return}
if ($FileVersion -and ($FilePath    -eq $null) ) {Write-Error $ExceptionMessage2; return}
if ($FilePath    -and ($FileVersion -eq $null) ) {Write-Error $ExceptionMessage2; return}

$Objects = New-Object -TypeName psobject

if ($AppName) { $Objects | Add-Member -MemberType NoteProperty -Name Name        -Value $AppName
                $Objects | Add-Member -MemberType NoteProperty -Name Version     -Value $AppVersion }
if ($FilePath){ $Objects | Add-Member -MemberType NoteProperty -Name FilePath    -Value $FilePath
                $Objects | Add-Member -MemberType NoteProperty -Name FileVersion -Value $FileVersion }
# WMI search 
if ($WMI) {

$WMI_Installed      =   Get-WmiObject -Namespace 'root\cimv2\sms' -Class SMS_InstalledSoftware | 
                        Where {($_.ARPDisplayName -eq "$AppName") -and ($_.ProductVersion -eq "$AppVersion") }
if ($WMI_Installed)     {$WMIFound    = $true} else {$WMIFound    = $false}
                        $Objects | Add-Member -MemberType NoteProperty -Name WMI -Value $WMIFound
} # End WMI

# Registry key paths and search
if ($Registry) {

$X64UninstallRegKey =  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$X32UninstallRegKey =  'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
$x64IntallerRegKeys =   Get-ChildItem -Path $X64UninstallRegKey
$x32IntallerRegKeys =   Get-ChildItem -Path $X32UninstallRegKey
$Regx64_Installed   =   $x64IntallerRegKeys | 
                        Where { ($_.GetValue('DisplayName') -eq "$AppName") -and ($_.GetValue('DisplayVersion') -eq "$AppVersion")}
$Regx32_Installed   =   $x32IntallerRegKeys | 
                        Where { ($_.GetValue('DisplayName') -eq "$AppName") -and ($_.GetValue('DisplayVersion') -eq "$AppVersion")}

if ($Regx64_Installed) {$Regx64 = $true} else {$Regx64 = $false}
if ($Regx32_Installed) {$Regx32 = $true} else {$Regx32 = $false}
$Objects | Add-Member -MemberType NoteProperty -Name Regx64 -Value $Regx64
$Objects | Add-Member -MemberType NoteProperty -Name Regx32 -Value $Regx32

} # End Reg

# Filepath search
if ($File)  {
                        $FoundFile      = try {Get-ItemProperty $FilePath -ErrorAction Stop} catch {$FoundFile = $null}
                        $FoundVersion   = $FoundFile.VersionInfo.FileVersion
                        if ($FoundFile -and ($FileVersion -eq $FoundVersion) ) 
                        {$FileB = $true} else {$FileB = $false}
                        $Objects | Add-Member -MemberType NoteProperty -Name FilePathFound -Value $FileB 
                        } else {$FileB = $null} # end filepath search logic


if ($WMI -or $Regx64 -or $Regx32 -or $FileB) {$Found  = $true} else {$Found  = $false}
$Objects | Add-Member -MemberType NoteProperty -Name Found -Value $Found 

$objects

}


}




# TEST AREA
    $ApplicationName        = 'Notepad++'
    $ApplicationVersion     = '6.9.2'
    $ApplicationFilePath    = 'C:\Program Files (x86)\Notepad++\notepad++.exe'
    $ApplicationFileVersion = '6.92'


Get-InstalledApp -AppName $ApplicationName -AppVersion $ApplicationVersion -FilePath $ApplicationFilePath -FileVersion $ApplicationFileVersion
Get-InstalledApp -WMI -AppName $ApplicationName -AppVersion $ApplicationVersion 
Get-InstalledApp -Registry -AppName $ApplicationName -AppVersion $ApplicationVersion
Get-InstalledApp -File -FilePath $ApplicationFilePath -FileVersion $ApplicationFileVersion

Get-InstalledApp -WMI -Registry -AppName #  -File -FilePath $ApplicationFilePath -FileVersion $ApplicationFileVersion

Get-InstalledApp -WMI -Registry -AppName $ApplicationName -AppVersion $ApplicationVersion -File -FilePath $ApplicationFilePath -FileVersion $ApplicationFileVersion

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


