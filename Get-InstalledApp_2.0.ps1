# Work in progress
function Get-InstalledApp {
[CmdletBinding()]
Param (
        [switch]$WMI,
        [switch]$Registry,
        [switch]$File
        )

 DynamicParam {
 $switches0 = @($WMI,$Registry) 
If ($switches0 -contains $true) {
    $SubAttribute0 = New-Object System.Management.Automation.ParameterAttribute
    $SubAttribute1 = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute
    $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    $attributeCollection = new-object System.Collections.ObjectModel.Collection[System.Attribute]
    $attributeCollection.Add($SubAttribute0) ; $attributeCollection.Add($SubAttribute1)
    $PAC1 = New-Object System.Management.Automation.RuntimeDefinedParameter('AppName',    [string], $attributeCollection)
    $PAC2 = New-Object System.Management.Automation.RuntimeDefinedParameter('AppVersion', [string], $attributeCollection)
    $paramDictionary.Add('AppName', $PAC1)
    $paramDictionary.Add('AppVersion', $PAC2)
    }

if ($File) {
    $SubAttribute2 = New-Object System.Management.Automation.ParameterAttribute
    $SubAttribute3 = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute
    $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    $attributeCollection = new-object System.Collections.ObjectModel.Collection[System.Attribute]
    $attributeCollection.Add($SubAttribute2) ; $attributeCollection.Add($SubAttribute3)
    $PAC3 = New-Object System.Management.Automation.RuntimeDefinedParameter('FilePath',    [string], $attributeCollection)
    $PAC4 = New-Object System.Management.Automation.RuntimeDefinedParameter('FileVersion', [string], $attributeCollection)
    $paramDictionary.Add('FilePath', $PAC3)
    $paramDictionary.Add('FileVersion', $PAC4)
    } 

    return $paramDictionary 

}

process {

#Messages for error handling
$ExceptionMessage0  = 'Please select one or more switches: WMI, Registry or File'
$ExceptionMessage1  = 'Please provide values for both -AppName and -AppVersion parameters'
$ExceptionMessage2  = 'Please provide values for both -FilePath and -FileVersion parameters'

$switches1 = @($WMI,$Registry,$File) ; If ($switches1 -notcontains $true) {Write-Error $ExceptionMessage0 ; Return }

$Objects     = New-Object -TypeName psobject
$AppName     = $PSBoundParameters.AppName
$AppVersion  = $PSBoundParameters.AppVersion
$FilePath    = $PSBoundParameters.FilePath
$FileVersion = $PSBoundParameters.FileVersion

if ($WMI -or $Registry) { 
If ([string]::IsNullOrWhiteSpace($AppName) -or [string]::IsNullOrWhiteSpace($AppVersion)) {Write-Error $ExceptionMessage1;Return}
$Objects | Add-Member -MemberType NoteProperty -Name Name        -Value $AppName | Out-Null
$Objects | Add-Member -MemberType NoteProperty -Name Version     -Value $AppVersion | Out-Null 
}

if ($File){ 
If ([string]::IsNullOrWhiteSpace($FilePath) -or [string]::IsNullOrWhiteSpace($FileVersion)) {Write-Error $ExceptionMessage2;Return}
$Objects | Add-Member -MemberType NoteProperty -Name FilePath    -Value $FilePath
$Objects | Add-Member -MemberType NoteProperty -Name FileVersion -Value $FileVersion }

# WMI search 
if ($WMI) {

$WMI_Installed      =   Get-WmiObject -Namespace 'root\cimv2\sms' -Class SMS_InstalledSoftware | 
                        Where {($_.ARPDisplayName -eq "$AppName") -and ($_.ProductVersion -eq "$AppVersion") }
if ($WMI_Installed)     {$WMIFound    = $true} else {$WMIFound    = $false}
                        $Objects | Add-Member -MemberType NoteProperty -Name WMI -Value $WMIFound
} # End WMI search

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

$Results = @($WMIFound,$Regx64,$Regx32,$FileB) 
if ($Results -contains $true) {$Found  = $true} else {$Found  = $false}
$Objects | Add-Member -MemberType NoteProperty -Name Found -Value $Found

$objects #Output results as objects

}


}

# TEST AREA
    $ApplicationName        = 'Notepad++'
    $ApplicationVersion     = '6.9.2'
    $ApplicationFilePath    = 'C:\Program Files (x86)\Notepad++\notepad++.exe'
    $ApplicationFileVersion = '6.92'


    Get-InstalledApp -WMI -AppName $ApplicationName -AppVersion $ApplicationVersion -File -FilePath $ApplicationFilePath -FileVersion $ApplicationFileVersion
