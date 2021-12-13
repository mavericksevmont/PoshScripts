# Log4j Microsoft Windows PowerShell    
# Find Log4j library instances in all Windows OS Drives and Directories
#  Requires Warren F's Invoke-Parallel.ps1 https://github.com/mavericksevmont/Invoke-Parallel
$Cred = Get-Credential
$Hosts = Get-Content $PSScriptRoot\Hosts.txt
Import-Module $PSScriptRoot\Invoke-Parallel.ps1 # Get this script and add it to same directory: https://github.com/mavericksevmont/Invoke-Parallel

$Hosts | Invoke-Parallel -ScriptBlock {

Invoke-Command -ComputerName $_ -ScriptBlock {
get-psdrive -PSProvider "FileSystem" | 
% {$Drive = $_.Root ; Get-ChildItem $Drive -Include *log4j*.jar* -Recurse -ErrorAction SilentlyContinue} | 
select @{n='Server';e={$env:COMPUTERNAME}},BaseName,Directory,CreationTimeUtc,LastAccessTimeUtc,LastWriteTimeUtc
} -Credential $Cred

} -OutVariable Results -ImportVariables

$Results | Export-csv $PSScriptRoot\Resultslog4.csv -Force -NoTypeInformation
