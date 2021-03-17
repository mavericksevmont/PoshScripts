function Invoke-SystemAccount {
<# Run PowerShell command or script as System Account by taking advantage of Scheduled tasks
e.g. 
$Command  = { whoami >> 'C:\Users\marcossevilla\Documents\Test 1\OutputTest.txt'}
# $Command = "[Security.Principal.WindowsIdentity]::GetCurrent() | out-file 'C:\Users\marcossevilla\Documents\Test 1\ServiceProcessBios.txt'  ; get-process | out-file 'C:\Users\marcossevilla\Documents\Test 1\ServiceProcessBios.txt' -Append"
$File = 'C:\Users\marcossevilla\Documents\Test 1\Script.ps1'
Invoke-SystemAccount -Command $Command
Invoke-SystemAccount -File $File

#>
[CmdletBinding()]
    param(  
    [Parameter(ParameterSetName='Com', Position=0)]$Command,
    [Parameter(ParameterSetName='Fil', Position=0)]$File              
                )

if ($Command) {$argument = "-ExecutionPolicy ByPass -NoExit -Command &{$Command}"}
if ($File)    {$argument = "-ExecutionPolicy ByPass -NoExit -File    `"$File`""  }

    $taskname  = "Invoke-SystemAccount"
    $action    = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument $argument
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $trigger   = New-ScheduledTaskTrigger -Once -At '0:00'
    $task      = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger

                 Register-ScheduledTask   -TaskName $taskname  -InputObject $task -Force | Out-Null
                 Start-ScheduledTask      -TaskName $taskname | Out-Null
                 Unregister-ScheduledTask -TaskName $taskname -Confirm:$false | Out-Null

}

