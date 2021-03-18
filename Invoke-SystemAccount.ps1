function Invoke-SystemAccount {

<# Run PowerShell command or script as System Account by taking advantage of Scheduled tasks
e.g. 
$Command  = { whoami >> 'C:\Users\marcossevilla\Documents\Test 1\OutputTest.txt'}
# $Command = "[Security.Principal.WindowsIdentity]::GetCurrent() | out-file 'C:\Users\marcossevilla\Documents\Test 1\ServiceProcessBios.txt'  ; get-process | out-file 'C:\Users\marcossevilla\Documents\Test 1\ServiceProcessBios.txt' -Append"
$File = 'C:\Users\marcossevilla\Documents\Test 1\Script.ps1'
Invoke-SystemAccount -Command $Command
Invoke-SystemAccount -File $File
The following runs PowerShell as 32-bit, if switch is not set, it runs default as x64
Invoke-SystemAccount -File $File -x32
#>

[CmdletBinding()]
    param(  
            [Parameter(ParameterSetName='Com', Position=0)]$Command,
            [Parameter(ParameterSetName='Fil', Position=0)]$File,
    [switch][Parameter(Position=1)]$x32              
                )

if  ($Command) {$argument = "-ExecutionPolicy ByPass -Command &{$Command}"; $Req = $Command   }
if  ($File)    {$argument = "-ExecutionPolicy ByPass -File    `"$File`""  ; $Req = $File      }
if  ($x32)     {$poshpath = "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\" ; $Platform = 'x32' } 
else           {$poshpath = "C:\Windows\System32\WindowsPowerShell\v1.0\" ; $Platform = 'x64' }

    $timeout   = 60 ##  seconds
    $taskname  = "Invoke-SystemAccount"
    $action    = New-ScheduledTaskAction -Execute "$poshpath`PowerShell.exe" -Argument $argument
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $trigger   = New-ScheduledTaskTrigger -Once -At '0:00'
    $task      = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger
    Write-Verbose  -Message "Registering task"# "Register task"
                 Register-ScheduledTask   -TaskName $taskname  -InputObject $task -Force  | Out-Null
    Write-Verbose  -Message "Starting task" # "Start task"
                 Start-ScheduledTask      -TaskName $taskname  | Out-Null
    $timer     = [Diagnostics.Stopwatch]::StartNew()

while ( ( (Get-ScheduledTask -TaskName $taskname).State -ne 'Ready') -and ( $timer.Elapsed.TotalSeconds -lt $timeout ) ) 
        { Write-Verbose  -Message "Waiting on scheduled task, elapsed time: $($timer.Elapsed.TotalSeconds) timeout: $timeout" }
        
        $timer.Stop()

if   ($timer.Elapsed.TotalSeconds -ge $timeout) {$TimedOut = $true} 
else                                            {$TimedOut = $false}
    
    $Results   = Get-ScheduledTaskInfo    -TaskName $taskname | select LastRunTime,LastTaskResult
                 Unregister-ScheduledTask -TaskName $taskname -Confirm:$false | Out-Null

[pscustomobject]@{
    
    Result     = $Results.LastTaskResult
    TimeOut    = $TimedOut
    Platform   = $Platform 
    RunTime    = $Results.LastRunTime
    Request    = $Req                     }


}
