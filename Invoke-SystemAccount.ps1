
function Invoke-SystemAccount {

#requires -version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Run PowerShell Script or Command as NT\SYSTEM. 
.DESCRIPTION
    It runs a specified PowerShell script or command as NT\SYSTEM either at 64-bit or 32-bit PowerShell.
.PARAMETER <Command>
    Use it to declare the PowerShell command you want to run, wrap it in parenthesis or quotes.
.PARAMETER <File>
   Use it to declare a PowerShell script you want to run, use full or relative path.
.PARAMETER <x32>
    Switch to run PowerShell as x86, default is x64.

  
.EXAMPLE

    # $Command = "[Security.Principal.WindowsIdentity]::GetCurrent() | out-file 'C:\Users\marcossevilla\Documents\Test 1\ServiceProcessBios.txt'  ; get-process | out-file 'C:\Users\marcossevilla\Documents\Test 1\ServiceProcessBios.txt' -Append"
    $Command   = { whoami >> 'C:\Users\marcossevilla\Documents\Test 1\OutputTest.txt'}
    $Command32 = "whoami >> 'C:\Users\marcossevilla\Documents\Test 1\OutputTest.txt'; [IntPtr]::size >> 'C:\Users\marcossevilla\Documents\Test 1\OutputTest.txt'"
    $File      = 'C:\Users\marcossevilla\Documents\Test 1\Script.ps1'

    Invoke-SystemAccount -Command $Command
    Invoke-SystemAccount -File    $File

    # The following run PowerShell as 32-bit, if switch is not set, it runs default as x64. [IntPtr]::size will show 4 if in 32-bit, and 8 if in 64-bit
    Invoke-SystemAccount -Command $Command32 -x32
    Invoke-SystemAccount -File    $File      -x32

    OUTPUT EXAMPLE:

    Result   : 0
    TimeOut  : False
    Platform : x64
    RunTime  : 3/24/2021 11:37:37 AM
    Request  : C:\Users\marcossevilla\Documents\Test 1\Script.ps1

    Result   : 0
    TimeOut  : False
    Platform : x32
    RunTime  : 3/24/2021 11:39:39 AM
    Request  : whoami >> 'C:\Users\marcossevilla\Documents\Test 1\OutputTest.txt'; [IntPtr]::size >> 'C:\Users\marcossevilla\Documents\Test 1\OutputTest.txt'

.NOTES
    Version:        1.0
        Authors:        Erick Sevilla
        Creation Date:  March/09/2021
        Purpose/Change: Initial script development

#>


[CmdletBinding()]
    param(  
            [Parameter(ParameterSetName='Com', Position=0)][ValidateNotNullOrEmpty()]$Command,
            [Parameter(ParameterSetName='Fil', Position=0)][ValidateNotNullOrEmpty()]$File,
                                                      [switch][Parameter(Position=1)]$x32              
                )

function Test-Administrator {  
$user = [Security.Principal.WindowsIdentity]::GetCurrent()
(New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) }
$IsAdmin = Test-Administrator

Write-Verbose -Message "Is Admin?: $IsAdmin"
if  (!$IsAdmin) {Write-Error "Requires elevation. Please run PowerShell as Administrator"; return }
if  ($Command)  {$argument = "-ExecutionPolicy ByPass -Command &{$Command}"; $Req = $Command   }
if  ($File)     {$argument = "-ExecutionPolicy ByPass -File    `"$File`""  ; $Req = $File      }
if  ($x32)      {$poshpath = "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\" ; $Platform = 'x32' } 
else            {$poshpath = "C:\Windows\System32\WindowsPowerShell\v1.0\" ; $Platform = 'x64' }
Write-Verbose -Message "Platform: $Platform"

    $timeout   = 60 ##  seconds
    $taskname  = "Invoke-SystemAccount"
    Unregister-ScheduledTask -TaskName $taskname -Confirm:$false -ErrorAction SilentlyContinue | Out-Null # Delete if it exists
    Write-Verbose -Message "Creating task. Name: $taskname"
    $action    = New-ScheduledTaskAction -Execute "$poshpath`PowerShell.exe" -Argument $argument
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $trigger   = New-ScheduledTaskTrigger -Once -At '0:00'
    $task      = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger
    Write-Verbose  -Message "Registering task"# "Register task"
                 Register-ScheduledTask   -TaskName $taskname  -InputObject $task -Force | Out-Null
    Write-Verbose  -Message "Starting task" # "Start task"
                 Start-ScheduledTask      -TaskName $taskname | Out-Null
    $timer     = [Diagnostics.Stopwatch]::StartNew()
    Write-Verbose  -Message "Collecting task results"

while ( ( (Get-ScheduledTask -TaskName $taskname).State -ne 'Ready') -and ( $timer.Elapsed.TotalSeconds -lt $timeout ) ) 
        { Write-Verbose  -Message "Waiting on scheduled task, elapsed time: $($timer.Elapsed.TotalSeconds) timeout: $timeout" }
        
        $timer.Stop()

if   ($timer.Elapsed.TotalSeconds -ge $timeout) {$TimedOut = $true} 
else                                            {$TimedOut = $false}
    
    $Results   = Get-ScheduledTaskInfo    -TaskName $taskname | select LastRunTime,LastTaskResult
    Write-Verbose  -Message "Removing task"
                 Unregister-ScheduledTask -TaskName $taskname -Confirm:$false | Out-Null

[pscustomobject]@{
    
    Result     = $Results.LastTaskResult
    TimeOut    = $TimedOut
    Platform   = $Platform 
    RunTime    = $Results.LastRunTime
    Request    = $Req                     }


}
