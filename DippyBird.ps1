<# Dippy Bird Script 
    Script by Maverick Sevmont
    Note: To send the ENTER key, add the tilde '~' symbol
#>

    #[int]$MinutesInput = Read-Host -Prompt "`r`nEnter minutes"
    #$Message = Read-Host -Prompt "`r`nEnter message"
    [int]$MinutesInput = "1000000"
         $Message = "{F15}"
    
    $Timestamp = Get-Date -Format g
    $startTime = (Get-Date)              
    $Iterations = ($MinutesInput*6)
    $SecondsRunning = ($MinutesInput*60)
    $myshell = New-Object -com "Wscript.Shell"
    Write-Host "`r`n *** DIPPY BIRD SCRIPT *** `r`n" -ForegroundColor Green
    Write-Host "Start time: $Timestamp" -ForegroundColor Cyan
    Write-Host "Total seconds running: $SecondsRunning " -ForegroundColor Cyan
    Write-Host "Total message iterations: $Iterations " -ForegroundColor Cyan

    for ($i = 0; $i -lt $Iterations; $i++) {
    Start-Sleep -Seconds 10
    $myshell.sendkeys($Message)
    
    $SecondsRunning = $SecondsRunning-10
    Write-Progress -Activity 'Dippy Bird working - Press "Ctrl + C" to STOP' -Status "$SecondsRunning seconds remaining... "

                                            }
                                        
    $endTime = (Get-Date)                            
    $ElapsedTime = ($endTime-$startTime).ToString('''Duration: ''mm'' min ''ss'' sec''')
    Write-Host "$ElapsedTime" -ForegroundColor Cyan
    Write-Host "`r`nDone!`n" -ForegroundColor Green

break