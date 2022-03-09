# PorwerShell - Automate Windows Security Pop-up
# List Current Windows: Get-Process | Where-Object {$_.MainWindowTitle -ne ""} | Select-Object MainWindowTitle
# Thanks to https://johnlouros.com/blog/how-to-automate-windows-security-prompt-input, this is based on his FindWindows function.

$Window  = 'Windows Security'
$PIN     = '0123456789' # Use Credential Manager or Secret Vault instead to grab this
$Retries = '60' 

Function Find-Window {
[CmdletBinding()]Param (
[string]$WindowName,
[int]$Retries = 10,
[int]$SleepInterval = 1000
)

[int]$CurrentTry = 0;
[bool]$WindowsFound = $false;

Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -AssemblyName System.Windows.Forms

Do {
     $CurrentTry++;
     Start-Sleep -Milliseconds $SleepInterval
     Try   { [Microsoft.VisualBasic.Interaction]::AppActivate($windowName) ; $windowFound = $true; }
     Catch { Write-Verbose "[$currentTry out of $Retries] Waiting for Window with title '$WindowName'" ; $WindowFound = $false }
   } While ($CurrentTry -lt $retries -and $WindowFound -eq $false)
     return $WindowFound
}

if ( Find-Window -WindowName $Window -Retries $Retries -Verbose ) {
        Start-Sleep -Milliseconds 250
        [System.Windows.Forms.SendKeys]::SendWait($PIN)
        [System.Windows.Forms.SendKeys]::SendWait('{TAB}')
        [System.Windows.Forms.SendKeys]::SendWait('{TAB}')
        [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
} else {break}
