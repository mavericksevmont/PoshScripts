<#

Name: Set-SMB1Config.ps1
Purpose:   Enable or disable SMB1. Runs locally.
Script by: Erick Sevilla
Date:      05/22/2020
Contact:   https://www.linkedin.com/in/ericksevilla/
Notes:     Can be easily adapted to run remotely by adding a computername param and adding \\computername to the sc.exe tool command
           Examples: Set-SMB1Config -Enabled   # Enables SMB1
                     Set-SMB1Config -Disabled  # Disable SMB1
#>

function Set-SMB1Config {
    [cmdletbinding()]
    param (
            [switch]$Enabled,
            [switch]$Disabled
        )

    if ($Enabled)
    { # Enabled
            # Must 'kill' the child process before stopping and modifying, otherwise it becomes a zombie service.
            $id = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'lanmanworkstation'" | 
            Select-Object -ExpandProperty ProcessId
            $process = Get-Process -Id $id 
            Stop-Process -id $id -Force
                Stop-Service -Name lanmanworkstation -Force
                & sc.exe config lanmanworkstation depend= bowser/mrxsmb10/mrxsmb20/nsi
                & sc.exe config mrxsmb10 start= auto 
                Start-Service -Name lanmanworkstation

                    } # End Enabled switch

    if ($Disabled)
    { # Disabled
            # Must 'kill' the child process before stopping and modifying, otherwise it becomes a zombie service.
            $id = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'lanmanworkstation'" | 
            Select-Object -ExpandProperty ProcessId
            $process = Get-Process -Id $id 
            Stop-Process -id $id -Force
                Stop-Service -Name lanmanworkstation -Force
                & sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
                & sc.exe config mrxsmb10 start= disabled 
                Start-Service -Name lanmanworkstation
       
                    } # End Disabled switch

     

                    sc.exe qc lanmanworkstation # output current configuration

} # End of function

# Set-SMB1Config -Disabled # Set to disable
# try {Set-SMB1Config -Disabled -ErrorAction Stop} catch {"Failed $_"} # Disable with error output as string to console

# Set-SMB1Config -Enabled  # Set to disable
# try {Set-SMB1Config -Enabled -ErrorAction Stop} catch {"Failed $_"} # Enable with error output as string to console
