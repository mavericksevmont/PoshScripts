<#
Name: Get-PendingRebootStatus.ps1
Purpose: Pass butter and Get if server is pending reboot status, checks 3 reg keys and wmi. Also checks the last boot and uptime.

Instructions:   Populate Servers.txt with server list, open PowerShell as admin, cd to script's location and run: .\Get-PendingReboot.ps1

RPending: ($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'RebootPending')
RRequired: ($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")).sNames -contains 'RebootRequired') {$PendingReboot = $true;$RRequired = 'True'}
PFROperations: ($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\",'PendingFileRenameOperations').sValue) {$PendingReboot = $true;$PFROperations = 'True'}
$SCCM_Namespace = Get-WmiObject -Namespace ROOT\CCM\ClientSDK -List -ComputerName $Computer -ErrorAction Ignore
if ($SCCM_Namespace) {if (([WmiClass]"\\$Computer\ROOT\CCM\ClientSDK:CCM_ClientUtilities").DetermineIfRebootPending().RebootPending -eq 'True') {$PendingReboot = $true;$CCM = 'True'}   
               
#>

Function Get-Uptime {
 
    [CmdletBinding()]
 
    Param (
        [Parameter(
                ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
 
        [string[]]
            $ComputerName = $env:COMPUTERNAME,
         
        [Switch]  
            $ShowOfflineComputers
     
        )
 
    BEGIN {
        $ErroredComputers = @()
    }
 
    PROCESS {
        Foreach ($Computer in $ComputerName) {
            Try {
                $OS = Get-WmiObject Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
                $Uptime = (Get-Date) - $OS.ConvertToDateTime($OS.LastBootUpTime)
                $Properties = @{ComputerName  = $Computer
                                LastBoot      = $OS.ConvertToDateTime($OS.LastBootUpTime)
                                Uptime        = ([String]$Uptime.Days + " Days " + $Uptime.Hours + " Hours " + $Uptime.Minutes + " Minutes")
                                }
 
                $Object = New-Object -TypeName PSObject -Property $Properties | Select ComputerName, LastBoot, UpTime
 
            } catch {
                if ($ShowOfflineComputers) {
                    $ErrorMessage = $Computer + " Error: " + $_.Exception.Message
                    $ErroredComputers += $ErrorMessage
 
                    $Properties = @{ComputerName  = $Computer
                                    LastBoot      = "Unable to Connect"
                                    Uptime        = "Error Shown Below"
                                    }
 
                    $Object = New-Object -TypeName PSObject -Property $Properties | Select ComputerName, LastBoot, UpTime
                }
                
            } finally {
                Write-Output $Object       
 
                $Object       = $null
                $OS           = $null
                $Uptime       = $null
                $ErrorMessage = $null
                $Properties   = $null
            }
        }
     
        if ($ShowOfflineComputers) {
            Write-Output ""
            Write-Output "Errors for Computers not able to connect."
            Write-Output $ErroredComputers
        }
    }
 
    END {}
 
}

Function Get-PendingRebootStatus {
 
    [CmdletBinding()]
    Param (
        [Parameter(
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
 
        [string[]]     $ComputerName = $env:COMPUTERNAME,
 
        [switch]       $ShowErrors
 
    )
 
 
    BEGIN {
        $ErrorsArray = @()
    }
 
    PROCESS {
        foreach ($Computer in $ComputerName) {
            try {
                $PendingReboot = $false
                $RPending='False'
                $RRequired='False'
                $PFROperations='False'
                $CCM='False'
                $LastBoot = ''
                $Uptime = ''
 
                $HKLM = [UInt32] "0x80000002"
                $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
                if ($WMI_Reg) {
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'RebootPending') {$PendingReboot = $true;$RPending = 'True'}
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")).sNames -contains 'RebootRequired') {$PendingReboot = $true;$RRequired = 'True'}
                    if ($WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\",'PendingFileRenameOperations').sValue) {$PendingReboot = $true;$PFROperations = 'True'}
                    $GU = Get-Uptime -ComputerName $Computer
                    $LastBoot = $GU.LastBoot;$Uptime = $GU.Uptime


                    $SCCM_Namespace = Get-WmiObject -Namespace ROOT\CCM\ClientSDK -List -ComputerName $Computer -ErrorAction Ignore
                    if ($SCCM_Namespace) {
                        if (([WmiClass]"\\$Computer\ROOT\CCM\ClientSDK:CCM_ClientUtilities").DetermineIfRebootPending().RebootPending -eq 'True') {$PendingReboot = $true;$CCM = 'True'}   
                    }
 
 
                    if ($PendingReboot -eq $true) {
                        $Properties = @{ComputerName   = $Computer.ToUpper()
                                        PendingReboot  = 'True'
                                        RPending = $RPending
                                        RRequired = $RRequired
                                        PFROperations = $PFROperations
                                        CCM = $CCM
                                        LastBoot = $LastBoot # 10.07.2019
                                        Uptime = $Uptime # 10.07.2019

                                        }
                        $Object = New-Object -TypeName PSObject -Property $Properties | Select ComputerName,PendingReboot,RPending,RRequired,PFROperations,CCM,LastBoot,Uptime
                    } else {
                        $Properties = @{ComputerName   = $Computer.ToUpper()
                                        PendingReboot  = 'False'
                                        RPending = $RPending
                                        RRequired = $RRequired
                                        PFROperations = $PFROperations
                                        CCM = $CCM
                                        LastBoot = $LastBoot # 10.07.2019
                                        Uptime = $Uptime # 10.07.2019
                                        }
                        $Object = New-Object -TypeName PSObject -Property $Properties | Select ComputerName,PendingReboot,RPending,RRequired,PFROperations,CCM,LastBoot,Uptime
                    }
                }
                 
            } catch {
                $Properties = @{ComputerName   = $Computer.ToUpper()
                                PendingReboot  = 'Error'
                                RPending = $RPending
                                        RRequired = $RRequired
                                        PFROperations = $PFROperations
                                        CCM = $CCM
                                        LastBoot = $LastBoot # 10.07.2019
                                        Uptime = $Uptime # 10.07.2019
                                }
                $Object = New-Object -TypeName PSObject -Property $Properties | Select ComputerName,PendingReboot,RPending,RRequired,PFROperations,CCM,LastBoot,Uptime
 
                $ErrorMessage = $Computer + " Error: " + $_.Exception.Message
                $ErrorsArray += $ErrorMessage
 
            } finally {
                Write-Output $Object
 
                $Object         = $null
                $ErrorMessage   = $null
                $Properties     = $null
                $WMI_Reg        = $null
                $SCCM_Namespace = $null
            }
        }
        if ($ShowErrors) {
            Write-Output "`n"
            Write-Output $ErrorsArray
        }
    }
 
    END {}
}


$Servers = Get-content $PSScriptRoot\Servers.txt
Get-PendingRebootStatus $Servers -OutVariable RebootStatsResults

$RebootStatsResults | Select * | Export-Csv $PSScriptRoot\PendingReboots_$(get-date -f yyyy-MM-dd-HH-mm).csv -Force -NoTypeInformation -Append
