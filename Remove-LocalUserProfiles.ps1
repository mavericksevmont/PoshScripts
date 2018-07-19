function Remove-LocalUserProfiles {
<#

     Original script: OneScript Team
     Modified by: Maverick Sevmont on July 18th, 2018: https://gallery.technet.microsoft.com/scriptcenter/Remove-Old-Local-User-080438f6
     Notes: Thanks to OneScript Team for the original script: https://gallery.technet.microsoft.com/scriptcenter/How-to-delete-user-d86ffd3c/view/Discussions/0
     Modifications:
     1) Enclosed script as a function
     2) Removed YES/NO persistent confirmation prompt
     3) Added "computername" parameter to run on remote hosts by taking advantage of its WMI content

 	.SYNOPSIS
        PowerShell script to list or delete user profiles specified.
    .DESCRIPTION
       List or delete user profiles specified on local or remote machines
    .PARAMETER  ListUnusedDay
		Lists unused older than a specified number of days in user profile.
	.PARAMETER  ListAll
		Lists all items in user profile.
    .PARAMETER  DeleteUnusedDay
		Delete the user profile that has not been used for more than the specified number of days.
    .PARAMETER  ExcludedUsers
		Specifies the user that you do not want to remove.
    .PARAMETER  Computername
		Specifies remote host
    .EXAMPLE
        C:\PS> C:\Script\RemoveLocalUserProfile.ps1 -ListUnusedDay 10

		ComputerName                            LocalPath                               LastUseTime
		------------                            ---------                               -----------
		WS-ANDTEST-01                           C:\Users\Administrator                  11/18/2013 1:37:26 PM
		WS-ANDTEST-01                           C:\Users\User001                        11/22/2013 10:50:35 AM
	.EXAMPLE
        C:\PS> C:\Script\RemoveLocalUserProfile.ps1 -ListAll

		ComputerName                            LocalPath                               LastUseTime
		------------                            ---------                               -----------
		WS-ANDTEST-01                           C:\Users\Administrator                  11/18/2013 1:37:26 PM
		WS-ANDTEST-01                           C:\Users\User001                        11/22/2013 10:50:35 AM
		WS-ANDTEST-01                           C:\Users\User002                        11/22/2012 10:50:35 AM
	.EXAMPLE
        C:\PS> C:\Script\RemoveLocalUserProfile.ps1 -DeleteUnusedDay 60

		ComputerName                  LocalPath                     LastUseTime                   Action
		------------                  ---------                     -----------                   ------
		WS-ANDTEST-01                 C:\Users\User001              11/22/2012 10:50:35 AM        Deleted
		WS-ANDTEST-01                 C:\Users\User002              11/22/2012 10:50:35 AM        Deleted
	.EXAMPLE
        C:\PS> C:\Script\RemoveLocalUserProfile.ps1 -DeleteUnusedDay 60 -ExcludedUsers "User001"

		ComputerName                  LocalPath                     LastUseTime                   Action
		------------                  ---------                     -----------                   ------
		WS-ANDTEST-01                 C:\Users\User002              11/22/2012 10:50:35 AM        Deleted
	.EXAMPLE
    Single Remote Host:
    Remove-LocalUserProfiles -Computername 'Hostname1' -ListUnusedDay 1

    Multiple remote hosts:
    $Computerlist = '127.0.0.1', 'Hostname2', 'Hostname3'
    foreach ($Computername in $Computerlist) {Remove-LocalUserProfiles -Computername $Computername -ListUnusedDay 1}
    
    Multiple remote hosts from a .txt list:
    $Computerlist = Get-Content 'C:\temp\ComputerList.txt'
    foreach ($Computername in $Computerlist) {Remove-LocalUserProfiles -Computername $Computername -ListUnusedDay 1}

    Parameter examples
    Remove-LocalUserProfiles -ListUnusedDay 10 # Lists unused older than 10 days
    Remove-LocalUserProfiles -ListAll # Lists all profiles
    Remove-LocalUserProfiles -DeleteUnusedDay 60 # Deletes profiles older than 60 days
    Remove-LocalUserProfiles -DeleteUnusedDay 60 -ExcludedUsers "User001" # Deletes profiles older than 60 days except "User001"
#>

Param
(
    
    [Parameter(HelpMessage="Used to specify remote host.")]
    [string]$Computername = $env:COMPUTERNAME, #'computername' parameter to query remote hosts if needed

	[Parameter(Mandatory=$true,Position=0,ParameterSetName='ListUnsed', `
	HelpMessage="Lists of unused more than a specified number of days in user profile.")]
	[Alias("lunused")][Int32]$ListUnusedDay,	
	
    [Parameter(Mandatory=$true,Position=0,ParameterSetName='ListAll', `
	HelpMessage="Lists of specified items in user profile.")]
	[Alias("all")][Switch]$ListAll,
	
	[Parameter(Mandatory=$true,Position=0,ParameterSetName='DeleteUnused', `
	HelpMessage="Delete the user profile that has not been used for more than the number of days as you specified.")]
	[Alias("dunused")][Int32]$DeleteUnusedDay,
	
	[Parameter(Mandatory=$false,Position=1,ParameterSetName='DeleteUnused', `
	HelpMessage="Specifies names of the user accounts that should not be removed.")]
	[Alias("excluded")][String[]]$ExcludedUsers
	
)

Try
{
	$UserProfileLists = Get-WmiObject -ComputerName $Computername -Class Win32_UserProfile | Select-Object @{Expression={$_.__SERVER};Label="ComputerName"},`
	LocalPath,@{Expression={$_.ConvertToDateTime($_.LastUseTime)};Label="LastUseTime"} `
	| Where{$_.LocalPath -notlike "*$env:SystemRoot*"}
}
Catch
{
    Throw "Gathering profile WMI information from $Computername failed. Be sure that WMI is functioning on this system."
}
	
If($ListAll)
{
	$UserProfileLists
}

If($ListUnusedDay -gt 0)
{
	$ProfileInfo = $UserProfileLists | Where-Object{$_.LastUseTime -le (Get-Date).AddDays(-$ListUnusedDay)}
	If($ProfileInfo -eq $null)
	{
		Write-Warning -Message "The item not found."
	}
	Else
	{
		$ProfileInfo
	}
}

If($DeleteUnusedDay -gt 0)
{
	$ProfileInfo = Get-WmiObject -ComputerName $Computername -Class Win32_UserProfile | `
	Where{$_.ConvertToDateTime($_.LastUseTime) -le (Get-Date).AddDays(-$DeleteUnusedDay) -and $_.LocalPath -notlike "*$env:SystemRoot*" }
	
	If($ExcludedUsers)
	{
		Foreach($ExcludedUser in $ExcludedUsers)
		{
			#Perform the recursion by calling itself.
			$ProfileInfo = $ProfileInfo | Where{$_.LocalPath -notlike "*$ExcludedUser*"}
		}
	}

	If($ProfileInfo -eq $null)
	{
		Write-Warning -Message "The item not found."
	}
	Else
	{
		Foreach($RemoveProfile in $ProfileInfo)
		            {
                        Try{$RemoveProfile.Delete();Write-Host "Delete profile '$($RemoveProfile.LocalPath)' successfully."}
						Catch{Write-Host "Delete profile failed." -ForegroundColor Red}
					}
	
		}
		$ProfileInfo|Select-Object @{Expression={$_.__SERVER};Label="ComputerName"},LocalPath, `
		@{Expression={$_.ConvertToDateTime($_.LastUseTime)};Label="LastUseTime"},`
		@{Name="Action";Expression={If(Test-Path -Path $_.LocalPath)
						{"Not Deleted"}
						Else
						{"Deleted"}
						}}
	}
                                            

                                    }
