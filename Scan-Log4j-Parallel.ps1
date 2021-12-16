<# Find Log4j library instances in all Drives and Directories
# Version 4
# Written by: Jason Bagget & Erick Sevilla
# Windows 2008 and above with PowerShell version 5.1
## Source server needs to be configured with 
### Set-Item WSMan:\localhost\Client\TrustedHosts *
### Restart-Service winrm
## Client servers need to be configured for remove sessions
### Set-ExecutionPolicy Unrestricted –force
### Enable-PSRemoting –force
### WinRM quickconfig
## For multiple hosts, requires Hosts.txt list of servers in same directory as script
## Added: Timeout, Dir and filename, NA result if not found, FAILED result to catch errors/exceptions, Force switch on GCI, version filter to generate second report with vulnerable file versions based on name
Hash collection and validation, and a bunch of nice things
## Hash list: https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes/blob/main/sha256sums.txt
#>



$OutDir         = 'C:\Temp' # Output directory for report
                if(!(get-item $OutDir -ErrorAction SilentlyContinue)){new-item $OutDir -ItemType Directory }
$OutFileName    = "Log4jResults_$env:COMPUTERNAME.csv" # Report FileName
$TimeoutSeconds = '3600' # Timeout for scan per server
$Hosts          = Get-Content $OutDir\Hosts.txt -ErrorAction SilentlyContinue ; If (!$Hosts) {$Hosts = "$env:COMPUTERNAME"}
                if((get-item $OutDir\Hosts.txt -ErrorAction SilentlyContinue)){$Cred = Get-Credential} # Specify admin credentials to connect to remote servers

function Invoke-Parallel {

    [cmdletbinding(DefaultParameterSetName='ScriptBlock')]
    Param (
        [Parameter(Mandatory=$false,position=0,ParameterSetName='ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory=$false,ParameterSetName='ScriptFile')]
        [ValidateScript({Test-Path $_ -pathtype leaf})]
        $ScriptFile,

        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [Alias('CN','__Server','IPAddress','Server','ComputerName')]
        [PSObject]$InputObject,

        [PSObject]$Parameter,

        [switch]$ImportVariables,
        [switch]$ImportModules,
        [switch]$ImportFunctions,

        [int]$Throttle = 20,
        [int]$SleepTimer = 200,
        [int]$RunspaceTimeout = 0,
        [switch]$NoCloseOnTimeout = $false,
        [int]$MaxQueue,

        [validatescript({Test-Path (Split-Path $_ -parent)})]
        [switch] $AppendLog = $false,
        [string]$LogFile,

        [switch] $Quiet = $false
    )
    begin {
        #No max queue specified?  Estimate one.
        #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
        if( -not $PSBoundParameters.ContainsKey('MaxQueue') ) {
            if($RunspaceTimeout -ne 0){ $script:MaxQueue = $Throttle }
            else{ $script:MaxQueue = $Throttle * 3 }
        }
        else {
            $script:MaxQueue = $MaxQueue
        }
        $ProgressId = Get-Random
        Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

        #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
        if ($ImportVariables -or $ImportModules -or $ImportFunctions) {
            $StandardUserEnv = [powershell]::Create().addscript({

                #Get modules, snapins, functions in this clean runspace
                $Modules = Get-Module | Select-Object -ExpandProperty Name
                $Snapins = Get-PSSnapin | Select-Object -ExpandProperty Name
                $Functions = Get-ChildItem function:\ | Select-Object -ExpandProperty Name

                #Get variables in this clean runspace
                #Called last to get vars like $? into session
                $Variables = Get-Variable | Select-Object -ExpandProperty Name

                #Return a hashtable where we can access each.
                @{
                    Variables   = $Variables
                    Modules     = $Modules
                    Snapins     = $Snapins
                    Functions   = $Functions
                }
            },$true).invoke()[0]

            if ($ImportVariables) {
                #Exclude common parameters, bound parameters, and automatic variables
                Function _temp {[cmdletbinding(SupportsShouldProcess=$True)] param() }
                $VariablesToExclude = @( (Get-Command _temp | Select-Object -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                Write-Verbose "Excluding variables $( ($VariablesToExclude | Sort-Object ) -join ", ")"

                # we don't use 'Get-Variable -Exclude', because it uses regexps.
                # One of the veriables that we pass is '$?'.
                # There could be other variables with such problems.
                # Scope 2 required if we move to a real module
                $UserVariables = @( Get-Variable | Where-Object { -not ($VariablesToExclude -contains $_.Name) } )
                Write-Verbose "Found variables to import: $( ($UserVariables | Select-Object -expandproperty Name | Sort-Object ) -join ", " | Out-String).`n"
            }
            if ($ImportModules) {
                $UserModules = @( Get-Module | Where-Object {$StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path $_.Path -ErrorAction SilentlyContinue)} | Select-Object -ExpandProperty Path )
                $UserSnapins = @( Get-PSSnapin | Select-Object -ExpandProperty Name | Where-Object {$StandardUserEnv.Snapins -notcontains $_ } )
            }
            if($ImportFunctions) {
                $UserFunctions = @( Get-ChildItem function:\ | Where-Object { $StandardUserEnv.Functions -notcontains $_.Name } )
            }
        }

        #region functions
            Function Get-RunspaceData {
                [cmdletbinding()]
                param( [switch]$Wait )
                #loop through runspaces
                #if $wait is specified, keep looping until all complete
                Do {
                    #set more to false for tracking completion
                    $more = $false

                    #Progress bar if we have inputobject count (bound parameter)
                    if (-not $Quiet) {
                        Write-Progress -Id $ProgressId -Activity "Running Query" -Status "Starting threads"`
                            -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
                            -PercentComplete $( Try { $script:completedCount / $totalCount * 100 } Catch {0} )
                    }

                    #run through each runspace.
                    Foreach($runspace in $runspaces) {

                        #get the duration - inaccurate
                        $currentdate = Get-Date
                        $runtime = $currentdate - $runspace.startTime
                        $runMin = [math]::Round( $runtime.totalminutes ,2 )

                        #set up log object
                        $log = "" | Select-Object Date, Action, Runtime, Status, Details
                        $log.Action = "Removing:'$($runspace.object)'"
                        $log.Date = $currentdate
                        $log.Runtime = "$runMin minutes"

                        #If runspace completed, end invoke, dispose, recycle, counter++
                        If ($runspace.Runspace.isCompleted) {

                            $script:completedCount++

                            #check if there were errors
                            if($runspace.powershell.Streams.Error.Count -gt 0) {
                                #set the logging info and move the file to completed
                                $log.status = "CompletedWithErrors"
                                Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                foreach($ErrorRecord in $runspace.powershell.Streams.Error) {
                                    Write-Error -ErrorRecord $ErrorRecord
                                }
                            }
                            else {
                                #add logging details and cleanup
                                $log.status = "Completed"
                                Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            }

                            #everything is logged, clean up the runspace
                            $runspace.powershell.EndInvoke($runspace.Runspace)
                            $runspace.powershell.dispose()
                            $runspace.Runspace = $null
                            $runspace.powershell = $null
                        }
                        #If runtime exceeds max, dispose the runspace
                        ElseIf ( $runspaceTimeout -ne 0 -and $runtime.totalseconds -gt $runspaceTimeout) {
                            $script:completedCount++
                            $timedOutTasks = $true

                            #add logging details and cleanup
                            $log.status = "TimedOut"
                            Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            Write-Error "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | out-string)"

                            #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                            if (!$noCloseOnTimeout) { $runspace.powershell.dispose() }
                            $runspace.Runspace = $null
                            $runspace.powershell = $null
                            $completedCount++
                        }

                        #If runspace isn't null set more to true
                        ElseIf ($runspace.Runspace -ne $null ) {
                            $log = $null
                            $more = $true
                        }

                        #log the results if a log file was indicated
                        if($logFile -and $log) {
                            ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                        }
                    }

                    #Clean out unused runspace jobs
                    $temphash = $runspaces.clone()
                    $temphash | Where-Object { $_.runspace -eq $Null } | ForEach-Object {
                        $Runspaces.remove($_)
                    }

                    #sleep for a bit if we will loop again
                    if($PSBoundParameters['Wait']){ Start-Sleep -milliseconds $SleepTimer }

                #Loop again only if -wait parameter and there are more runspaces to process
                } while ($more -and $PSBoundParameters['Wait'])

            #End of runspace function
            }
        #endregion functions

        #region Init

            if($PSCmdlet.ParameterSetName -eq 'ScriptFile') {
                $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | out-string) )
            }
            elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock') {
                #Start building parameter names for the param block
                [string[]]$ParamsToAdd = '$_'
                if( $PSBoundParameters.ContainsKey('Parameter') ) {
                    $ParamsToAdd += '$Parameter'
                }

                $UsingVariableData = $Null

                # This code enables $Using support through the AST.
                # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!

                if($PSVersionTable.PSVersion.Major -gt 2) {
                    #Extract using references
                    $UsingVariables = $ScriptBlock.ast.FindAll({$args[0] -is [System.Management.Automation.Language.UsingExpressionAst]},$True)

                    If ($UsingVariables) {
                        $List = New-Object 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                        ForEach ($Ast in $UsingVariables) {
                            [void]$list.Add($Ast.SubExpression)
                        }

                        $UsingVar = $UsingVariables | Group-Object -Property SubExpression | ForEach-Object {$_.Group | Select-Object -First 1}

                        #Extract the name, value, and create replacements for each
                        $UsingVariableData = ForEach ($Var in $UsingVar) {
                            try {
                                $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                                [pscustomobject]@{
                                    Name = $Var.SubExpression.Extent.Text
                                    Value = $Value.Value
                                    NewName = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                    NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                }
                            }
                            catch {
                                Write-Error "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                            }
                        }
                        $ParamsToAdd += $UsingVariableData | Select-Object -ExpandProperty NewName -Unique

                        $NewParams = $UsingVariableData.NewName -join ', '
                        $Tuple = [Tuple]::Create($list, $NewParams)
                        $bindingFlags = [Reflection.BindingFlags]"Default,NonPublic,Instance"
                        $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))

                        $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                        $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                        Write-Verbose $StringScriptBlock
                    }
                }

                $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ", "))`r`n" + $Scriptblock.ToString())
            }
            else {
                Throw "Must provide ScriptBlock or ScriptFile"; Break
            }

            Write-Debug "`$ScriptBlock: $($ScriptBlock | Out-String)"
            Write-Verbose "Creating runspace pool and session states"

            #If specified, add variables and modules/snapins to session state
            $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            if($ImportVariables -and $UserVariables.count -gt 0) {
                foreach($Variable in $UserVariables) {
                    $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                }
            }
            if ($ImportModules) {
                if($UserModules.count -gt 0) {
                    foreach($ModulePath in $UserModules) {
                        $sessionstate.ImportPSModule($ModulePath)
                    }
                }
                if($UserSnapins.count -gt 0) {
                    foreach($PSSnapin in $UserSnapins) {
                        [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                    }
                }
            }
            if($ImportFunctions -and $UserFunctions.count -gt 0) {
                foreach ($FunctionDef in $UserFunctions) {
                    $sessionstate.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $FunctionDef.Name,$FunctionDef.ScriptBlock))
                }
            }

            #Create runspace pool
            $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
            $runspacepool.Open()

            Write-Verbose "Creating empty collection to hold runspace jobs"
            $Script:runspaces = New-Object System.Collections.ArrayList

            #If inputObject is bound get a total count and set bound to true
            $bound = $PSBoundParameters.keys -contains "InputObject"
            if(-not $bound) {
                [System.Collections.ArrayList]$allObjects = @()
            }

            #Set up log file if specified
            if( $LogFile -and (-not (Test-Path $LogFile) -or $AppendLog -eq $false)){
                New-Item -ItemType file -Path $logFile -Force | Out-Null
                ("" | Select-Object -Property Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
            }

            #write initial log entry
            $log = "" | Select-Object -Property Date, Action, Runtime, Status, Details
                $log.Date = Get-Date
                $log.Action = "Batch processing started"
                $log.Runtime = $null
                $log.Status = "Started"
                $log.Details = $null
                if($logFile) {
                    ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                }
            $timedOutTasks = $false
        #endregion INIT
    }
    process {
        #add piped objects to all objects or set all objects to bound input object parameter
        if($bound) {
            $allObjects = $InputObject
        }
        else {
            [void]$allObjects.add( $InputObject )
        }
    }
    end {
        #Use Try/Finally to catch Ctrl+C and clean up.
        try {
            #counts for progress
            $totalCount = $allObjects.count
            $script:completedCount = 0
            $startedCount = 0
            foreach($object in $allObjects) {
                #region add scripts to runspace pool
                    #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                    $powershell = [powershell]::Create()

                    if ($VerbosePreference -eq 'Continue') {
                        [void]$PowerShell.AddScript({$VerbosePreference = 'Continue'})
                    }

                    [void]$PowerShell.AddScript($ScriptBlock).AddArgument($object)

                    if ($parameter) {
                        [void]$PowerShell.AddArgument($parameter)
                    }

                    # $Using support from Boe Prox
                    if ($UsingVariableData) {
                        Foreach($UsingVariable in $UsingVariableData) {
                            Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                            [void]$PowerShell.AddArgument($UsingVariable.Value)
                        }
                    }

                    #Add the runspace into the powershell instance
                    $powershell.RunspacePool = $runspacepool

                    #Create a temporary collection for each runspace
                    $temp = "" | Select-Object PowerShell, StartTime, object, Runspace
                    $temp.PowerShell = $powershell
                    $temp.StartTime = Get-Date
                    $temp.object = $object

                    #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                    $temp.Runspace = $powershell.BeginInvoke()
                    $startedCount++

                    #Add the temp tracking info to $runspaces collection
                    Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                    $runspaces.Add($temp) | Out-Null

                    #loop through existing runspaces one time
                    Get-RunspaceData

                    #If we have more running than max queue (used to control timeout accuracy)
                    #Script scope resolves odd PowerShell 2 issue
                    $firstRun = $true
                    while ($runspaces.count -ge $Script:MaxQueue) {
                        #give verbose output
                        if($firstRun) {
                            Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                        }
                        $firstRun = $false

                        #run get-runspace data and sleep for a short while
                        Get-RunspaceData
                        Start-Sleep -Milliseconds $sleepTimer
                    }
                #endregion add scripts to runspace pool
            }
            Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where-Object {$_.Runspace -ne $Null}).Count) )

            Get-RunspaceData -wait
            if (-not $quiet) {
                Write-Progress -Id $ProgressId -Activity "Running Query" -Status "Starting threads" -Completed
            }
        }
        finally {
            #Close the runspace pool, unless we specified no close on timeout and something timed out
            if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($noCloseOnTimeout -eq $false) ) ) {
                Write-Verbose "Closing the runspace pool"
                $runspacepool.close()
            }
            #collect garbage
            [gc]::Collect()
        }
    }
}

$Hosts | Invoke-Parallel -ScriptBlock {
$ServerName = $_
try {
if((get-item $OutDir\Hosts.txt -ErrorAction SilentlyContinue)){
$Result = Invoke-Command  -ComputerName $ServerName -ScriptBlock {
Add-Type -assembly "system.io.compression.filesystem"
$Hashes = @(
'bf4f41403280c1b115650d470f9b260a5c9042c04d9bcc2a6ca504a66379b2d6'
'58e9f72081efff9bdaabd82e3b3efe5b1b9f1666cefe28f429ad7176a6d770ae'
'ed285ad5ac6a8cf13461d6c2874fdcd3bf67002844831f66e21c2d0adda43fa4'
'dbf88c623cc2ad99d82fa4c575fb105e2083465a47b84d64e2e1a63e183c274e'
'a38ddff1e797adb39a08876932bc2538d771ff7db23885fb883fec526aff4fc8'
'7d86841489afd1097576a649094ae1efb79b3147cd162ba019861dfad4e9573b'
'4bfb0d5022dc499908da4597f3e19f9f64d3cc98ce756a2249c72179d3d75c47'
'473f15c04122dad810c919b2f3484d46560fd2dd4573f6695d387195816b02a6'
'b3fae4f84d4303cdbad4696554b4e8d2381ad3faf6e0c3c8d2ce60a4388caa02'
'dcde6033b205433d6e9855c93740f798951fa3a3f252035a768d9f356fde806d'
'85338f694c844c8b66d8a1b981bcf38627f95579209b2662182a009d849e1a4c'
'db3906edad6009d1886ec1e2a198249b6d99820a3575f8ec80c6ce57f08d521a'
'ec411a34fee49692f196e4dc0a905b25d0667825904862fdba153df5e53183e0'
'a00a54e3fb8cb83fab38f8714f240ecc13ab9c492584aa571aec5fc71b48732d'
'c584d1000591efa391386264e0d43ec35f4dbb146cad9390f73358d9c84ee78d'
'8bdb662843c1f4b120fb4c25a5636008085900cdf9947b1dadb9b672ea6134dc'
'c830cde8f929c35dad42cbdb6b28447df69ceffe99937bf420d32424df4d076a'
'6ae3b0cb657e051f97835a6432c2b0f50a651b36b6d4af395bbe9060bb4ef4b2'
'535e19bf14d8c76ec00a7e8490287ca2e2597cae2de5b8f1f65eb81ef1c2a4c6'
'42de36e61d454afff5e50e6930961c85b55d681e23931efd248fd9b9b9297239'
'4f53e4d52efcccdc446017426c15001bb0fe444c7a6cdc9966f8741cf210d997'
'df00277045338ceaa6f70a7b8eee178710b3ba51eac28c1142ec802157492de6'
'28433734bd9e3121e0a0b78238d5131837b9dbe26f1a930bc872bad44e68e44e'
'cf65f0d33640f2cd0a0b06dd86a5c6353938ccb25f4ffd14116b4884181e0392'
'5bb84e110d5f18cee47021a024d358227612dd6dac7b97fa781f85c6ad3ccee4'
'ccf02bb919e1a44b13b366ea1b203f98772650475f2a06e9fac4b3c957a7c3fa'
'815a73e20e90a413662eefe8594414684df3d5723edcd76070e1a5aee864616e'
'10ef331115cbbd18b5be3f3761e046523f9c95c103484082b18e67a7c36e570c'
'dc815be299f81c180aa8d2924f1b015f2c46686e866bc410e72de75f7cd41aae'
'9275f5d57709e2204900d3dae2727f5932f85d3813ad31c9d351def03dd3d03d'
'f35ccc9978797a895e5bee58fa8c3b7ad6d5ee55386e9e532f141ee8ed2e937d'
'5256517e6237b888c65c8691f29219b6658d800c23e81d5167c4a8bbd2a0daa3'
'd4485176aea67cc85f5ccc45bb66166f8bfc715ae4a695f0d870a1f8d848cc3d'
'3fcc4c1f2f806acfc395144c98b8ba2a80fe1bf5e3ad3397588bbd2610a37100'
'057a48fe378586b6913d29b4b10162b4b5045277f1be66b7a01fb7e30bd05ef3'
'5dbd6bb2381bf54563ea15bc9fbb6d7094eaf7184e6975c50f8996f77bfc3f2c'
'c39b0ea14e7766440c59e5ae5f48adee038d9b1c7a1375b376e966ca12c22cd3'
'6f38a25482d82cd118c4255f25b9d78d96821d22bab498cdce9cda7a563ca992'
'54962835992e303928aa909730ce3a50e311068c0960c708e82ab76701db5e6b'
'e5e9b0f8d72f4e7b9022b7a83c673334d7967981191d2d98f9c57dc97b4caae1'
'68d793940c28ddff6670be703690dfdf9e77315970c42c4af40ca7261a8570fa'
'9da0f5ca7c8eab693d090ae759275b9db4ca5acdbcfe4a63d3871e0b17367463'
'006fc6623fbb961084243cfc327c885f3c57f2eba8ee05fbc4e93e5358778c85'
).ToUpper()

function Get-Hash
{
    <#
    .SYNOPSIS

    Get-Hash is a PowerShell Version 2 port of Get-FileHash that supports hashing files, as well as, strings.

    .PARAMETER InputObject

    This is the actual item used to calculate the hash. This value will support [Byte[]] or [System.IO.Stream] objects.

    .PARAMETER FilePath

    Specifies the path to a file to hash. Wildcard characters are permitted.

    .PARAMETER Text

    A string to calculate a cryptographic hash for.

    .PARAMETER Encoding

    Specified the character encoding to use for the string passed to the Text parameter. The default encoding type is Unicode. The acceptable values for this parameter are:

    - ASCII
    - BigEndianUnicode
    - Default
    - Unicode
    - UTF32
    - UTF7
    - UTF8

    .PARAMETER Algorithm

    Specifies the cryptographic hash function to use for computing the hash value of the contents of the specified file. A cryptographic hash function includes the property that it is not possible to find two distinct inputs that generate the same hash values. Hash functions are commonly used with digital signatures and for data integrity. The acceptable values for this parameter are:
    
    - SHA1
    - SHA256
    - SHA384
    - SHA512
    - MACTripleDES
    - MD5
    - RIPEMD160
    
    If no value is specified, or if the parameter is omitted, the default value is SHA256.
    For security reasons, MD5 and SHA1, which are no longer considered secure, should only be used for simple change validation, and should not be used to generate hash values for files that require protection from attack or tampering.

    .NOTES
    
    This function was adapted from https://p0w3rsh3ll.wordpress.com/2015/02/05/backporting-the-get-filehash-function/
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .EXAMPLE

    Get-Hash -Text 'This is a string'

    .EXAMPLE

    Get-Hash -FilePath C:\This\is\a\filepath.exe

    #>

    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Object')]
        $InputObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        [ValidateNotNullOrEmpty()]
        $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Text')]
        [string]
        [ValidateNotNullOrEmpty()]
        $Text,

        [Parameter(ParameterSetName = 'Text')]
        [string]
        [ValidateSet('ASCII', 'BigEndianUnicode', 'Default', 'Unicode', 'UTF32', 'UTF7', 'UTF8')]
        $Encoding = 'Unicode',

        [Parameter()]
        [string]
        [ValidateSet("MACTripleDES", "MD5", "RIPEMD160", "SHA1", "SHA256", "SHA384", "SHA512")]
        $Algorithm = "SHA256"
    )

    switch($PSCmdlet.ParameterSetName)
    {
        File
        {
            try
            {
                $FullPath = Resolve-Path -Path $FilePath -ErrorAction Stop
                $InputObject = [System.IO.File]::OpenRead($FilePath)
                Get-Hash -InputObject $InputObject -Algorithm $Algorithm
            }
            catch
            {
                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $null
                }
            }
        }
        Text
        {
            $InputObject = [System.Text.Encoding]::$Encoding.GetBytes($Text)
            Get-Hash -InputObject $InputObject -Algorithm $Algorithm
        }
        Object
        {
            if($InputObject.GetType() -eq [Byte[]] -or $InputObject.GetType().BaseType -eq [System.IO.Stream])
            {
                # Construct the strongly-typed crypto object
                $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)

                # Compute file-hash using the crypto object
                [Byte[]] $computedHash = $Hasher.ComputeHash($InputObject)
                [string] $hash = [BitConverter]::ToString($computedHash) -replace '-',''

                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $hash
                }

                $retVal
            }
        }
    }
}
Get-PSDrive -PSProvider "FileSystem" -ErrorAction SilentlyContinue | % {$Drive = $_.Root ; Get-ChildItem $Drive -Include '*log4j*.jar*' -Recurse -ErrorAction SilentlyContinue}  | 
select -ErrorAction SilentlyContinue -Property @{n='Server';e={$env:COMPUTERNAME}},BaseName,Directory,CreationTimeUtc,LastAccessTimeUtc,LastWriteTimeUtc,@{n='HashSHA256';e={(Get-Hash -ErrorAction SilentlyContinue -FilePath ($_.FullName)).Hash}},@{n='IsHashVulnerable';e={if(($Hashes).Contains((Get-Hash -FilePath ($_.FullName)).Hash) -eq $true){"TRUE"}else{"FALSE"}}},@{n="IsExploitable";e={
$zip = [io.compression.zipfile]::OpenRead(($_.FullName))
$file = $zip.Entries | where-object { $_.Name -like "*JndiLookup.class"}
if(($file)){($file).Name.Replace("/","\")}
}
},@{n="ImplementationVersion";e={
$Files  = [IO.Compression.ZipFile]::OpenRead(($_.FullName)).Entries | where {$_.Name -like '*MANIFEST.MF'}
$Stream = $Files.Open()
$Reader = New-Object IO.StreamReader($stream)
$Text   = $Reader.ReadToEnd()
"$(((($Text -split '\r\n') | Select-String -Pattern Implementation-Version) -split '\s')[-1])"
#$Reader.Close()
#$Stream.Close()
#$Files.Dispose()
}},@{n="BundleVersion";e={
$Files  = [IO.Compression.ZipFile]::OpenRead(($_.FullName)).Entries | where {$_.Name -like '*MANIFEST.MF'}
$Stream = $Files.Open()
$Reader = New-Object IO.StreamReader($stream)
$Text   = $Reader.ReadToEnd()
"$(((($Text -split '\r\n') | Select-String -Pattern Bundle-Version) -split '\s')[-1])"
#$Reader.Close()
#$Stream.Close()
#$Files.Dispose()
}}

 #################################################################################################
} -Credential $Cred  -ErrorAction Stop
}else{
Add-Type -assembly "system.io.compression.filesystem"
function Get-Hash
{
    <#
    .SYNOPSIS

    Get-Hash is a PowerShell Version 2 port of Get-FileHash that supports hashing files, as well as, strings.

    .PARAMETER InputObject

    This is the actual item used to calculate the hash. This value will support [Byte[]] or [System.IO.Stream] objects.

    .PARAMETER FilePath

    Specifies the path to a file to hash. Wildcard characters are permitted.

    .PARAMETER Text

    A string to calculate a cryptographic hash for.

    .PARAMETER Encoding

    Specified the character encoding to use for the string passed to the Text parameter. The default encoding type is Unicode. The acceptable values for this parameter are:

    - ASCII
    - BigEndianUnicode
    - Default
    - Unicode
    - UTF32
    - UTF7
    - UTF8

    .PARAMETER Algorithm

    Specifies the cryptographic hash function to use for computing the hash value of the contents of the specified file. A cryptographic hash function includes the property that it is not possible to find two distinct inputs that generate the same hash values. Hash functions are commonly used with digital signatures and for data integrity. The acceptable values for this parameter are:
    
    - SHA1
    - SHA256
    - SHA384
    - SHA512
    - MACTripleDES
    - MD5
    - RIPEMD160
    
    If no value is specified, or if the parameter is omitted, the default value is SHA256.
    For security reasons, MD5 and SHA1, which are no longer considered secure, should only be used for simple change validation, and should not be used to generate hash values for files that require protection from attack or tampering.

    .NOTES
    
    This function was adapted from https://p0w3rsh3ll.wordpress.com/2015/02/05/backporting-the-get-filehash-function/
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .EXAMPLE

    Get-Hash -Text 'This is a string'

    .EXAMPLE

    Get-Hash -FilePath C:\This\is\a\filepath.exe

    #>

    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Object')]
        $InputObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        [ValidateNotNullOrEmpty()]
        $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Text')]
        [string]
        [ValidateNotNullOrEmpty()]
        $Text,

        [Parameter(ParameterSetName = 'Text')]
        [string]
        [ValidateSet('ASCII', 'BigEndianUnicode', 'Default', 'Unicode', 'UTF32', 'UTF7', 'UTF8')]
        $Encoding = 'Unicode',

        [Parameter()]
        [string]
        [ValidateSet("MACTripleDES", "MD5", "RIPEMD160", "SHA1", "SHA256", "SHA384", "SHA512")]
        $Algorithm = "SHA256"
    )

    switch($PSCmdlet.ParameterSetName)
    {
        File
        {
            try
            {
                $FullPath = Resolve-Path -Path $FilePath -ErrorAction Stop
                $InputObject = [System.IO.File]::OpenRead($FilePath)
                Get-Hash -InputObject $InputObject -Algorithm $Algorithm
            }
            catch
            {
                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $null
                }
            }
        }
        Text
        {
            $InputObject = [System.Text.Encoding]::$Encoding.GetBytes($Text)
            Get-Hash -InputObject $InputObject -Algorithm $Algorithm
        }
        Object
        {
            if($InputObject.GetType() -eq [Byte[]] -or $InputObject.GetType().BaseType -eq [System.IO.Stream])
            {
                # Construct the strongly-typed crypto object
                $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)

                # Compute file-hash using the crypto object
                [Byte[]] $computedHash = $Hasher.ComputeHash($InputObject)
                [string] $hash = [BitConverter]::ToString($computedHash) -replace '-',''

                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $hash
                }

                $retVal
            }
        }
    }
}
$Hashes = @(
'bf4f41403280c1b115650d470f9b260a5c9042c04d9bcc2a6ca504a66379b2d6'
'58e9f72081efff9bdaabd82e3b3efe5b1b9f1666cefe28f429ad7176a6d770ae'
'ed285ad5ac6a8cf13461d6c2874fdcd3bf67002844831f66e21c2d0adda43fa4'
'dbf88c623cc2ad99d82fa4c575fb105e2083465a47b84d64e2e1a63e183c274e'
'a38ddff1e797adb39a08876932bc2538d771ff7db23885fb883fec526aff4fc8'
'7d86841489afd1097576a649094ae1efb79b3147cd162ba019861dfad4e9573b'
'4bfb0d5022dc499908da4597f3e19f9f64d3cc98ce756a2249c72179d3d75c47'
'473f15c04122dad810c919b2f3484d46560fd2dd4573f6695d387195816b02a6'
'b3fae4f84d4303cdbad4696554b4e8d2381ad3faf6e0c3c8d2ce60a4388caa02'
'dcde6033b205433d6e9855c93740f798951fa3a3f252035a768d9f356fde806d'
'85338f694c844c8b66d8a1b981bcf38627f95579209b2662182a009d849e1a4c'
'db3906edad6009d1886ec1e2a198249b6d99820a3575f8ec80c6ce57f08d521a'
'ec411a34fee49692f196e4dc0a905b25d0667825904862fdba153df5e53183e0'
'a00a54e3fb8cb83fab38f8714f240ecc13ab9c492584aa571aec5fc71b48732d'
'c584d1000591efa391386264e0d43ec35f4dbb146cad9390f73358d9c84ee78d'
'8bdb662843c1f4b120fb4c25a5636008085900cdf9947b1dadb9b672ea6134dc'
'c830cde8f929c35dad42cbdb6b28447df69ceffe99937bf420d32424df4d076a'
'6ae3b0cb657e051f97835a6432c2b0f50a651b36b6d4af395bbe9060bb4ef4b2'
'535e19bf14d8c76ec00a7e8490287ca2e2597cae2de5b8f1f65eb81ef1c2a4c6'
'42de36e61d454afff5e50e6930961c85b55d681e23931efd248fd9b9b9297239'
'4f53e4d52efcccdc446017426c15001bb0fe444c7a6cdc9966f8741cf210d997'
'df00277045338ceaa6f70a7b8eee178710b3ba51eac28c1142ec802157492de6'
'28433734bd9e3121e0a0b78238d5131837b9dbe26f1a930bc872bad44e68e44e'
'cf65f0d33640f2cd0a0b06dd86a5c6353938ccb25f4ffd14116b4884181e0392'
'5bb84e110d5f18cee47021a024d358227612dd6dac7b97fa781f85c6ad3ccee4'
'ccf02bb919e1a44b13b366ea1b203f98772650475f2a06e9fac4b3c957a7c3fa'
'815a73e20e90a413662eefe8594414684df3d5723edcd76070e1a5aee864616e'
'10ef331115cbbd18b5be3f3761e046523f9c95c103484082b18e67a7c36e570c'
'dc815be299f81c180aa8d2924f1b015f2c46686e866bc410e72de75f7cd41aae'
'9275f5d57709e2204900d3dae2727f5932f85d3813ad31c9d351def03dd3d03d'
'f35ccc9978797a895e5bee58fa8c3b7ad6d5ee55386e9e532f141ee8ed2e937d'
'5256517e6237b888c65c8691f29219b6658d800c23e81d5167c4a8bbd2a0daa3'
'd4485176aea67cc85f5ccc45bb66166f8bfc715ae4a695f0d870a1f8d848cc3d'
'3fcc4c1f2f806acfc395144c98b8ba2a80fe1bf5e3ad3397588bbd2610a37100'
'057a48fe378586b6913d29b4b10162b4b5045277f1be66b7a01fb7e30bd05ef3'
'5dbd6bb2381bf54563ea15bc9fbb6d7094eaf7184e6975c50f8996f77bfc3f2c'
'c39b0ea14e7766440c59e5ae5f48adee038d9b1c7a1375b376e966ca12c22cd3'
'6f38a25482d82cd118c4255f25b9d78d96821d22bab498cdce9cda7a563ca992'
'54962835992e303928aa909730ce3a50e311068c0960c708e82ab76701db5e6b'
'e5e9b0f8d72f4e7b9022b7a83c673334d7967981191d2d98f9c57dc97b4caae1'
'68d793940c28ddff6670be703690dfdf9e77315970c42c4af40ca7261a8570fa'
'9da0f5ca7c8eab693d090ae759275b9db4ca5acdbcfe4a63d3871e0b17367463'
'006fc6623fbb961084243cfc327c885f3c57f2eba8ee05fbc4e93e5358778c85'
).ToUpper()

$Result =
Get-PSDrive -PSProvider "FileSystem" -ErrorAction SilentlyContinue | % {$Drive = $_.Root ; Get-ChildItem $Drive -Include '*log4j*.jar*' -Recurse -ErrorAction SilentlyContinue}  | 
select -ErrorAction SilentlyContinue -Property @{n='Server';e={$env:COMPUTERNAME}},BaseName,Directory,CreationTimeUtc,LastAccessTimeUtc,LastWriteTimeUtc,@{n='HashSHA256';e={(Get-Hash -ErrorAction SilentlyContinue -FilePath ($_.FullName)).Hash}},@{n='IsHashVulnerable';e={if(($Hashes).Contains((Get-Hash -FilePath ($_.FullName)).Hash) -eq $true){"TRUE"}else{"FALSE"}}},@{n="IsExploitable";e={
$zip = [io.compression.zipfile]::OpenRead(($_.FullName))
$file = $zip.Entries | where-object { $_.Name -like "*JndiLookup.class"}
if(($file)){($file).Name.Replace("/","\")}
}
},@{n="ImplementationVersion";e={
$Files  = [IO.Compression.ZipFile]::OpenRead(($_.FullName)).Entries | where {$_.Name -like '*MANIFEST.MF'}
$Stream = $Files.Open()
$Reader = New-Object IO.StreamReader($stream)
$Text   = $Reader.ReadToEnd()
"$(((($Text -split '\r\n') | Select-String -Pattern Implementation-Version) -split '\s')[-1])"
#$Reader.Close()
#$Stream.Close()
#$Files.Dispose()
}},@{n="BundleVersion";e={
$Files  = [IO.Compression.ZipFile]::OpenRead(($_.FullName)).Entries | where {$_.Name -like '*MANIFEST.MF'}
$Stream = $Files.Open()
$Reader = New-Object IO.StreamReader($stream)
$Text   = $Reader.ReadToEnd()
"$(((($Text -split '\r\n') | Select-String -Pattern Bundle-Version) -split '\s')[-1])"
#$Reader.Close()
#$Stream.Close()
#$Files.Dispose()
}}

} # else ends here
If ($Result) {
$MS = Get-Random -Minimum 100 -Maximum 350
Start-Sleep -Milliseconds $MS
$Result | Export-Csv "$OutDir\$OutFileName" -Force -NoTypeInformation -Append
} else {
$MS = Get-Random -Minimum 100 -Maximum 350
Start-Sleep -Milliseconds $MS
                    $Result = [pscustomobject]@{
                    Server            = "$ServerName"
                    BaseName          = 'NA'
                    Directory         = 'NA'
                    CreationTimeUtc   = 'NA'
                    LastAccessTimeUtc = 'NA'
                    LastWriteTimeUtc  = 'NA'
                    HashSHA256        = 'NA'
                    IsHashVulnerable  = 'NA'
                    ImplementationVersion='NA'
                    BundleVersion='NA'
                    IsExploitable='NA'
                    }
                    $MS = Get-Random -Minimum 100 -Maximum 350
                    Start-Sleep -Milliseconds $MS
                    $Result | Export-Csv "$OutDir\$OutFileName" -Force -NoTypeInformation -Append
                    }
} catch {
                    $MS = Get-Random -Minimum 100 -Maximum 350
                    Start-Sleep -Milliseconds $MS
                    $Result = [pscustomobject]@{
                    Server            = "$ServerName"
                    BaseName          = 'Error'
                    Directory         = "$($PSItem.ToString())"
                    CreationTimeUtc   = 'Error'
                    LastAccessTimeUtc = 'Error'
                    LastWriteTimeUtc  = 'Error'
                    HashSHA256        = 'Error'
                    IsHashVulnerable  = 'Error'
                    ImplementationVersion='Error'
                    BundleVersion='Error'
                    IsExploitable='Error'
                    }
                    $MS = Get-Random -Minimum 100 -Maximum 350
                    Start-Sleep -Milliseconds $MS
                    $Result | Export-Csv "$OutDir\$OutFileName" -Force -NoTypeInformation -Append

}
} -ImportVariables -Verbose -RunspaceTimeout $TimeoutSeconds

Start-Sleep -Seconds 1
$Captured = $(Import-csv "$OutDir\$OutFileName").Server | select -Unique
$Hosts | foreach {
if ($_ -notin $Captured) {
                    $Result = [pscustomobject]@{
                    Server            = "$_"
                    BaseName          = 'FAILED'
                    Directory         = 'FAILED TO CONNECT TO SERVER'
                    CreationTimeUtc   = 'FAILED'
                    LastAccessTimeUtc = 'FAILED'
                    LastWriteTimeUtc  = 'FAILED'
                    HashSHA256        = 'FAILED'
                    IsHashVulnerable  = 'FAILED'
                    }
                    $Result | Export-Csv "$OutDir\$OutFileName"-Force -NoTypeInformation -Append

}

}

# Create this as a function later, so it can be used from within the scriptblocks for invoke-command
$ErrorActionPreference = 'SilentlyContinue'
$Results = Import-Csv "$OutDir\$OutFileName"
$Vulnerable = $Results | where {$_.BaseName -match '-2\.*'} -ErrorAction SilentlyContinue
$Vulnerable = $Vulnerable | where {[version]::Parse(($_.BaseName).split('-')[-1]) -le [version]::Parse('2.15') -and [version]::Parse(($_.BaseName).split('-')[-1]) -ge [version]::Parse('2.0')} -ErrorAction SilentlyContinue
#$Vulnerable = $Vulnerable | where {$_.BaseName -notmatch '.*api.*'}
$Vulnerable | Export-Csv "$OutDir\Vulnerable_$OutFileName" -Force -NoTypeInformation -Append
