function Get-SNowTicket {
        [cmdletbinding()]param($Instance,$Ticket,$Credential,[switch]$PDF)
            if (!$Credential) {$Credential = Get-Credential}
            $Ticket = $Ticket.Trim()
            Write-Verbose "Processing $Ticket"
                if ($Ticket -like 'REQ*')    { $Table = 'sc_request'     } # REQUEST
                if ($Ticket -like 'INC*')    { $Table = 'incident'       } # INCIDENT
                if ($Ticket -like 'RIT*')    { $Table = 'sc_req_item'    } # REQUEST INCIDENT
                if ($Ticket -like 'PRB*')    { $Table = 'problem'        } # PROBLEM
                if ($Ticket -like 'CHG*')    { $Table = 'change_request' } # CHANGE
                if ($Ticket -like 'TASK*')   { $Table = 'sc_task'        } # TASK
                if ($Ticket -like 'CTASK*')  { $Table = 'change_task'    } # CHANGE TASK
                if ($Ticket -like 'PTASK*')  { $Table = 'problem_task'   } # PROBLEM TASK   
            $Uri = "https://$Instance.service-now.com/api/now/table/$Table`?sysparm_query=number=$Ticket&sysparm_display_value=true"
            $TicketData = (Invoke-RestMethod -Uri $Uri -Method Get -Credential $Credential).result
            $TicketData
            if ($PDF) {
                Write-Verbose "Downloading $Ticket as PDF..."
                if (!$PSScriptRoot) {$PSScriptRoot = '.\'}
                $Uri  = "https://$Instance.service-now.com/$Table.do?sys_id=$($TicketData.sys_id)&PDF"
                $Path = (New-Item -Path $PSScriptRoot  -Name PDF -ItemType Directory -Force -Verbose).FullName
                Invoke-RestMethod -Uri $URI  -Method Get -Credential $Credential -OutFile $Path\$Ticket.pdf -Verbose 
                Write-Verbose "File location: $Path\$Ticket.pdf"
                }
            }
