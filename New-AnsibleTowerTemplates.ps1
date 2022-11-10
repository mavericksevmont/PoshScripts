# Create templates in Ansible Tower
# Documentation:
# https://docs.ansible.com/ansible-tower/latest/html/towerapi/api_ref.html
# https://AnsibleTowerurihere/api/v2/roles/
# https://www.pdq.com/blog/how-to-manage-powershell-secrets-with-secretsmanagement/

# MANDATORY Vars
$Token            = 'TOKENIDHERE' # Use secret store, don't be that kind of lazy
$TowerURL         = 'ansibletowerurihere'
$OrgId            = 5   # sample id
$ProjectId        = 5   # sample id
$InventoryId      = 5   # sample id
$User             = 5   # sample id
$InstanceGroupId  = 5   # sample id
$TemplateBaseName = 'templatename'
$PlaybookBaseName = 'playbookname'
$Description      = 'Test: Created from REST API'
$ContentType      = 'application/json'
$headers          = @{ Authorization = "Bearer $Token" }

# Create Workflow template
Write-Host "Creating WF Template" -ForegroundColor Green
$URI  = "https://$TowerURL/api/v2/workflow_job_templates/"
$body = @{
    name                    = "$TemplateBaseName-wf"
    description             = $Description
    organization            = $OrgId
    ask_variables_on_launch = 'True'
    allow_simultaneous      = 'True'
} | ConvertTo-Json
$WFData = Invoke-RestMethod `
-Uri $URI `
-Headers $headers `
-Body $body `
-SkipCertificateCheck `
-Method Post `
-ContentType $ContentType

#Add permissions to WF template:
Write-Host "Adding permissions to WF Template" -ForegroundColor Cyan
$URI  = "https://$TowerURL/api/v2/users/$User/roles/" 
$body = @{ id = $WFData.summary_fields.object_roles.execute_role.id } | ConvertTo-Json 
$WFPermissions = Invoke-RestMethod `
-Uri $URI `
-Headers $headers `
-Body $body `
-SkipCertificateCheck `
-Method Post `
-ContentType $ContentType 

# Create all templates and add to workflow
$Regions = @('ae','eus','gwc','scus','sea','suk')
$Regions | foreach {
Write-Host "Creating JT for $_" -ForegroundColor Green
$TemplateName = "$TemplateBaseName-$_-jt"
$PlaybookName = "$PlaybookBaseName-$_.yml"
$URI          = "https://$TowerURL/api/v2/organizations/$OrgId/job_templates/"
$Method       = 'POST'

#Create Job Template
$body        = @{
    name        = $TemplateName
    project     = $ProjectId 
    inventory   = $InventoryId 
    playbook    = $PlaybookName 
    description = $Description
    ask_variables_on_launch = 'True'
    ask_verbosity_on_launch = 'True'
    allow_simultaneous      = 'True'
                } | ConvertTo-Json
$JTData = Invoke-RestMethod `
-Uri $URI `
-Headers $headers `
-Body $body `
-SkipCertificateCheck `
-Method $Method `
-ContentType $ContentType

# Add credentials
Write-Host "Adding Credentials to JT" -ForegroundColor Cyan
$CredentialIds = 9,7 # sample ids
$URI  = "https://$TowerURL/api/v2/job_templates/$($JTData.id)/credentials/"
$CredentialIds | foreach {
$body = @{ id = $_ } | ConvertTo-Json
$JTCredentials = Invoke-RestMethod `
-Uri $URI `
-Headers $headers `
-Body $body `
-SkipCertificateCheck `
-Method Post `
-ContentType $ContentType 
}

# Add Instance Group
Write-Host "Adding Intance Group to JT" -ForegroundColor Cyan
$URI  = "https://$TowerURL/api/v2/job_templates/$($JTData.id)/instance_groups/"
$body = @{ id = $InstanceGroupId } | ConvertTo-Json
$InstanceJT = Invoke-RestMethod `
-Uri $URI `
-Headers $headers `
-Body $body `
-SkipCertificateCheck `
-Method Post `
-ContentType $ContentType 

# Add permissions
#$JTData.summary_fields.object_roles.read_role.id
#$JTData.summary_fields.object_roles.execute_role.id
Write-Host "Adding Permissions to JT" -ForegroundColor Cyan
$URI  = "https://$TowerURL/api/v2/users/$User/roles/"
$body = @{ id = $JTData.summary_fields.object_roles.execute_role.id } | ConvertTo-Json 
$PermissionsJT = Invoke-RestMethod `
-Uri $URI `
-Headers $headers `
-Body $body `
-SkipCertificateCheck `
-Method Post `
-ContentType $ContentType 

# Add jt node to workflow
Write-Host "Adding JT node to Workflow" -ForegroundColor Cyan
$URI  = "https://$TowerURL/api/v2/workflow_job_templates/$($WFData.id)/workflow_nodes/"
$body = @{ unified_job_template = $JTData.id } | ConvertTo-Json  # job template id 
$NodeData = Invoke-RestMethod `
-Uri $URI `
-Headers $headers `
-Body $body `
-SkipCertificateCheck `
-Method Post `
-ContentType $ContentType
} #End foreach loop
