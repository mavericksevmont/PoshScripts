# GET RESULTS DIRECTLY THROUGH URL FILTER
# Documentation: https://docs.ansible.com/ansible-tower/latest/html/towerapi/api_ref.html
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Bearer SuperSecretTokenGoesHere")
$headers.Add("ask_credential_on_launch", "false") 
$JobID    = '337947' # The Job ID
# $ TaskName is the Name of the task you want to pull the data from, replace spaces with %20, output from this task must be json format, e.g. "| to_json"
$TaskName = 'Print%20Script%20Results' 
$URI      = "https://ansibletowerdomainurlthingnamegoeshere/api/v2/jobs/$JobId/job_events/?event__contains=runner_on_ok&task__contains=$TaskName"
$Results = Invoke-RestMethod -Uri $URI -Headers $headers
$Results.results.event_data.res.msg # try to surf the previous properties if you don't see your data
