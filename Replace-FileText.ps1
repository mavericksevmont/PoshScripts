function Replace-FileText {
[CmdletBinding()]
[Alias("rft")]
Param($FileName,$SearchFor,$ReplaceWith)
    $Files = Get-ChildItem $FileName -Recurse -ErrorAction Stop
    $Files | ForEach-Object {(Get-Content $_) -Replace "$SearchFor","$ReplaceWith" | Set-Content $_.FullName }
    }
    
# Examples:
# rft -FileName "C:\Tests\FileName*.txt" -SearchFor 'OldWord' -ReplaceWith 'NewWord'
# Replace-FileText -FileName "C:\Tests\FileName*.txt" -SearchFor 'OldWord' -ReplaceWith 'NewWord'
