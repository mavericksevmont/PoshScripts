
function Replace-FileText {
[CmdletBinding()]
[Alias("rft")]
Param($FileName,$SearchFor,$ReplaceWith)
$Files = gci $FileName -Recurse -ErrorAction Stop
$Files | % {(gc $_) -replace "$Find","$ReplaceWith" | sc $_.fullname }
}

# Works for multiple files and/or directories. Examples:
rft -FileName "C:\Tests\FileName*.txt" -SearchFor 'OldWord' -ReplaceWith 'NewWord'
Replace-FileText -FileName "C:\Tests*\FileName*.txt" -SearchFor 'OldWord' -ReplaceWith 'NewWord'
