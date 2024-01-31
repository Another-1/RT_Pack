Write-Output 'Подгружаем функции'
. "$PSScriptRoot\_functions.ps1"

Test-Version ( $PSCommandPath | Split-Path -Leaf )
Test-Version ( '_functions.ps1' )
Test-PSVersion
Test-Module 'PsIni' 'для чтения настроек TLO'
Test-Module 'PSSQLite' 'для работы с базой TLO'