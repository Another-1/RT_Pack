$ProgressPreference = 'SilentlyContinue'
Write-Output 'Подгружаем настройки'

try {
    . ( Join-Path $PSScriptRoot _settings.ps1 )
}
catch { Write-Host ( 'Не найден файл настроек ' + ( Join-Path $PSScriptRoot _settings.ps1 ) + ', видимо это первый запуск.' ) }

$str = 'Подгружаем функции'
if ( $use_timestamp -ne 'Y' ) { Write-Host $str } else { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) }
. ( Join-Path $PSScriptRoot _functions.ps1 )

Test-PSVersion
if ( ( Test-Version '_functions.ps1' 'Adder' ) -eq $true ) {
    Write-Log 'Запускаем новую версию  _functions.ps1'
    . ( Join-Path $PSScriptRoot '_functions.ps1' )
}
Test-Version ( $PSCommandPath | Split-Path -Leaf ) 'Marker'

$use_timestamp = Test-Setting 'use_timestamp'
$tlo_path = Test-Setting 'tlo_path' -required
$ini_path = Join-Path $tlo_path 'data' 'config.ini'
Write-Log 'Читаем настройки Web-TLO'
$ini_data = Get-IniContent $ini_path

$clients = Get-Clients
$clients_torrents = Get-ClientsTorrents -clients $clients -mess_sender 'Marker' -noIDs

foreach ( $torrent in $clients_torrents ) {
    if ( $torrent.state -in ( 'downloading', 'forcedDL', 'stalledDL', 'pausedDL') -and $torrent.tags -notlike "*$down_tag*" ) {
        Set-Comment -client $clients[$torrent.client_key] -torrent $torrent -label $down_tag
    }
    elseif ( $torrent.state -in ( 'queuedUP', 'stalledUP', 'forcedUP', 'pausedUP', 'uploading' ) -and $torrent.tags -notlike "*$seed_tag*" ) {
        if ( -and $torrent.tags -like "*$down_tag*" ) {
            Remove-Comment -client $clients[$torrent.client_key] -torrent $torrent -label $down_tag -silent
        }
    
        Set-Comment -client $clients[$torrent.client_key] -torrent $torrent -label $seed_tag -silent
    }
}
