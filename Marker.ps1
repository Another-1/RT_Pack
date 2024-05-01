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
$down_tag = Test-Setting 'down_tag' -required
$seed_tag = Test-Setting 'seed_tag' -required
$tg_token = Test-Setting 'tg_token'
if ( $tg_token -ne '') {
    $tg_chat = Test-Setting 'tg_chat' -required
}

$ini_path = Join-Path $tlo_path 'data' 'config.ini'
Write-Log 'Читаем настройки Web-TLO'
$ini_data = Get-IniContent $ini_path

$clients = Get-Clients
$clients_torrents = Get-ClientsTorrents -clients $clients -mess_sender 'Marker' -noIDs
$seed_cnt = 0
$down_cnt = 0

$test_torrent = @( $clients_torrents | Where-Object { $_.name -eq 'Boredoms' } ) | Select-Object -First 1
if ( $test_torrent ) { $test_torrent }
Pause

foreach ( $torrent in $clients_torrents ) {
    if ( $torrent.state -in ( 'downloading', 'forcedDL', 'stalledDL', 'pausedDL') ) {
        if ( $torrent.tags -notlike "*$down_tag*" ) {
            Write-Log "Метим раздачу $($torrent.name) меткой $down_tag"
            Set-Comment -client $clients[$torrent.client_key] -torrent $torrent -label $down_tag
            $torrent.state = 'OK'
        }
        $down_cnt++
    }
    elseif ( $torrent.state -in ( 'queuedUP', 'stalledUP', 'forcedUP', 'pausedUP', 'uploading' ) ) {
        if ( $torrent.tags -like "*$down_tag*" ) {
            Write-Log "Снимаем с раздачи $($torrent.name) метку $down_tag"
            Remove-Comment -client $clients[$torrent.client_key] -torrent $torrent -label $down_tag -silent
        }
        if ( $torrent.tags -notlike "*$seed_tag*" ) {
            Write-Log "Метим раздачу $($torrent.name) меткой $seed_tag"
            Set-Comment -client $clients[$torrent.client_key] -torrent $torrent -label $seed_tag -silent
            $seed_cnt++            
        }
        if ( $torrent.state -eq 'forcedUP' ) {
            Write-Log "Перевожу раздачу $($torrent.name) в статус Seeding"
            $start_keys = @($torrent.hash)
            Start-Torrents -hashes $start_keys -client $clients[$torrent.client_key]
        }
    }
}
Send-TGMessage -message "Переведено в seeding: $seed_cnt`nОсталось в downloading: $down_cnt" -token $tg_token -chat_id $tg_chat -mess_sender 'Marker'
