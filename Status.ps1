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
if ( ( Test-Version '_functions.ps1' 'Status' ) -eq $true ) {
    Write-Log 'Запускаем новую версию  _functions.ps1'
    . ( Join-Path $PSScriptRoot '_functions.ps1' )
}

Test-Version ( $PSCommandPath | Split-Path -Leaf ) 'Status'

if ( Test-Path ( Join-Path $PSScriptRoot 'settings.json') ) {
    $settings = Get-Content -Path ( Join-Path $PSScriptRoot 'settings.json') | ConvertFrom-Json -AsHashtable
    $standalone = $true
}
else {
    try {
        . ( Join-Path $PSScriptRoot _settings.ps1 )
        $settings = [ordered]@{}
        $settings.interface = @{}
        $settings.interface.use_timestamp = ( $use_timestamp -eq 'Y' ? 'Y' : 'N' )
        $standalone = $false
    }
    catch { Write-Host ( 'Не найден файл настроек ' + ( Join-Path $PSScriptRoot _settings.ps1 ) + ', видимо это первый запуск.' ) }
}

if ( $standalone -eq $false ) {
    $tlo_path = Test-Setting 'tlo_path' -required
    $ini_path = Join-Path $tlo_path 'data' 'config.ini'
    Write-Log 'Читаем настройки Web-TLO'
    $ini_data = Remove-Quotes( Import-Ini $ini_path )
}

$use_timestamp = Test-Setting 'use_timestamp'
$tlo_path = Test-Setting 'tlo_path' -required
$tg_token = Test-Setting 'tg_token'
if ( $tg_token -ne '') {
    $tg_chat = Test-Setting 'tg_chat' -required
}

Get-Clients
if ( $rss_mark -and $rss_mark.ToUpper() -eq 'N' -and $rss ) { 
    if ( $rss.client ) {
        $settings.clients.Remove( $rss.client )
    }
}

Get-ClientApiVersions -clients $settings.clients
if ( !$clients_torrents ) {
    $clients_torrents = Get-ClientsTorrents -mess_sender 'Status' -noIDs
}

$overall = [ordered]@{}
foreach ( $client in $settings.clients.Keys ) {
    # if ( !$overall[$client] ) { $overall[$client] = [ordered]@{ seeding = 0; downloading = 0; stalled = 0; stopped = 0; checking = 0; error = 0 } }
    if ( !$overall[$client] ) { $overall[$client] = [ordered]@{ } }
    foreach ( $torrent in $clients_torrents | Where-Object { $_.client_key -eq $client } ) {
        if ( $torrent.state -in ( 'queuedUP', 'stalledUP', 'forcedUP', 'uploading' ) ) {
            if ( !$overall[$client].seeding ) { $overall[$client].seeding = 1 } else { $overall[$client].seeding++ }
        }
        elseif ( $torrent.state -in ( 'downloading', 'forcedDL', 'metaDL', 'queuedDL', 'allocating' ) ) {
            if ( !$overall[$client].downloading ) { $overall[$client].downloading = 1 } else { $overall[$client].downloading++ }
        }
        elseif ( $torrent.state -eq 'stalledDL' ) {
            if ( !$overall[$client].stalled ) { $overall[$client].stalled = 1 } else { $overall[$client].stalled++ }
        }
        elseif ( $torrent.state -in ( $settings.clients[$torrent.client_key].stopped_state_dl, $settings.clients[$torrent.client_key].stopped_state ) ) {
            if ( !$overall[$client].stopped ) { $overall[$client].stopped = 1 } else { $overall[$client].stopped++ }
        }
        elseif ( $torrent.state -in ( 'checkingUP', 'checkingDL', 'checkingResumeData' ) ) {
            if ( !$overall[$client].checking ) { $overall[$client].checking = 1 } else { $overall[$client].checking++ }
        }
        elseif ( $torrent.state -in ( 'missingFiles', 'error' ) ) {
            if ( !$overall[$client].error ) { $overall[$client].error = 1 } else { $overall[$client].error++ }
        }
    }
}

$message = ''
$overall.Keys | ForEach-Object {
    if ( $message -ne '') { $message += "`n`n" }
    $message += "<b><u>Клиент $_</u></b>"
    if ( $overall[$_].seeding ) { $message += "`nSeeding: $( $overall[$_].seeding)" }
    if ( $overall[$_].downloading ) { $message += "`nDownloading: $( $overall[$_].downloading)" }
    if ( $overall[$_].stalled ) { $message += "`nStalled: $( $overall[$_].stalled)" }
    if ( $overall[$_].stopped ) { $message += "`nStopped: $( $overall[$_].stopped)" }
    if ( $overall[$_].checking ) { $message += "`nChecking: $( $overall[$_].checking)" }
    if ( $overall[$_].error ) { $message += "`nError: $( $overall[$_].error)" }
}
$settings.telegram = @{}
$settings.telegram.tg_token = Test-Setting 'tg_token' -json_section $json_section
$settings.telegram.tg_chat = Test-Setting 'tg_chat' -required -json_section $json_section
Send-TGMessage -message $message -token $settings.telegram.tg_token -chat_id $settings.telegram.tg_chat -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')
