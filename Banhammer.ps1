# $debug = 1
. ( Join-Path $PSScriptRoot '_functions.ps1' )
Write-Output 'Подгружаем настройки'
if ( Test-Path -Path ( Join-Path $PSScriptRoot 'settings.json') ) {
    $settings = Get-Content -Path ( Join-Path $PSScriptRoot 'settings.json') | ConvertFrom-Json -AsHashtable; $standalone = $true
}
else {
    if ( Test-Path ( Join-Path $PSScriptRoot _settings.ps1 ) ) { . ( Join-Path $PSScriptRoot _settings.ps1 ) }
    Test-Module 'PsIni' 'для чтения настроек TLO'
    $tlo_path = Test-Setting 'tlo_path' -required
    $ini_path = Join-Path $tlo_path 'data' 'config.ini'
    Write-Log 'Читаем настройки Web-TLO'
    $ini_data = Get-IniContent $ini_path
    if ( !$settings ) { $settings = @{} }
    if ( !$settings.controller ) { $settings.controller = @{} }
    if ( !$settings.clients ) { Get-Clients ( $settings ) }
    if ( !$settings.connection ) { Set-ConnectDetails( $settings ) }
    $standalone = $false
}


if ( !$debug ) {
    Write-Log 'Проверяем актуальность Banhammer и _functions' 
    if ( ( Test-Version '_functions.ps1' 'Banhammer' ) -eq $true ) {
        Write-Log 'Запускаем новую версию  _functions.ps1'
        . ( Join-Path $PSScriptRoot '_functions.ps1' )
    }

    Test-Version ( $PSCommandPath | Split-Path -Leaf ) 'Banhammer'
}

Set-Proxy( $settings )

foreach ( $client in $settings.clients.Values ) {
    Initialize-Client $client
    if ( $client.sid ) {
        $torrents_list = Get-ClientTorrents -client $client -mess_sender 'Mover' -verbos -completed 

        Write-Log 'Анализируем пиров'
        foreach ( $torrent in ( $torrents_list | Where-Object { $_.state -in ( 'downloading', 'uploading', 'forcedUP', 'stalledDL' ) } ) ) {
            $peers = ( ( Get-TorrentPeers -client $client -hash $torrent.hash ).content | ConvertFrom-Json -AsHashtable ).peers
            foreach ( $peer_key in $peers.Keys | Where-Object { $peers[$_].up_speed -gt 0 -and $peers[$_].progress -eq 0 } ) {
                Write-Log "$($torrent.Name) $($peers[$peer_key].ip) $($peers[$peer_key].client) $( $peers[$peer_key].peer_id_client )" -Yellow
            }
        }
    }
}
Write-Log 'Кончили анализировать'
