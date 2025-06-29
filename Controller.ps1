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
    if ( !$settings.sections ) {
        $sections = Get-IniSections
        Get-IniSectionDetails $settings $sections
    }
    if ( $control_override -and !$settings.controller.control_override ) { $settings.controller.control_override = $control_override }
    if ( !$settings.connection ) { Set-ConnectDetails( $settings ) }
    $standalone = $false
}

$json_section = ( $standalone -eq $true ? 'controller' : '' )
$settings.controller.old_starts_per_run = Test-Setting 'old_starts_per_run' -json_section $json_section

$settings.controller.min_stop_to_start = Test-Setting 'min_stop_to_start' -json_section $json_section

if ( $standalone -eq $false ) {
    $settings.controller.global_seeds = $ini_data['topics_control'].peers
    $settings.controller.priority = $ini_data['topics_control'].priority
}

if ( $settings.controller.priority -eq '1' ) {
    # регулировка на уровне раздела
    $settings.sections.keys | ForEach-Object { $settings.sections[$_].control_peers = ( $settings.sections[$_].control_peers -ne '' ? $settings.sections[$_].control_peers : -2 ).ToInt32($null) }
    $settings.sections.Keys | Where-Object { $settings.sections[$_].control_peers -eq -2 } | ForEach-Object { $settings.sections[$_].control_peers = $settings.controller.global_seeds.ToInt32($null) }
}
else {
    #регулировка на уровне клиента
    $settings.sections.keys | ForEach-Object { $settings.sections[$_].control_peers = $settings.clients[$settings.sections[$_].client].control_peers }
    $settings.sections.Keys | Where-Object { $settings.sections[$_].control_peers -eq -2 } | ForEach-Object { $settings.sections[$_].control_peers = $settings.controller.global_seeds.ToInt32($null) }
}

if ( !$debug ) {
    Write-Log 'Проверяем актуальность Controller и _functions' 
    if ( ( Test-Version '_functions.ps1' 'Controller' ) -eq $true ) {
        Write-Log 'Запускаем новую версию  _functions.ps1'
        . ( Join-Path $PSScriptRoot '_functions.ps1' )
    }

    Test-Version ( $PSCommandPath | Split-Path -Leaf ) 'Controller'
}

Write-Log 'Строим таблицы'

$ok_to_start = (Get-Date).ToUniversalTime().AddDays( 0 - $settings.controller.min_stop_to_start )
if ( $settings.controller.control_override -and (Get-Date).hour -in $settings.controller.control_override.hours ) { 
    foreach ( $section in @($settings.sections.Keys) ) {
        if ( !$settings.sections[$section].client ) {
            Write-Log "Не указан клиент для подраздела $section" -Red
            continue
        }
        if ( $settings.controller.control_override.client -and $settings.controller.control_override.client[$settings.sections[$section].client] ) {
            $settings.sections[$section].control_peers = $settings.controller.control_override.client[$settings.sections[$section].client]
        }
        elseif ( $settings.controller.control_override.global ) {
            $settings.sections[$section].control_peers = $settings.controller.control_override.global
        }
    }
}

$long_ago = @{}

$ProgressPreference = 'SilentlyContinue' # чтобы не мелькать прогресс-барами от скачивания торрентов

Set-Proxy( $settings )

if ( !$tracker_torrents) {
    Write-Log 'Автономный запуск, надо сходить на трекер за актуальными сидами и ID'
    $tracker_torrents = Get-RepTorrents -sections $settings.sections.keys -call_from 'Controller'
}
if ( !$clients_torrents -or $clients_torrents.count -eq 0 ) {
    Get-ClientApiVersions $settings.clients
    $clients_torrents = Get-ClientsTorrents 'Controller'
    $hash_to_id = @{}
    $id_to_info = @{}
    
    Write-Log 'Сортируем таблицы'
    $clients_torrents | Where-Object { $null -ne $_.topic_id } | ForEach-Object {
        if ( !$_.infohash_v1 -or $nul -eq $_.infohash_v1 -or $_.infohash_v1 -eq '' ) { $_.infohash_v1 = $_.hash }
        $hash_to_id[$_.infohash_v1] = $_.topic_id
        $id_to_info[$_.topic_id] = 1
    }
}

if ( !$api_seeding -or $debug -eq $false ) {
    $states = @{}
    $api_seeding = Get-APISeeding -sections $settings.sections.keys -seeding_days $min_stop_to_start -call_from 'Controller'
    if ( $null -eq $api_seeding ) { exit }
    Write-Log 'Осмысливаем полученное'
    $clients_torrents | Where-Object { $null -ne $_.topic_id } | ForEach-Object {
        $states[$_.hash] = @{
            client    = $_.client_key
            state     = $_.state
            # seeder_last_seen = $( $null -ne $api_seeding[$_.topic_id] -and $api_seeding[$_.topic_id] -gt 0 ? $api_seeding[$_.topic_id] : ( $ok_to_start ).AddDays( -1 ) )
            save_path = $_.save_path
        }
        if ( ( $api_seeding[$_.topic_id] -gt 0 ? $api_seeding[$_.topic_id] : ( $ok_to_start ).AddDays( -1 ) ) -le $ok_to_start ) {
            $long_ago[$_.hash] = 1
        }
    }
}

$batch_size = 400

$started = 0
$stopped = 0
if (  $rss ) {
    $settings.clients.Remove( $rss.client ? $rss.client : 'RSS' )
}
foreach ( $client_key in $settings.clients.keys ) {
    Write-Log ( 'Регулируем клиент ' + $client_key + ( $stop_forced -eq $true ? ' с остановкой принудительно запущенных' : '' ) )

    $start_keys = @()
    $stop_keys = @()
    $states.Keys | Where-Object { $states[$_].client -eq $client_key } | ForEach-Object {
        try { 
            # if ( $states[$_].state -eq 'pausedUP' -and $tracker_torrents[$_].seeders -lt $section_seeds[$tracker_torrents[$_].section] ) {
            if ( $states[$_].state -eq $settings.clients[$client_key].stopped_state -and ( $tracker_torrents[$_].seeders -lt $settings.sections[$tracker_torrents[$_].section].control_peers -or $long_ago[$_] ) ) {
                if ( $start_keys.count -eq $batch_size ) {
                    Start-Torrents $start_keys $settings.clients[$client_key] -mess_sender 'Controller'
                    $started += $start_keys.count
                    $start_keys = @()
                }
                if ( -not( $busy_disks -and $states[$_].save_path[0] -in $busy_disks[$client_key] )) {
                    $start_keys += $_
                    $states[$_].state = 'uploading' # чтобы потом правильно запустить старые
                }
                else { write-Log "Раздача $_ на слишком занятом сейчас диске" }
            }
            elseif ( ( $states[$_].state -in @('uploading', 'stalledUP', 'queuedUP') -or ( $states[$_].state -eq 'forcedUP' -and $stop_forced -eq 'Y' ) ) `
                    -and $tracker_torrents[$_].seeders -gt ( $settings.sections[$tracker_torrents[$_].section].control_peers + $( $null -eq $hysteresis ? 0 : $hysteresis ) ) `
                    -and !$long_ago[$_]
            ) {

                if ( $stop_keys.count -eq $batch_size ) {
                    Stop-Torrents $stop_keys $settings.clients[$client_key] -mess_sender 'Controller'
                    $stopped += $stop_keys.count
                    $stop_keys = @()
                }
                $stop_keys += $_
            }
        }
        catch { } # на случай поглощённых раздач.
    }
    if ( $start_keys.count -gt 0 ) {
        Start-Torrents -hashes $start_keys -client $settings.clients[$client_key] -mess_sender 'Controller'
        $started += $start_keys.count
    }
    if ( $stop_keys.count -gt 0 ) {
        Stop-Torrents -hashes $stop_keys -client $settings.clients[$client_key] -mess_sender 'Controller'
        $stopped += $stop_keys.count
    }
}

$lv_str1 = "Запущено: $( Get-Spell -qty $started -spelling 1 -entity 'torrents' ). "
$lv_str2 = "Остановлено: $( Get-Spell -qty $stopped -spelling 1 -entity 'torrents' )."
$lv_str = "$lv_str1`n$lv_str2"
Write-Log ( $lv_str1 + $lv_str2 )
if ( $report_controller -eq 'Y') { Send-TGMessage -message $lv_str -token $tg_token -chat_id $tg_chat -mess_sender 'Controller' }
