# $debug = 1
. ( Join-Path $PSScriptRoot '_functions.ps1' )
Write-Output 'Подгружаем настройки'
if ( Test-Path -Path ( Join-Path $PSScriptRoot 'settings.json') ) {
    $settings = Get-Content -Path ( Join-Path $PSScriptRoot 'settings.json') | ConvertFrom-Json -AsHashtable; $standalone = $true
}
else {
    if ( Test-Path ( Join-Path $PSScriptRoot _settings.ps1 ) ) { . ( Join-Path $PSScriptRoot _settings.ps1 ) }
    Test-Module -module 'PSIni' -description 'для чтения настроек TLO' -MinimumVersion '4.0.0.0'
    $tlo_path = Test-Setting 'tlo_path' -required
    $ini_path = Join-Path $tlo_path 'data' 'config.ini'
    Write-Log 'Читаем настройки Web-TLO'
    $ini_data = Remove-Quotes( Import-Ini $ini_path )
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
# $settings.controller.old_starts_per_run = Test-Setting 'old_starts_per_run' -json_section $json_section
$settings.controller.min_stop_to_start = Test-Setting 'min_stop_to_start' -json_section $json_section

if ( $standalone -eq $false ) {
    $settings.controller.global_peers = $ini_data['topics_control'].peers
    $settings.controller.priority = $ini_data['topics_control'].priority
    $settings.controller.intervals = $ini_data['topics_control'].intervals
    $settings.controller.min_stop_to_start = $ini_data['topics_control'].days_until_unseeded ? $ini_data['topics_control'].days_until_unseeded : $min_stop_to_start
    $settings.controller.old_starts_per_run = $ini_data['topics_control'].max_unseeded_count
}

if ( $settings.controller.intervals ) {
    Write-Log 'Включен "Динамический набор интервалов количества пиров", игнорируем прочие настройки регулировки'
    $intervals_array = $settings.controller.intervals.split('/').split('|') | ForEach-Object { $_ -notlike '*:*' ?  "1:$_" : $_ }
    $hourly = @{}
    $hour = 0
    foreach ( $interval in $intervals_array ) {
        $seeds = ( $interval | Select-String -Pattern '\d+$' ).matches[0].value.ToInt32($null)
        $length = ( $interval | Select-String -Pattern '^\d+' ).matches[0].value.ToInt32($nul)
        0..($length - 1) | ForEach-Object {
            $hour += 1
            $hourly[$hour] = $seeds
        }
    }
    $interval_seeds = $hourly[ ( Get-Date).Hour ]
    Write-Log "В $( Get-Spell (Get-Date).Hour -entity 'hours' ) лимит сидов установлен в $interval_seeds"
}

else {
    if ( $settings.controller.priority -eq '1' ) {
        # регулировка на уровне раздела
        Write-Log 'Выбрана регулировка по подразделам'
        $settings.sections.keys | ForEach-Object {
            $settings.sections[$_].control_peers = ( $settings.sections[$_].control_peers -ne '' ? $settings.sections[$_].control_peers : $settings.controller.global_peers ).ToInt32($null)
        }
    }
    else {
        #регулировка на уровне клиента
        Write-Log 'Выбрана регулировка по клиентам'
        $settings.clients.Keys | ForEach-Object { $settings.clients[$_].control_peers = ( $settings.clients[$_].control_peers -ne '' ? $settings.clients[$_].control_peers : $settings.controller.global_peers ).ToInt32($null) }
    }
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
$ProgressPreference = 'SilentlyContinue' # чтобы не мелькать прогресс-барами от скачивания торрентов

Set-Proxy( $settings )

if ( !$tracker_torrents) {
    Write-Log 'Автономный запуск, надо сходить на трекер за актуальными сидами и ID'
    $tracker_torrents = Get-RepTorrents -sections $settings.sections.keys -call_from 'Controller'
}
if ( !$clients_torrents -or $clients_torrents.count -eq 0 ) {
    Get-ClientApiVersions $settings.clients
    $clients_torrents = Get-ClientsTorrents 'Controller'
    # $hash_to_id = @{}
    # $id_to_info = @{}
    
    # Write-Log 'Сортируем таблицы'
    # $clients_torrents | Where-Object { $null -ne $_.topic_id } | ForEach-Object {
    #     if ( !$_.infohash_v1 -or $nul -eq $_.infohash_v1 -or $_.infohash_v1 -eq '' ) { $_.infohash_v1 = $_.hash }
    #     $hash_to_id[$_.infohash_v1] = $_.topic_id
    #     $id_to_info[$_.topic_id] = 1
    # }
}
Remove-Variable -Name 'hash_to_id' -ErrorAction SilentlyContinue
Remove-Variable -Name 'id_to_info' -ErrorAction SilentlyContinue

if ( !$api_seeding -or $debug -eq $false ) {
    $states = @{}
    $api_seeding = Get-RepSeeding -sections $settings.sections.keys -seeding_days $min_stop_to_start -call_from 'Controller'
    if ( $null -eq $api_seeding ) { exit }
    Write-Log 'Осмысливаем полученное'
    $clients_torrents | Where-Object { $null -ne $_.topic_id } | ForEach-Object {
        $states[$_.hash] = @{
            client    = $_.client_key
            state     = $_.state
            save_path = $_.save_path
            topic_id  = $_.topic_id
        }
        # if ( ( $api_seeding[$_.topic_id] -gt 0 ? $api_seeding[$_.topic_id] : ( $ok_to_start ).AddDays( -1 ) ) -le $ok_to_start ) {
        #     $long_ago[$_.hash] = 1
        # }
    }
}

$hash_to_client = @{}
$clients_torrents | ForEach-Object { $hash_to_client[$_.hash] = $_.client_key }

$batch_size = 400

$started = 0
$stopped = 0
if (  $rss ) {
    $settings.clients.Remove( $rss.client ? $rss.client : 'RSS' )
    if (  $rss2 ) {
        $settings.clients.Remove( $rss2.client ? $rss2.client : 'RSS2' )
    }
}
# $started_counts = @{}
$started_olds = 0
foreach ( $client_key in $settings.clients.keys ) {
    # foreach ( $client_key in $settings.clients.keys | Where-Object { $_ -ne 'Aorus' } ) {
    # Write-Log ( 'Регулируем клиент ' + $client_key + ( $stop_forced -eq $true ? ' с остановкой принудительно запущенных' : '' ) )
    $start_keys = @()
    $stop_keys = @()
    $states.Keys | Where-Object { $states[$_].client -eq $client_key } | ForEach-Object {
        try { 
            $switching_peers = $interval_seeds ? $interval_seeds : $settings.controller.priority -eq '1' ? $settings.sections[$tracker_torrents[$_].section].control_peers : $settings.clients[$hash_to_client[$_]]
            if ( $states[$_].state -eq $settings.clients[$client_key].stopped_state ) {
                if ( $tracker_torrents[$_].seeders -lt $switching_peers -or ( $api_seeding[$states[$_].topic_id] -gt 0 ? $api_seeding[$states[$_].topic_id] : ( $ok_to_start ).AddDays( -1 ) ) -le $ok_to_start ) {
                    if ( $tracker_torrents[$_].seeders -ge $switching_peers -and $api_seeding[$states[$_].topic_id] -gt 0 ? $api_seeding[$states[$_].topic_id] : ( $ok_to_start ).AddDays( -1 ) -le $ok_to_start ) {
                        $started_olds += 1
                        if ( $started_olds -ge $settings.controller.old_starts_per_run ) {
                            continue
                        }
                    }
                    if ( $start_keys.count -eq $batch_size ) {
                        Start-Torrents $start_keys $settings.clients[$client_key] -mess_sender 'Controller'
                        $started += $start_keys.count
                        $start_keys = @()
                    }
                    if ( -not( $busy_disks -and $states[$_].save_path[0] -in $busy_disks[$client_key] )) {
                        $start_keys += $_
                        $states[$_].state = 'uploading' # чтобы потом правильно запустить старые
                        # if ( $null -eq $started_counts[$settings.sections[$tracker_torrents[$_].section].label] ) { $started_counts[$settings.sections[$tracker_torrents[$_].section].label] = 0 }
                        # $started_counts[$settings.sections[$tracker_torrents[$_].section].label] += 1
                    }
                    else { write-Log "Раздача $_ на слишком занятом сейчас диске" }
                }
            }
            elseif ( $states[$_].state -in @('uploading', 'stalledUP', 'queuedUP', 'forcedUP' ) ) {
                if ( ( $states[$_].state -ne 'forcedUP' -or $stop_forced -eq 'Y' ) `
                        -and $tracker_torrents[$_].seeders -gt $switching_peers -and $api_seeding[$states[$_].topic_id] -gt 0 ? $api_seeding[$states[$_].topic_id] : ( $ok_to_start ).AddDays( -1 ) -gt $ok_to_start ) {

                    if ( $stop_keys.count -eq $batch_size ) {
                        Stop-Torrents $stop_keys $settings.clients[$client_key] -mess_sender 'Controller'
                        $stopped += $stop_keys.count
                        $stop_keys = @()
                    }
                    $stop_keys += $_
                }
                # else {
                #     if ( $null -eq $started_counts[$settings.sections[$tracker_torrents[$_].section].label] ) { $started_counts[$settings.sections[$tracker_torrents[$_].section].label] = 0 }
                #     $started_counts[$settings.sections[$tracker_torrents[$_].section].label] += 1
                # }
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
