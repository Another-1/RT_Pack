# function  Start-batch {
#     $spell = Get-Spell $start_keys.count 2
#     Write-Log ( "Запускаем $spell в клиенте " + $clients[$client].name )
#     Start-Torrents $start_keys $clients[$client]
#     # Set-StartStop $start_keys
# }
# function  Stop-batch {
#     $spell = Get-Spell $stop_keys.count 2
#     Write-Log ( "Тормозим $spell в клиенте " + $clients[$client].name )
#     Stop-Torrents $stop_keys $clients[$client]
#     # Set-StartStop $stop_keys
# }

if ( !$tracker_torrents) {
    Write-Output 'Подгружаем настройки'

    # $separator = $( $PSVersionTable.OS.ToLower().contains('windows') ? '\' : '/' )
    . ( Join-Path $PSScriptRoot '_settings.ps1' )

    $str = 'Подгружаем функции'
    if ( $use_timestamp -ne 'Y' ) { Write-Host $str } else { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) }
    . ( Join-Path $PSScriptRoot '_functions.ps1' )
}

Write-Log 'Проверяем актуальность Controller и _functions' 
if ( ( Test-Version '_functions.ps1' 'Controller' ) -eq $true ) {
    Write-Log 'Запускаем новую версию  _functions.ps1'
    . ( Join-Path $PSScriptRoot '_functions.ps1' )
}
Test-Version ( $PSCommandPath | Split-Path -Leaf ) 'Controller'
Remove-Item ( Join-Path $PSScriptRoot '*.new' ) -ErrorAction SilentlyContinue

If ( !$ini_data) {
    Test-Module 'PsIni' 'для чтения настроек TLO'
    # Test-Module 'PSSQLite' 'для работы с базой TLO'
    $tlo_path = Test-Setting 'tlo_path' -required
    $ini_path = Join-Path $tlo_path 'data' 'config.ini'
    Write-Log 'Читаем настройки Web-TLO'
    $ini_data = Get-IniContent $ini_path
}
# $hours_to_stop = Test-Setting 'hours_to_stop'
# $ok_to_stop = (Get-Date).ToUniversalTime().AddHours( 0 - $hours_to_stop )
$ok_to_stop = (Get-Date).ToUniversalTime().AddDays( -1 )
$old_starts_per_run = Test-Setting 'old_starts_per_run'
$min_stop_to_start = Test-Setting 'min_stop_to_start'
$ok_to_start = (Get-Date).ToUniversalTime().AddDays( 0 - $min_stop_to_start )
$auto_update = Test-Setting 'auto_update'

$global_seeds = $ini_data['topics_control'].peers
$section_seeds = @{}

Write-Log 'Строим таблицы'
$sections = $ini_data.sections.subsections.split( ',' )
$section_details = Get-IniSectionDetails $sections
$sections | ForEach-Object { $section_seeds[$_] = ( $section_details[$_].control_peers -ne '' ? $section_details[$_].control_peers : $global_seeds ) }
if ( $control_override -and (Get-Date).hour -in $control_override.hours ) { 
    foreach ( $section in @($section_seeds.Keys) ) {
        if ( $control_override.client[$clients[$section_details[$section].client].Name] ) {
            $section_seeds[$section] = $control_override.client[$clients[$section_details[$section].client].Name]
        }
        elseif ( $control_override.global ) {
            $section_seeds[$section] = $control_override.global
        }

    }
}
$states = @{}
$paused_sort = [System.Collections.ArrayList]::new()

$ProgressPreference = 'SilentlyContinue' # чтобы не мелькать прогресс-барами от скачивания торрентов

if ( !$tracker_torrents) {
    Write-Log 'Автономный запуск, надо сходить на трекер за актуальными сидами и ID'
    $forum = Set-ForumDetails # чтобы подтянуть настройки прокси для следующего шага
    # $tracker_torrents = Get-TrackerTorrents $sections -1 # без ограничения на количество сидов. Нужно чтобы получить оттуда сидов.
    $tracker_torrents = Get-APITorrents -sections $sections -id $ini_data.'torrent-tracker'.user_id -api_key $ini_data.'torrent-tracker'.api_key -call_from 'Controller'
}
if ( !$clients_torrents -or $clients_torrents.count -eq 0 ) {
    $clients = Get-Clients
    $clients_torrents = Get-ClientsTorrents $clients 'Controller'
    $hash_to_id = @{}
    $id_to_info = @{}
    
    Write-Log 'Сортируем таблицы'
    $clients_torrents | Where-Object { $null -ne $_.topic_id } | ForEach-Object {
        if ( !$_.infohash_v1 -or $nul -eq $_.infohash_v1 -or $_.infohash_v1 -eq '' ) { $_.infohash_v1 = $_.hash }
        $hash_to_id[$_.infohash_v1] = $_.topic_id
        $id_to_info[$_.topic_id] = 1
    }
}

# Write-Log 'Выгружаем даты запусков по хранимым раздачам'
$api_seeding = Get-APISeeding -id $ini_data.'torrent-tracker'.user_id -api_key $ini_data.'torrent-tracker'.api_key -call_from 'Controller'
if ( $null -eq $api_seeding ) { exit }
# $i = 0
Write-Log 'Осмысливаем полученное'
$clients_torrents | Where-Object { $null -ne $_.topic_id -and $_.topic_id -ne '349785' } | ForEach-Object {
    $states[$_.hash] = @{
        client           = $_.client_key
        state            = $_.state
        seeder_last_seen = $( $null -ne $api_seeding[$_.topic_id] -and $api_seeding[$_.topic_id] -gt 0 ? $api_seeding[$_.topic_id] : ( $ok_to_start ).AddDays( -1 ) )
    }
    # $states[$_.hash] = @{ client = $_.client_key; state = $_.state; seeder_last_seen = $tracker_torrents[$_.infohash_v1].seeder_last_seen }
    if ( $_.state -eq 'pausedUP' ) {
        $paused_sort.Add( [PSCustomObject]@{ hash = $_.infohash_v1; client = $_.client_key; seeder_last_seen = $states[$_.infohash_v1].seeder_last_seen } ) | Out-Null
    }
}

$batch_size = 400

$started = 0
$stopped = 0
foreach ( $client in $clients.keys ) {
    Write-Log ( 'Регулируем клиент ' + $clients[$client].Name + ( $stop_forced -eq $true ? ' с остановкой принудительно запущенных' : '' ) )

    $start_keys = @()
    $stop_keys = @()
    $states.Keys | Where-Object { $states[$_].client -eq $client } | ForEach-Object {
        try { 
            if ( $states[$_].state -eq 'pausedUP' -and $tracker_torrents[$_].seeders -lt $section_seeds[$tracker_torrents[$_].section] ) {
                if ( $start_keys.count -eq $batch_size ) {
                    # Start-batch
                    Start-Torrents $start_keys $clients[$client]
                    $started += $start_keys.count
                    $start_keys = @()
                }
                $start_keys += $_
                $states[$_].state = 'uploading' # чтобы потом правильно запустить старые
            }
            elseif ( ( $states[$_].state -in @('uploading', 'stalledUP', 'queuedUP') -or ( $states[$_].state -eq 'forcedUP' -and $stop_forced )) `
                    -and $tracker_torrents[$_].seeders -gt ( $section_seeds[$tracker_torrents[$_].section] ) `
                    -and $states[$_].seeder_last_seen -gt $ok_to_stop
            ) {

                if ( $stop_keys.count -eq $batch_size ) {
                    # Stop-batch
                    Stop-Torrents $stop_keys $clients[$client]
                    $stopped += $stop_keys.count
                    $stop_keys = @()
                }
                $stop_keys += $_
            }
        }
        catch { } # на случай поглощённых раздач.
    }
    if ( $start_keys.count -gt 0) {
        # Start-batch
        Start-Torrents $start_keys $clients[$client]
        $started += $start_keys.count
    }
    if ( $stop_keys.count -gt 0) {
        # Stop-batch
        Stop-Torrents $stop_keys $clients[$client]
        $stopped += $stop_keys.count
    }
}

$lv_str1 = Get-Spell $min_stop_to_start 1 'days'
$lv_str2 = Get-Spell $old_starts_per_run 1 'torrents'
Write-Log "Ищем раздачи, остановленные более чем $lv_str1 в количестве не более $lv_str2"

$paused_sort = @( ( $paused_sort | Where-Object { $states[$_.hash].state -eq 'pausedUP' -and $_.seeder_last_seen -le $ok_to_start } | Sort-Object -Property client | Sort-Object -Property seeder_last_seen -Stable ) | `
        Select-Object -First $old_starts_per_run | Sort-Object -Property client )
$lv_str = Get-Spell $paused_sort.count 1 'torrents'

Write-Log "Найдено $lv_str"

if ( $paused_sort -and $paused_sort.Count -gt 0 ) {
    Write-Log 'Запускаем давно стоящие раздачи'
    $counter = 0
    $start_keys = @()
    $client = 'Z'
    # $paused_sort.GetEnumerator() | ForEach-Object {
    foreach ( $state in $paused_sort.GetEnumerator() ) {
        if ( $client -eq 'Z' ) {
            $client = $state.client
        }
        # if ($counter -gt 625 ) { break }
        if ( $start_keys.count -eq $batch_size -or $state.client -ne $client ) {
            # Start-batch
            Start-Torrents $start_keys $clients[$client]
            $client = $state.client
            $started += $start_keys.count
            $start_keys = @()
        }
        $start_keys += $state.hash
        $counter++
    }
    if ( $start_keys.count -gt 0 ) {
        # Start-batch
        Start-Torrents $start_keys $clients[$client]
        $started += $start_keys.count
    }
}
$lv_str1 = "Запущено: $( Get-Spell -qty $started -spelling 1 -entity 'torrents' ). "
$lv_str2 = "Остановлено: $( Get-Spell -qty $stopped -spelling 1 -entity 'torrents' )."
$lv_str = "$lv_str1`n$lv_str2"
Write-Log ( $lv_str1 + $lv_str2 )
if ( $report_controller -eq 'Y') { Send-TGMessage -message $lv_str -token $tg_token -chat_id $tg_chat -mess_sender 'Controller' }
