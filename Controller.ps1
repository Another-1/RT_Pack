function  Start-batch {
    $spell = Get-Spell $start_keys.count 2
    Write-Log ( "Запускаем $spell в клиенте " + $clients[$client].name )
    Start-Torrents $start_keys $clients[$client]
    # Set-StartStop $start_keys
}
function  Stop-batch {
    $spell = Get-Spell $stop_keys.count 2
    Write-Log ( "Тормозим $spell в клиенте " + $clients[$client].name )
    Stop-Torrents $stop_keys $clients[$client]
    # Set-StartStop $stop_keys
}

if ( !$ini_data ) {
    Write-Output 'Подгружаем настройки'
    $separator = $( $PSVersionTable.OS.ToLower().contains('windows') ? '\' : '/' )
    . ( $PSScriptRoot + $separator + '_settings.ps1' )

    $str = 'Подгружаем функции'
    if ( $use_timestamp -ne 'Y' ) { Write-Host $str } else { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) }
    . "$PSScriptRoot\_functions.ps1"

    Write-Log 'Проверяем актуальность скриптов' 
    Test-Version '_functions.ps1' 'Controller'
    Test-Version ( $PSCommandPath | Split-Path -Leaf ) 'Controller'

    if ( !$ini_data ) {
        Test-Module 'PsIni' 'для чтения настроек TLO'
        Test-Module 'PSSQLite' 'для работы с базой TLO'
        $tlo_path = Test-Setting 'tlo_path' -required
        $ini_path = $tlo_path + $separator + 'data' + $separator + 'config.ini'
        Write-Log 'Читаем настройки Web-TLO'
        $ini_data = Get-IniContent $ini_path
    }
}
$hours_to_stop = Test-Setting 'hours_to_stop'
$ok_to_stop = ( Get-Date ).AddHours( 0 - $hours_to_stop )
$old_starts_per_run = Test-Setting 'old_starts_per_run'
$min_stop_to_start = Test-Setting 'min_stop_to_start'
$ok_to_start = ( Get-Date ).AddDays( 0 - $min_stop_to_start )
$auto_update = Test-Setting 'auto_update'

$global_seeds = $ini_data['topics_control'].peers
$section_seeds = @{}

Write-Log 'Строим таблицы'
$sections = $ini_data.sections.subsections.split( ',' )
$section_details = Get-IniSectionDetails $sections
$sections | ForEach-Object { $section_seeds[$_] = ( $section_details[$_].control_peers -ne '' ? $section_details[$_].control_peers : $global_seeds ) }
    
$states = @{}
$paused_sort = [System.Collections.ArrayList]::new()

if ( !$tracker_torrents) {
    Write-Log 'Автономный запуск, надо сходить на трекер за актуальными сидами и ID'
    $forum = Set-ForumDetails # чтобы подтянуть настройки прокси для следующего шага
    $tracker_torrents = Get-TrackerTorrents $sections -1 # без ограничения на количество сидов. Нужно чтобы получить оттуда сидов.
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

Write-Log 'Выгружаем даты запусков по хранимым раздачам'
$api_seeding = Get-APISeeding -id $ini_data.'torrent-tracker'.user_id -api_key $ini_data.'torrent-tracker'.api_key
# $i = 0
$clients_torrents | Where-Object { $null -ne $_.topic_id -and $_.topic_id -ne '349785' } | ForEach-Object {
    # $states[$_.hash] = @{ client = $_.client_key; state = $_.state; last_seen_date = $( $null -ne $api_seeding[$_.topic_id] -and $api_seeding[$_.topic_id] -gt 0 ? $api_seeding[$_.topic_id] : (([System.DateTimeOffset]::FromUnixTimeSeconds($_.completion_on)).DateTime) ) }
    $states[$_.hash] = @{ client = $_.client_key; state = $_.state; last_seen_date = $( $null -ne $api_seeding[$_.topic_id] -and $api_seeding[$_.topic_id] -gt 0 ? $api_seeding[$_.topic_id] : ( $ok_to_start ).AddDays( -1 ) ); completion_on = $_.completion_on }
    if ( $_.state -eq 'pausedUP' ) {
        $paused_sort.Add( [PSCustomObject]@{ hash = $_.hash; client = $_.client_key; last_seen_date = $states[$_.hash].last_seen_date } ) | Out-Null
    }
}

$batch_size = 400

foreach ( $client in $clients.keys ) {
    Write-Log ( 'Регулируем клиент ' + $clients[$client].Name + ( $stop_forced -eq $true ? ' с остановкой принудительно запущенных' : '' ) )

    $start_keys = @()
    $stop_keys = @()
    $states.Keys | Where-Object { $states[$_].client -eq $client } | ForEach-Object {
        try { 
            if ( $states[$_].state -eq 'pausedUP' -and $tracker_torrents[$_].seeders -lt $section_seeds[$tracker_torrents[$_].section] ) {
                if ( $start_keys.count -eq $batch_size ) {
                    Start-batch
                    $start_keys = @()
                }
                $start_keys += $_
                $states[$_].state = 'uploading' # чтобы потом правильно запустить старые
            }
            elseif ( ( $states[$_].state -in @('uploading', 'stalledUP') -or ( $states[$_].state -eq 'forcedUP' -and $stop_forced )) `
                    -and $tracker_torrents[$_].seeders -gt ( $section_seeds[$tracker_torrents[$_].section] ) `
                    -and $states[$_].completion_on -le $ok_to_stop `
                    -and $states[$_].last_seen_date -gt $ok_to_start )
                    {

                if ( $stop_keys.count -eq $batch_size ) {
                    Stop-batch
                    $stop_keys = @()
                }
                $stop_keys += $_
            }
        }
        catch { } # на случай поглощённых раздач.
    }
    if ( $start_keys.count -gt 0) {
        Start-batch
    }
    if ( $stop_keys.count -gt 0) {
        Stop-batch
    }
}

$lv_str1 = Get-Spell $min_stop_to_start 1 'days'
$lv_str2 = Get-Spell $old_starts_per_run 1 'torrents'
Write-Log "Ищем раздачи, остановленные более $lv_str1 в количестве не более $lv_str2"

$paused_sort = ( $paused_sort | Where-Object { $states[$_.hash].state -eq 'pausedUP' -and $_.last_seen_date -le $ok_to_start } | Sort-Object -Property client | Sort-Object -Property last_seen_date -Stable ) | `
    Select-Object -First $old_starts_per_run | Sort-Object -Property client
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
            Start-batch
            $client = $state.client
            $start_keys = @()
        }
        $start_keys += $state.hash
        $counter++
    }
    if ( $start_keys.count -gt 0 ) {
        Start-batch
    }
}
