function  Start-batch {
    $spell = Get-Spell $start_keys.count 2
    Write-Log ( "Запускаем $spell в клиенте " + $clients[$client].name )
    Start-Torrents $start_keys $clients[$client]
    Set-StartStop $start_keys
}
function  Stop-batch {
    $spell = Get-Spell $stop_keys.count 2
    Write-Log ( "Тормозим $spell в клиенте " + $clients[$client].name )
    Stop-Torrents $stop_keys $clients[$client]
    Set-StartStop $stop_keys
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
$ok_to_stop = ( Get-Date -UFormat %s ).ToInt32($null) - ( $hours_to_stop * 60 * 60 )
$old_starts_per_run = Test-Setting 'old_starts_per_run'
$min_stop_to_start  = Test-Setting 'min_stop_to_start'
$ok_to_start = ( Get-Date -UFormat %s ).ToInt32($null) - ( $min_stop_to_start * 24 * 60 * 60 )
$auto_update = Test-Setting 'auto_update'

$global_seeds = $ini_data['topics_control'].peers
$section_seeds = @{}
# if ( $nul -ne $single_seed_time ) {
#     if ( ( $single_seed_time.start -lt $single_seed_time.end -and ( Get-Date -Format 'HH' ) -in ( $single_seed_time.start..$single_seed_time.end ) ) `
#             -or ( $single_seed_time.start -gt $single_seed_time.end -and ( Get-Date -Format 'HH' ) -in ( $single_seed_time.end..$single_seed_time.start ) )
#     ) {
#         if ( ( Get-Date -Format 'dddd' ) -notin @( 'суббота', 'воскресенье') ) {
#             Write-Log 'Аншлаг на раздачах, регулируем всё в 2'
#         }
#         else { Write-Log 'Выходной, регулируем всё по настройкам.' }    
#     }
#     else {
#         Write-Log 'Не аншлаг на раздачах, регулируем всё по настройкам.'
#     }
# }

$db_data = @{}
$database_path = $PSScriptRoot + $separator + 'starts.db'
Write-Log 'Подключаемся к БД запусков'
$conn = Open-Database $database_path
# Invoke-SqliteQuery -Query ( "PRAGMA journal_mode = MEMORY" ) -SQLiteConnection $conn | Out-Null
Invoke-SqliteQuery -Query 'CREATE TABLE IF NOT EXISTS start_dates (id VARCHAR PRIMARY KEY NOT NULL, start_date INT)' -SQLiteConnection $conn
Write-Log 'Выгружаем из БД даты запусков'
Invoke-SqliteQuery -Query 'SELECT * FROM start_dates' -SQLiteConnection $conn | ForEach-Object { $db_data[$_.id] = $_.start_date } 

Write-Log 'Строим таблицы'
$sections = $ini_data.sections.subsections.split( ',' )
$section_details = Get-IniSectionDetails $sections
$sections | ForEach-Object {
    $section_seeds[$_] = ( $section_details[$_].control_peers -ne '' ? $section_details[$_].control_peers : $global_seeds )
    #     if (
    #         $nul -ne $single_seed_time `
    #             -and ( $single_seed_time.start -lt $single_seed_time.end -and ( Get-Date -Format 'HH' ) -in ( $single_seed_time.start..$single_seed_time.end ) `
    #                 -or ( $single_seed_time.start -gt $single_seed_time.end -and ( Get-Date -Format 'HH' ) -in ( $single_seed_time.end..$single_seed_time.start ) ) ) `
    #             -and $section_seeds[$_.ToInt32($nul)] -lt 4 `
    #             -and ( ( Get-Date -Format 'dddd' ) -notin @( 'суббота', 'воскресенье') )
    #     ) {
    #         $section_seeds[$_.ToInt32($nul)] = 2 
    #     }
}
    
$states = @{}
$paused_sort = [System.Collections.ArrayList]::new()

if ( !$tracker_torrents) {
    Write-Log 'Автономный запуск, надо сходить на трекер за актуальными сидами и ID'
    $forum = Set-ForumDetails # чтобы подтянуть настройки прокси для следующего шага
    $tracker_torrents = Get-TrackerTorrents $sections -1 # без ограничения на количество сидов
}
if ( !$clients_torrents -or $clients_torrents.count -eq 0 ) {
    $clients = Get-Clients
    $clients_torrents = Get-ClientsTorrents $clients
    $hash_to_id = @{}
    $id_to_info = @{}
    
    Write-Log 'Сортируем таблицы'
    $clients_torrents | Where-Object { $null -ne $_.topic_id } | ForEach-Object {
        if ( !$_.infohash_v1 -or $nul -eq $_.infohash_v1 -or $_.infohash_v1 -eq '' ) { $_.infohash_v1 = $_.hash }
        $hash_to_id[$_.infohash_v1] = $_.topic_id
        $id_to_info[$_.topic_id] = 1
    }
}

# $i = 0
$clients_torrents | Where-Object { $null -ne $_.topic_id -and $_.topic_id -ne '349785' -and $_.topic_id -ne '6336688' } | ForEach-Object {
    $states[$_.hash] = @{ client = $_.client_key; state = $_.state; start_date = $( $null -ne $db_data[$_.topic_id] -and $db_data[$_.topic_id] -gt 0 ? $db_data[$_.topic_id] : $_.completion_on ) }
    if ( $_.state -eq 'pausedUP' ) {
        $paused_sort.Add( [PSCustomObject]@{ hash = $_.hash; client = $_.client_key; start_date = $( $null -ne $db_data[$_.topic_id] -and $db_data[$_.topic_id] -gt 0 ? $db_data[$_.topic_id] : 0 ) } ) | Out-Null
    }
}

$batch_size = 400

foreach ( $client in $clients.keys ) {
    Write-Log ( 'Регулируем клиент ' + $clients[$client].Name )
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
            elseif ( $states[$_].state -in @('uploading', 'stalledUP') -and $tracker_torrents[$_].seeders -gt ( $section_seeds[$tracker_torrents[$_].section] ) -and $states[$_].start_date -le $ok_to_stop ) {
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

$paused_sort = ( $paused_sort | Where-Object { $states[$_.hash].state -eq 'pausedUP' -and $_.start_date -le $ok_to_start } | Sort-Object -Property client  | Sort-Object -Property start_date -Stable ) | `
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
if ( $id_to_info ) {
    Write-Log 'Очищаем БД запусков от неактуальных раздач'
    $db_data.keys | Where-Object { !$id_to_info[$_] } | ForEach-Object {
        Invoke-SqliteQuery -Query "DELETE FROM start_dates WHERE id = @id" -SqlParameters @{ id = $_ } -SQLiteConnection $conn | ForEach-Object { $db_data[$_.id] = $_.start_date }
    }
}
$conn.Close()
Remove-Variable -Name conn