param ([switch]$delay )

if ( $delay ) {
    Write-Host 'Запуск после обновления, ждём 5 секунд чтобы старое окно точно закрылось.'
    Start-Sleep -Seconds 5
}

if ( ( ( Get-Process | Where-Object { $_.ProcessName -eq 'pwsh' } ).CommandLine -like ('*' + ( $PSCommandPath | Split-Path -Leaf ) ) ).count -gt 1 ) {
    Write-Host 'Я и так уже выполняюсь, выходим' -ForegroundColor Red
    exit
}

$ProgressPreference = 'SilentlyContinue'

$separator = $( $PSVersionTable.OS.ToLower().contains('windows') ? '\' : '/' )

$settings_file = Join-Path $PSScriptRoot 'settings.json'
if ( Test-Path $settings_file ) {
    # $debug = 1
    Write-Output "Подгружаем настройки из $settings_file"
    $settings = Get-Content -Path $settings_file | ConvertFrom-Json -AsHashtable
    $standalone = $true
}
else {
    $settings_file = Join-Path $PSScriptRoot '_settings.ps1'
    try {
        Write-Output "Подгружаем настройки из $settings_file"
        . ( Join-Path $PSScriptRoot _settings.ps1 )
    }
    catch {
        Write-Host ( "Не найден файл настроек $settings_file, видимо это первый запуск." )
    }
    $settings = [ordered]@{}
    $settings.interface = @{}
    $settings.interface.use_timestamp = ( $use_timestamp -eq 'Y' ? 'Y' : 'N' )
    $standalone = $false
}

$str = 'Подгружаем функции'
if ( $settings.interface.use_timestamp -ne 'Y' ) { Write-Host $str } else { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) }
. ( Join-Path $PSScriptRoot _functions.ps1 )

Test-ForumWorkingHours -verbose

if ( !$debug ) {
    Test-PSVersion
    Test-Module 'PsIni' 'для чтения настроек TLO'
    Test-Module 'PSSQLite' 'для работы с базой TLO'
    Write-Log 'Проверяем актуальность скриптов' 
    if ( ( Test-Version -name '_functions.ps1' -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') ) -eq $true ) {
        Write-Log 'Запускаем новую версию  _functions.ps1'
        . ( Join-Path $PSScriptRoot '_functions.ps1' )
    }
    Test-Version -name ( $PSCommandPath | Split-Path -Leaf ) -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')
}

try { . ( Join-Path $PSScriptRoot '_client_ssd.ps1' ) } catch { }
Write-Log 'Проверяем наличие всех нужных настроек'
if ( !$settings.telegram ) { $settings.telegram = [ordered]@{} }
$json_section = ( $standalone -eq $true ? 'telegram' : '' )
$settings.telegram.tg_token = Test-Setting 'tg_token' -json_section $json_section
if ( $settings.telegram.tg_token -ne '' ) {
    $settings.telegram.tg_chat = Test-Setting 'tg_chat' -required -json_section $json_section
    $settings.telegram.alert_oldies = Test-Setting 'alert_oldies' -required -json_section $json_section
    $settings.telegram.report_nowork = Test-Setting 'report_nowork' -required -json_section $json_section
    $settings.telegram.report_obsolete = Test-Setting 'report_obsolete' -required -json_section $json_section
}

if ( !$settings.interface ) { $settings.interface = [ordered]@{} }
if ( $standalone -eq $true ) { $settings.interface.use_timestamp = Test-Setting 'use_timestamp' -json_path 'interface' -required } else { $settings.interface.use_timestamp = Test-Setting 'use_timestamp' -required }
if ( $standalone -eq $false ) {
    $tlo_path = Test-Setting 'tlo_path' -required
    $ini_path = Join-Path $tlo_path 'data' 'config.ini'
    Write-Log 'Читаем настройки Web-TLO'
    $ini_data = Get-IniContent $ini_path
}
if ( !$settings.adder ) { $settings.adder = [ordered]@{} }
$json_section = ( $standalone -eq $true ? 'adder' : '' )
$settings.adder.get_news = Test-Setting 'get_news' -json_section $json_section
$settings.adder.min_days = Test-Setting 'min_days' -default $ini_data.sections.rule_date_release -required -json_section$json_section
if (!$settings.adder.min_days ) { $settings.adder.min_days = 0 }
$settings.adder.get_blacklist = Test-Setting 'get_blacklist' -json_section $json_section
$settings.adder.max_seeds = Test-Setting -setting 'max_seeds' -default $ini_data.sections.rule_topics -json_section $json_section
$settings.adder.get_hidden = Test-Setting 'get_hidden' -json_section $json_section
$settings.adder.get_shown = Test-Setting 'get_shown' -json_section $json_section
$settings.adder.get_lows = Test-Setting 'get_lows' -json_section $json_section
$settings.adder.get_mids = Test-Setting 'get_mids' -json_section $json_section
$settings.adder.get_highs = Test-Setting 'get_highs' -json_section $json_section
$settings.adder.control = Test-Setting 'control' -json_section $json_section
$settings.adder.report_stalled = Test-Setting 'report_stalled' -json_section $json_section
if ( $settings.adder.report_stalled -eq 'Y' ) { $settings.adder.stalled_pwd = Test-Setting 'stalled_pwd' -json_section $json_section -required }
$settings.adder.update_stats = Test-Setting 'update_stats' -json_section $json_section
if ( $update_stats -eq 'Y' ) { $settings.adder.update_obsolete = Test-Setting 'update_obsolete' -json_section $json_section }

$json_section = ( $standalone -eq $true ? 'others' : '' )
if ( !$settings.others ) { $settings.others = [ordered]@{} }
$settings.others.auto_update = Test-Setting 'auto_update' -required -json_section $json_section

if ( $update_stats -eq 'Y' -and $standalone -ne $true ) {
    if ( !$send_reports ) { Write-Log 'Для обновления БД TLO и отправки отчётов нужен интерпретатор php на этом же компе.' }
    $send_reports = Test-Setting 'send_reports'
    while ( $true ) {
        $php_path = Test-Setting 'php_path' -required
        If ( Test-Path $php_path ) { break }
        Write-Log 'Не нахожу такого файла, проверьте ввод' -ForegroundColor -Red
        Remove-Variable -Name $php_path
    }
}

if ( $update_trigger -and $psversionTable.Platform.ToLower() -like '*win*') {
    $database_path = Join-Path $PSScriptRoot 'updates.db'
    Write-Log 'Подключаемся к БД обновлений раздач'
    $up_conn = Open-Database $database_path
    Invoke-SqliteQuery -Query 'CREATE TABLE IF NOT EXISTS updates (id INT PRIMARY KEY NOT NULL, cnt INT)' -SQLiteConnection $up_conn
}

if ( !$settings.connection -and $standlone -ne $true ) {
    if ( !$settings.connection ) { $settings.connection = [ordered]@{} }
    Set-ConnectDetails $settings
    Set-Proxy( $settings )
}

if ( $ini_data ) { $section_numbers = $ini_data.sections.subsections.split( ',' ) } else { $section_numbers = $settings.sections.keys }
$all_sections = $section_numbers
$ini_sections = $section_numbers
if ( !$settings.adder.never_obsolete -and $never_obsolete ) { $settings.adder.never_obsolete = $never_obsolete }
if ( $settings.adder.never_obsolete ) {
    $never_obsolete_array = $never_obsolete.Replace(' ', '').split(',')
    $all_sections += $never_obsolete_array
    $all_sections = $all_sections | Select-Object -Unique
    Write-Log 'Запрашиваем список всех разделов чтобы исключить празничные, если на дворе не праздник'
    $existing_sections = (( Get-ApiHTTP -url '/v1/static/cat_forum_tree' ) | ConvertFrom-Json -AsHashtable ).result.f.keys
    Write-Log "Обнаружено разделов на форуме: $($existing_sections.count)"
    Write-Log "Исключаем праздничные разделы по праздникам, которые не на дворе"
    $all_sections = $all_sections | Where-Object { $_ -in $existing_sections }
}
Write-Log "Разделов в работе: $( $section_numbers.count )"
if ( $forced_sections ) { $settings.adder.forced_sections = $forced_sections }
if ( $settings.adder.forced_sections ) {
    if ( $inverse_forced -eq 'Y' ) {
        Write-Log 'Обнаружена инвертированная настройка forced_sections, отбрасываем лишние разделы'
    }
    else {
        Write-Log 'Обнаружена настройка forced_sections, отбрасываем лишние разделы'
    }
    $forced_sections = $settings.adder.forced_sections.Replace(' ', '')
    $forced_sections_array = @()
    $forced_sections.split(',') | ForEach-Object { $forced_sections_array += $_ }
    if ( $inverse_forced -eq 'Y' ) {
        $section_numbers = $section_numbers | Where-Object { $_ -notin $forced_sections_array }
    }
    else {
        $section_numbers = $section_numbers | Where-Object { $_ -in $forced_sections_array }
    }
    Write-Log "Осталось разделов: $( $section_numbers.count )"
}
if ( $section_numbers.count -eq 0 ) {
    Write-Log 'Значит и делать ничего не надо, выходим.'
    exit
}

If ( Test-Path "$PSScriptRoot\_masks.ps1" ) {
    Write-Log 'Подтягиваем из БД TLO названия раздач из маскированных разделов по хранимым раздачам'
    . "$PSScriptRoot\_masks.ps1"
    $masks_db = @{}
    $masks_sect = @{}
    $conn = Open-TLODatabase
    $columnNames = Get-DB_ColumnNames $conn
    $masks.GetEnumerator() | ForEach-Object {
        $group_mask = $_.Value
        foreach ( $section in ( $_.Key -replace ( '\s*', '')).split(',') ) {
            $sql_sentence = 'SELECT id FROM Topics WHERE ' + $columnNames['forum_id'] + '=' + $section + ' AND ' + `
            ( ( $group_mask | ForEach-Object {
                        '( ' + $columnNames['name'] + ' NOT LIKE ' + ( ( $_ -split ' ' | ForEach-Object { "'%$_%'" } ) -join ( ' OR ' + $columnNames['name'] + ' NOT LIKE ' ) ) + ' ) '
                    } ) -join ' AND ' )
            $db_return = ( Invoke-SqliteQuery -Query $sql_sentence -SQLiteConnection $conn )
            if ( $db_return ) {
                @($db_return.id).GetEnumerator() | ForEach-Object {
                    if ( !$masks_db[$section]) { $masks_db[$section] = @{} }
                    $masks_db[$section][$_.ToInt64($null)] = 1
                } # Список всех неподходящих раздач по этому разделу
                Write-Log ( 'По разделу ' + $section + ' отброшено масками ' + ( Get-Spell -qty $masks_db[$section].count -spelling 1 -entity 'torrents' ) )
            }
            $masks_sect[$section] = $group_mask
        }
    }
    $conn.Close()
}
else {
    Remove-Variable -Name masks_db -ErrorAction SilentlyContinue
}

if ( $standalone -ne $true ) {
    Get-Clients
    Write-Log 'Достаём из TLO подробности о разделах'
    Get-IniSectionDetails $settings $ini_sections
}

if ( $settings.adder.get_blacklist -eq 'N' -and $standalone -ne $true ) {
    $blacklist = Get-Blacklist -verbose
    if ( !$blacklist -or $blacklist.Count -eq 0 ) {
        $oldblacklist = Get-OldBlacklist
    }
    $spell = Get-Spell ( $blacklist.Count + $oldblacklist.Count ) 1 'torrents'
    Write-Log "В чёрных списках $spell"
}

Get-ClientApiVersions $settings.clients -mess_sender 'Adder'

if ( $debug -ne 1 -or $env:TERM_PROGRAM -ne 'vscode' -or $null -eq $tracker_torrents -or $tracker_torrents.count -eq 0 ) {
    if ( !$settings.adder.avg_seeds -and $standalone -ne $true ) {
        $settings.adder.avg_seeds = ( $ini_data.sections.avg_seeders -eq '1' ) 
        # $tracker_torrents = Get-RepTorrents -sections $all_sections -id $settings.connection.user_id -api_key $settings.connection.api_key -call_from ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') -avg_seeds:$settings.adder.avg_seeds
        $conn = Open-TLODatabase
        $tracker_torrents = Get-RepTorrents -sections $( $forced_sections -and ( $control -ne 'Y') ? $section_numbers : $all_sections ) -id $settings.connection.user_id -api_key $settings.connection.api_key `
            -call_from ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') -avg_seeds:$settings.adder.avg_seeds -conn $conn
        $conn.Close()
    }
}

if ( $debug -ne 1 -or $env:TERM_PROGRAM -ne 'vscode' -or $null -eq $clients_torrents -or $clients_torrents.count -eq 0 ) {
    if ( $forced_sections -and $control -ne 'Y' ) {
        $db_hash_to_id = @{}
        $db_conn = Open-TLODatabase
        $query = 'SELECT info_hash, topic_id FROM Torrents'
        Invoke-SqliteQuery -Query $query -SQLiteConnection $conn -ErrorAction SilentlyContinue | ForEach-Object { $db_hash_to_id[$_.info_hash] = $_.topic_id }
    }
    $clients_torrents = Get-ClientsTorrents -clients $settings.clients -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')
}

$hash_to_id = @{}
$id_to_info = @{}

Write-Log 'Сортируем таблицы'
$clients_torrents | Where-Object { $null -ne $_.topic_id } | ForEach-Object {
    if ( !$_.infohash_v1 -or $nul -eq $_.infohash_v1 -or $_.infohash_v1 -eq '' ) { $_.infohash_v1 = $_.hash }
    $hash_to_id[$_.infohash_v1] = $_.topic_id

    $id_to_info[$_.topic_id] = @{
        client_key = $_.client_key # string
        save_path  = $_.save_path
        category   = $_.category
        name       = $_.name
        hash       = $_.hash
        size       = $_.size
    }
}

Write-Log 'Ищем новые раздачи'

$new_torrents_keys = $tracker_torrents.keys | Where-Object { $null -eq $hash_to_id[$_] }
$spell = Get-Spell $new_torrents_keys.count 1 'torrents'
Write-Log ( "Новых: $spell" )

$new_torrents_keys_2 = @()
if ( $max_seeds -ne -1 ) {
    Write-Log "Отсеиваем (только от добавления) раздачи с количеством сидов больше $max_seeds"
    $new_torrents_keys_2 = $new_torrents_keys | Where-Object { $tracker_torrents[$_].avg_seeders -le $max_seeds }
    Write-Log ( 'Отсеялось раздач: ' + ( $new_torrents_keys.count - $new_torrents_keys_2.count ) )

    # $spell = Get-Spell $new_torrents_keys_2.count 1 'torrents'
    # Write-Log ( "Осталось : $spell" )
}
else { $new_torrents_keys_2 = $new_torrents_keys }

if ( $get_hidden -and $get_hidden -eq 'N' ) {
    Write-Log 'Отсеиваем раздачи из скрытых и праздничных разделов'
    $sections_to_skip = $section_numbers | Where-Object { $settings.sections[$_].hide_topics -ne 'N' }
    if ($sections_to_skip ) { Write-Log "Будут отсеяны разделы: $( $sections_to_skip -join( ', ' ) )" }
    $new_torrents_keys = $new_torrents_keys | Where-Object { $settings.sections[$tracker_torrents[$_].section].hide_topics -eq 'N' }
    Write-Log ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

if ( $get_shown -and $get_shown -eq 'N' ) { 
    Write-Log 'Отсеиваем раздачи из видимых разделов'
    $new_torrents_keys = $new_torrents_keys | Where-Object { $settings.sections[$tracker_torrents[$_].section].hide_topics -eq '1' }
    Write-Log ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

if ( $get_lows -and $get_lows.ToUpper() -eq 'N' ) {
    Write-Log 'Отсеиваем раздачи с низким приоритетом'
    $new_torrents_keys = $new_torrents_keys | Where-Object { $tracker_torrents[$_].keeping_priority -ne '0' }
    Write-Log ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

if ( $get_mids -and $get_mids.ToUpper() -eq 'N' ) {
    Write-Log 'Отсеиваем раздачи со средним приоритетом'
    $new_torrents_keys = $new_torrents_keys | Where-Object { $tracker_torrents[$_].keeping_priority -ne '1' }
    Write-Log ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

if ( $get_highs -and $get_highs.ToUpper() -eq 'N' ) {
    Write-Log 'Отсеиваем раздачи с высоким приоритетом'
    $new_torrents_keys = $new_torrents_keys | Where-Object { $tracker_torrents[$_].keeping_priority -ne '2' }
    Write-Log ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

if ( $nul -ne $get_blacklist -and $get_blacklist.ToUpper() -eq 'N' ) {
    Write-Log 'Отсеиваем раздачи из чёрного списка'
    if ( $blacklist.Count -ne 0 ) { $new_torrents_keys = $new_torrents_keys | Where-Object { $null -eq $blacklist[$_] } }
    if ( $oldblacklist -and $oldblacklist.Count -ne 0 ) { $new_torrents_keys = $new_torrents_keys | Where-Object { $null -eq $oldblacklist[$tracker_torrents[$_].topic_id] } }
    Write-Log ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

if ( $masks_db ) {
    Write-Log 'Отфильтровываем уже известные раздачи по маскам'
    # $new_torrents_keys = $new_torrents_keys | Where-Object { !$masks_db_plain[$tracker_torrents[$_].topic_id] }
    # $new_torrents_keys_tmp = @()
    # foreach ( $key in $new_torrents_keys ) {
    $new_torrents_keys = $new_torrents_keys | Where-Object { $null -eq $masks_db[$tracker_torrents[$_].section] -or $null -eq $masks_db[$tracker_torrents[$_].section][$tracker_torrents[$_].topic_id] }
    # }
    # }
    Write-Log ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

if ( $max_keepers -and $max_keepers -gt -1 -and !$kept ) {
    Write-Log 'Указано ограничение на количество хранителей, необходимо подтянуть данные из отчётов по хранимым разделам'
    $kept = GetRepKeptTorrents -sections $section_numbers -call_from ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') -max_keepers $max_keepers
}

if ( $kept ) {
    Write-Log 'Отфильтровываем раздачи, у которых слишком много хранителей'
    $new_torrents_keys = $new_torrents_keys | Where-Object { $tracker_torrents[$_].topic_id -notin $kept }
    $spell = Get-Spell $new_torrents_keys.count 1 'torrents'
    Write-Log ( "Осталось : $spell" )
}

$added = @{}
$refreshed = @{}

if ( $new_torrents_keys ) {
    Write-Log 'Сортируем новые раздачи по клиентам'
    $new_torrents_keys = $new_torrents_keys | Sort-Object -Property { $tracker_torrents[$_].tor_size_bytes } | Sort-Object -Property { $settings.sections[$tracker_torrents[$_].section].client } -Stable
    $spell = Get-Spell $new_torrents_keys.count 1 'torrents'
    Write-Log "Рассортировали все $spell"
    $ProgressPreference = 'SilentlyContinue' # чтобы не мелькать прогресс-барами от скачивания торрентов
    foreach ( $new_torrent_key in $new_torrents_keys | Where-Object { $settings.sections[$tracker_torrents[$_].section] -and ( !$never_obsolete -or $tracker_torrents[$_].section -notin $never_obsolete_array ) } ) {
        # Remove-Variable -Name new_topic_title -ErrorAction SilentlyContinue
        $new_tracker_data = $tracker_torrents[$new_torrent_key]
        $existing_torrent = $id_to_info[ $new_tracker_data.topic_id ]
        if ( $existing_torrent ) {
            $client = $settings.clients[$existing_torrent.client_key]
            Write-Log ( "Раздача " + $new_tracker_data.topic_id + ' обнаружена в клиенте ' + $existing_torrent.client_key )
        }
        else {
            if ( !$settings.sections[$new_tracker_data.section].client ) {
                Write-Log "Не указан клиент для подраздела $($new_tracker_data.section)" -Red
                continue
            }
            $client = $settings.clients[$settings.sections[$new_tracker_data.section].client]
        }
        
        if ( $new_tracker_data.topic_poster -in $priority_releasers.keys ) {
            $min_delay = $priority_releasers[$new_tracker_data.topic_poster.ToInt32($null)]
        }
        else {
            $min_delay = $min_days
        }
        if ( $existing_torrent ) {
            # if ( !$settings.connection.sid ) { Initialize-Forum }
            $new_torrent_file = Get-ForumTorrentFile $new_tracker_data.topic_id
            if ( $null -eq $new_torrent_file ) { Write-Log 'Проблемы с доступностью форума' -Red ; exit }
            $on_ssd = ( $nul -ne $ssd -and $existing_torrent.save_path[0] -in $ssd[$existing_torrent.client_key] )
            # Write-Log "Получаем с трекера название раздачи $($new_tracker_data.topic_id) из раздела $($new_tracker_data.section)"
            if ( $new_tracker_data.topic_title -eq '' -or $null -eq $new_tracker_data.topic_title ) {
                $new_tracker_data.topic_title = ( Get-ForumTorrentInfo $new_tracker_data.topic_id -call_from ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') ).topic_title
            }
            $text = "Обновляем раздачу " + $new_tracker_data.topic_id + " " + $new_tracker_data.topic_title + ' в клиенте ' + $client.name + ' (' + ( to_kmg $existing_torrent.size 1 ) + ' -> ' + ( to_kmg $new_tracker_data.tor_size_bytes 1 ) + ')'
            Write-Log $text
            # подмена временного каталога если раздача хранится на SSD.
            if ( $ssd ) {
                if ( $on_ssd -eq $true ) {
                    Write-Log 'Отключаем преаллокацию'
                    Set-ClientSetting $client 'preallocate_all' $false
                    Start-Sleep -Milliseconds 100
                }
                else {
                    Set-ClientSetting $client 'preallocate_all' $true
                    Start-Sleep -Milliseconds 100
                }
                Set-ClientSetting $client 'temp_path_enabled' $false
            }
            $success = Add-ClientTorrent -client $client -file $new_torrent_file -path $existing_torrent.save_path -category $existing_torrent.category -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') -addToTop:$( $add_to_top -eq 'Y' )
            if ( $success -eq $true ) {
                Write-Log 'Ждём 5 секунд чтобы раздача точно "подхватилась"'
                Start-Sleep -Seconds 5
                $new_topic_info = ( Get-ClientTorrents -client $client -hash $new_torrent_key -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') )
                $new_topic_title = $new_topic_info.name
                if ( $null -ne $new_topic_title -and $new_topic_title -eq $existing_torrent.name -and $settings.sections[$new_tracker_data.section].data_subfolder -le '2') {
                    Remove-ClientTorrent -client $client -torrent $existing_torrent
                }
                elseif ($null -ne $new_topic_title ) {
                    Remove-ClientTorrent -client $client -torrent $existing_torrent -deleteFiles
                }
                Start-Sleep -Milliseconds 100 
                $torrent_to_tag = [PSCustomObject]@{
                    hash     = $new_torrent_key
                    topic_id = $new_tracker_data.topic_id
                }
                If ( $refreshed_label ) { Set-Comment -client $client -torrent $torrent_to_tag -label $refreshed_label }
                if ( !$refreshed[ $client.name ] ) { $refreshed[ $client.name ] = @{} }
                $refreshed_ids += $new_tracker_data.topic_id
                if ( !$refreshed[ $client.name ][ $new_tracker_data.section] ) { $refreshed[ $client.name ][ $new_tracker_data.section ] = [System.Collections.ArrayList]::new() }
                # }
                if ( $ssd ) {
                    $refreshed[ $client.name ][ $new_tracker_data.section ] += [PSCustomObject]@{
                        id       = $new_tracker_data.topic_id
                        comment  = ( $on_ssd ? ' SSD' : ' HDD' ) + ' ' + $existing_torrent.save_path[0]
                        name     = $new_tracker_data.topic_title
                        old_size = $existing_torrent.size
                        new_size = $new_tracker_data.tor_size_bytes
                    }
                }
                else {
                    $refreshed[ $client.name ][ $new_tracker_data.section ] += [PSCustomObject]@{
                        id       = $new_tracker_data.topic_id
                        comment  = ''
                        name     = $new_tracker_data.topic_title
                        old_size = $existing_torrent.size
                        new_size = $new_tracker_data.tor_size_bytes
                    }
                }
                if ( $update_trigger ) {
                    if ( !$disk_types ) { $disk_types = Get-DiskTypes }
                    if ( $disk_types -and $disk_types[ $existing_torrent.save_path[0] ] -eq 'HDD' ) {
                        Write-Log 'Фиксируем факт обновления в БД обновлений'
                        $current_cnt = ( Invoke-SqliteQuery -Query "SELECT cnt FROM updates WHERE id = $($new_tracker_data.topic_id)" -SQLiteConnection $up_conn ).cnt
                        if ( !$current_cnt ) {
                            Invoke-SqliteQuery -Query "INSERT INTO updates (id, cnt) VALUES ( $($new_tracker_data.topic_id), 1 )" -SQLiteConnection $up_conn | Out-Null
                        }
                        else {
                            $current_cnt = $current_cnt + 1
                            Invoke-SqliteQuery -Query "UPDATE updates SET cnt = $current_cnt WHERE id = $($new_tracker_data.topic_id) " -SQLiteConnection $up_conn | Out-Null
                        }
                        if ( $current_cnt -ge $update_trigger) {
                            Send-TGMessage -message "Рекомендуется перенести в клиенте <b>$($client.name)</b> на SSD раздачу $($new_tracker_data.topic_id) $($existing_torrent.name)" -token $settings.telegram.tg_token -chat_id $settings.telegram.tg_chat -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')
                        }
                    }
                }

            }
        }
        elseif ( !$existing_torrent -and $get_news -eq 'Y' -and ( $new_tracker_data.reg_time -lt ( ( Get-Date ).ToUniversalTime( ).AddDays( 0 - $min_delay ) ) -or $new_tracker_data.tor_status -eq 2 ) -and $new_torrent_key -in $new_torrents_keys_2 ) {
            # $mask_passed = $true
            # сначала проверяем по базе неподходящих раздач в БД TLO
            Remove-Variable mask_passed -ErrorAction SilentlyContinue
            if ( $masks_db -and $masks_db[$new_tracker_data.section.ToString()] -and $masks_db[$new_tracker_data.section.ToString()][$new_tracker_data.topic_id] ) { $mask_passed = $false }

            else {
                # if ( $masks_like -and $masks_like[$new_tracker_data.section.ToString()] ) {
                if ( $masks_sect -and $masks_sect[$new_tracker_data.section.ToString()] ) {
                    if ( $new_tracker_data.topic_title -eq '' -or $null -eq $new_tracker_data.topic_title ) {
                        Write-Log "Получаем с трекера название раздачи $($new_tracker_data.topic_id) из раздела $($new_tracker_data.section), так как API его не вернуло (бывает)"
                        $new_tracker_data.topic_title = ( Get-ForumTorrentInfo $new_tracker_data.topic_id -call_from ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') ).topic_title
                    }
                    # $masks_like[$new_tracker_data.section.ToString()] | ForEach-Object {
                    #     if ( -not $mask_passed -and $new_tracker_data.topic_title -like $_ ) {
                    #         $mask_passed = $true
                    #     }
                    # }
                    $mask_passed = $false
                    Foreach ( $mask_line in $masks_sect[$new_tracker_data.section] ) {
                        ForEach ( $mask_word in $mask_line.split(' ') ) {
                            $mask_passed = ($new_tracker_data.topic_title -match "\b$($mask_word.Replace('_','\s'))\b")
                            if ( !$mask_passed ) { break }
                        }
                        if ( $mask_passed ) {
                            Write-Log "Сработала маска $mask_line на раздачу $($new_tracker_data.topic_title)"
                            break 
                        }
                    }
                }
                else { $mask_passed = 'N/A' }
            }
            # if ( $masks_like -and -not $mask_passed ) {
            if ( $masks_sect -and -not $mask_passed ) {
                Write-Log ( 'Новая раздача ' + $new_tracker_data.topic_title + ' отброшена масками' )
                continue
            }
            if ( $new_tracker_data.section -in $skip_sections ) {
                continue
            }

            ### DEBUG ###
            # if ( $client.name -eq 'NAS-NEW' -and $new_tracker_data.section -eq '1574' ) { continue }

            $new_torrent_file = Get-ForumTorrentFile $new_tracker_data.topic_id
            if ( $new_tracker_data.topic_title -eq '' -or $null -eq $new_tracker_data.topic_title ) {
                $new_tracker_data.topic_title = ( Get-ForumTorrentInfo $new_tracker_data.topic_id -call_from ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') ).topic_title
            }
            $text = "Добавляем раздачу " + $new_tracker_data.topic_id + " " + $new_tracker_data.topic_title + ' в клиент ' + $client.name + ' (' + ( to_kmg $new_tracker_data.tor_size_bytes 1 ) + ')'
            Write-Log $text
            $save_path = $settings.sections[$new_tracker_data.section].data_folder
            if ( $settings.sections[$new_tracker_data.section].data_subfolder -eq '1' ) {
                $save_path = ( $save_path -replace ( '\\$', '') -replace ( '/$', '') ) + '/' + $new_tracker_data.topic_id # добавляем ID к имени папки для сохранения
            }       
            elseif ( $settings.sections[$new_tracker_data.section].data_subfolder -eq '2' ) {
                $save_path = ( $save_path -replace ( '\\$', '') -replace ( '/$', '') ) + '/' + $new_torrent_key  # добавляем hash к имени папки для сохранения
            }
            $on_ssd = ( $ssd -and $save_path[0] -in $ssd[$settings.sections[$new_tracker_data.section].client] )
            if ( $ssd -and $ssd[$settings.sections[$new_tracker_data.section].client] ) {
                if ( $on_ssd -eq $false ) {
                    Set-ClientSetting $client 'temp_path' ( Join-Path ( $ssd[$settings.sections[$new_tracker_data.section].client][0] + $( $separator -eq '\' ? ':' : '' ) ) 'Incomplete' )
                    Set-ClientSetting $client 'temp_path_enabled' $true
                    Set-ClientSetting $client 'preallocate_all' $false
                }
                else {
                    Set-ClientSetting $client 'temp_path_enabled' $false
                    Set-ClientSetting $client 'preallocate_all' $false
                }
            }
            $success = Add-ClientTorrent -client $client -file $new_torrent_file -path $save_path -category $settings.sections[$new_tracker_data.section].label -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') -addToTop:$( $add_to_top -eq 'Y' )
            if ( $success -eq $true ) {
                if ( $masks ) {
                    If ( $mask_passed -eq $true -and $mask_label ) {
                        Write-Log 'Раздача добавлена по маске и задана метка маски. Надо проставить метку. Ждём 2 секунды чтобы раздача "подхватилась"'
                        Start-Sleep -Seconds 2
                        $client_torrent = Get-ClientTorrents -client $client -hash $new_torrent_key -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')
                        Set-Comment -client $client -torrent $client_torrent -label $mask_label -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')
                    }
                    elseif ( !$mask_label ) { Write-Log 'Метка масок не задана, простановка метки маски не требуется' }
                    elseif ( $mask_passed -eq $false ) { Write-Log 'Маска не пройдена, но раздача добавлена. Такого не должно было произойти. Где-то косяк' }
                }
                elseif ( $news_label ) {
                    Write-Log 'Указана маска для новых раздач. Ждём 2 секунды чтобы раздача "подхватилась'
                    Start-Sleep -Seconds 2
                    $client_torrent = Get-ClientTorrents -client $client -hash $new_torrent_key -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')
                    Write-Log "Проставляем метку $news_label"
                    Set-Comment -client $client -torrent $client_torrent -label $news_label -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')

                }
                if ( $nul -ne $settings.telegram.tg_token -and '' -ne $settings.telegram.tg_token ) {
                    if ( !$added[ $client.name ] ) { $added[ $client.name ] = @{} }
                    if ( !$added[ $client.name ][ $new_tracker_data.section ] ) { $added[ $client.name ][ $new_tracker_data.section ] = [System.Collections.ArrayList]::new() }
                    $added[ $client.name ][ $new_tracker_data.section ] += [PSCustomObject]@{ id = $new_tracker_data.topic_id; name = $new_tracker_data.topic_title; size = $new_tracker_data.tor_size_bytes }
                }
            }
        }
        elseif ( !$existing_torrent -and $get_news -eq 'Y' -and ( $new_tracker_data.reg_time -lt ( ( Get-Date ).ToUniversalTime( ).AddDays( 0 - $min_delay ) ) -or $new_tracker_data.tor_status -eq 2 ) `
                -and $new_torrent_key -notin $new_torrents_keys_2 ) {
            # раздача слишком многосидовая для добавления (но была бы нормальная для обновления, просто оказалось нечего обновлять)
        }
        elseif ( !$existing_torrent -eq 'Y' -and $get_news -eq 'Y' -and $new_tracker_data.reg_time -ge ( (Get-Date).ToUniversalTime().AddDays( 0 - $min_delay ) ) ) {
            Write-Log ( 'Раздача ' + $new_tracker_data.topic_id + ' слишком новая.' )
        }
        elseif ( $get_news -ne 'Y') {
            # раздача новая, но выбрано не добавлять новые. Значит ничего и не делаем.
        }
        else {
            Write-Log ( 'Случилось что-то странное на раздаче ' + $new_tracker_data.topic_id + ' лучше остановимся' ) -Red
            exit
        }
    }
} # по наличию новых раздач.

Write-Log "Добавлено: $(Get-Spell -qty ( ( $added.keys | ForEach-Object { $added[$_] } ).values.id.count ) -spelling 1 -entity 'torrents' )"
Write-Log "Обновлено: $(Get-Spell -qty ( ( $refreshed.keys | ForEach-Object { $refreshed[$_] } ).values.id.count ) -spelling 1 -entity 'torrents' )"

Remove-Variable -Name obsolete -ErrorAction SilentlyContinue
if ( $nul -ne $settings.telegram.tg_token -and '' -ne $settings.telegram.tg_token -and $settings.telegram.report_obsolete -and $settings.telegram.report_obsolete -eq 'Y' ) {
    Write-Log 'Ищем неактуальные раздачи.'
    if ( $forced_sections -and $db_hash_to_id ) {
        # $hash_to_id = $hash_to_id.keys{ key = $_; value = $hash_to_id[ ( $hash_to_id.keys | Where-Object { $db_hash_to_id[$_] } ) ] }
        $hash_to_id = $hash_to_id.keys | Where-Object { $tracker_torrents[$_] } | ForEach-Object { @{ $_ = $hash_to_id[$_] } }
    }
    $obsolete_keys = @($hash_to_id.Keys | Where-Object { !$tracker_torrents[$_] } | Where-Object { $refreshed_ids -notcontains $hash_to_id[$_] } | `
            Where-Object { $tracker_torrents.Values.topic_id -notcontains $hash_to_id[$_] } | Where-Object { !$ignored_obsolete -or $nul -eq $ignored_obsolete[$hash_to_id[$_]] } )
    if ( $skip_obsolete ) {
        $obsolete_keys = $obsolete_keys | Where-Object { $id_to_info[$hash_to_id[$_]].client_key -notin $skip_obsolete }
    }
    $obsolete_torrents = $clients_torrents | Where-Object { $_.hash -in $obsolete_keys } | Where-Object { $_.topic_id -ne '' }
    if ( $rss ) {
        $obsolete_torrents = $obsolete_torrents | Where-Object { $_.category -ne $rss.category }
    }
    $obsolete_torrents | ForEach-Object {
        If ( !$obsolete ) { $obsolete = @{} }
        Write-Log ( "Левая раздача " + $_.topic_id + ' в клиенте ' + $_.client_key )
        if ( !$obsolete[$settings.clients[$_.client_key]] ) { $obsolete[ $settings.clients[$_.client_key]] = [System.Collections.ArrayList]::new() }
        $obsolete[$settings.clients[$_.client_key]] += ( $_.topic_id )
    }
}

if ( $nul -ne $settings.telegram.tg_token -and '' -ne $settings.telegram.tg_token -and $report_broken -and $report_broken -eq 'Y' ) {
    Remove-Variable broken -ErrorAction SilentlyContinue
    Write-Log 'Ищем проблемные раздачи.'
    $clients_torrents | Where-Object { $_.state -in ( 'missingFiles', 'error' ) } | ForEach-Object {
        if ( !$broken ) { $broken = @{ } }
        Write-Log ( "Проблемная раздача " + $_.topic_id + ' в клиенте ' + $_.client_key )
        if ( !$broken[$settings.clients[$_.client_key]] ) { $broken[ $settings.clients[$_.client_key]] = [System.Collections.ArrayList]::new() }
        $broken[$settings.clients[$_.client_key]] += ( $_.topic_id )
    }
}

if ( $rss ) {
    $rss_ids = @()
    if ( !$rss.url ) { $rss.url = 'https://rutr.my.to/ask_help.php' }
    $retry_cnt = 1
    while ( $true ) {
        try {
            $rss_data = ( Invoke-RestMethod -Uri $rss.url ).description.'#cdata-section'
            break
        }
        catch {
            if ( $error[0].Exception.Message -match 'time') {
                Write-Log "Нет ответа...`nЖдём 10 секунд и пробуем ещё раз" -Red    
            }
            else {
                Write-Log "Ошибка $($error[0].Exception.Message)`nЖдём 10 секунд и пробуем ещё раз" -Red
            }
            Start-Sleep -Seconds 10; $retry_cnt++; Write-Log "Попытка номер $retry_cnt"
            If ( $retry_cnt -gt 10 ) { break }
        }
    }

    $rss_add_cnt = 0
    if ( $rss_data -and $rss_data.count -gt 0 ) { Write-Log 'Добавляем новые раздачи из RSS' }
    foreach ( $rss_record in $rss_data ) {
        $id = ( $rss_record.split( "`n" ) | Select-String 't=\d+"' ).matches.value.replace( 't=', '' ).replace( '"', '').ToInt64($null)
        $rss_ids += $id
        if ( !$id_to_info[$id] ) {
            $keeper = ( $rss_record.split( "`n" ) | Select-String '👤 .+?</a>' ).matches.value.replace( '👤 ', '' ).replace( '</a>', '')
            $hash = ( $rss_record.split( "`n" ) | Select-String 'btih:.+?&tr' ).matches.value.replace( 'btih:', '' ).replace( '&tr', '')
            Write-Log "Добавляем раздачу $id для $keeper"
            $new_torrent_file = Get-ForumTorrentFile $id
            $success = Add-ClientTorrent -client $settings.clients[$rss.client] -file $new_torrent_file -path $rss.save_path -category $rss.category -addToTop:$( $add_to_top -eq 'Y' )
            Start-Sleep -Seconds 1
            if ( $success -eq $true -and $rss.tag_user.ToUpper() -eq 'Y' ) {
                Set-Comment -client $settings.clients[$rss.client] -torrent @{ hash = $hash } -label $keeper -silent
            }
            $rss_add_cnt++
        }
    }
    $rss_del_cnt = 0
    if ( $rss.purge -and $rss.purge.ToUpper() -eq 'Y' -and $rss.category -and $rss.category -ne '' ) {
        Write-Log 'Удаляем старые ненужные RSS-раздачи'
        foreach ( $rss_torrent in ( $clients_torrents | Where-Object { $_.category -eq $rss.category } ) ) {
            if ( $rss_torrent.topic_id -notin $rss_ids -and $rss_torrent.state -in @('uploading', 'stalledUP', 'queuedUP', 'forcedUP' ) -and $rss_torrent.completion_on -le ( ( Get-Date -UFormat %s ).ToInt32($null) - 24 * 60 * 60 ) ) {
                # $existing_torrent = $id_to_info[ $rss_torrent.topic_id ]
                $client = $settings.clients[$rss_torrent.client_key]
                Write-Log "Удаляем раздачу $($rss_torrent.topic_id) - $($rss_torrent.name)"
                Remove-ClientTorrent -client $client -torrent $rss_torrent -deleteFiles
                $rss_del_cnt++
            }
        }
    }
}

if ( $control -eq 'Y' ) {
    Write-Log 'Запускаем встроенную регулировку'
    . ( Join-Path $PSScriptRoot Controller.ps1 )
}

$report_flag_file = "$PSScriptRoot\report_needed.flg"
if ( ( $refreshed.Count -gt 0 -or $added.Count -gt 0 -or ( $obsolete.Count -gt 0 -and $update_obsolete -eq 'Y' ) ) -and $update_stats -eq 'Y' -and $php_path ) {
    New-Item -Path $report_flag_file -ErrorAction SilentlyContinue | Out-Null
}
elseif ( $update_stats -ne 'Y' -or !$php_path ) {
    Remove-Item -Path $report_flag_file -ErrorAction SilentlyContinue | Out-Null
}

if ( ( $refreshed.Count -gt 0 -or $added.Count -gt 0 -or ( $obsolete.Count -gt 0 -and $settings.telegram.report_obsolete -eq 'Y' ) -or ( $broken.count -gt 0 -and $report_broken -eq 'Y' ) -or $notify_nowork -eq 'Y' -or $rss_add_cnt -gt 0 -or $rss_del_cnt -gt 0 ) -and $settings.telegram.tg_token -ne '' -and $settings.telegram.tg_chat -ne '' ) {
    Send-TGReport -refreshed $refreshed -added $added -rss_add_cnt $rss_add_cnt -rss_del_cnt $rss_del_cnt -obsolete $obsolete -broken $broken -token $settings.telegram.tg_token -chat_id $settings.telegram.tg_chat -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')
}
elseif ( $settings.telegram.report_nowork -eq 'Y' -and $settings.telegram.tg_token -ne '' -and $settings.telegram.tg_chat -ne '' ) { 
    Send-TGMessage -message ( ( $mention_script_tg -eq 'Y' ? 'Я' : ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') ) + ' отработал, ничего делать не пришлось.' ) -token $settings.telegram.tg_token -chat_id $settings.telegram.tg_chat -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')
}

if ( $update_trigger ) {
    $up_conn.Close()
}

if ( $report_stalled -eq 'Y' ) {
    Write-Log 'Ищем некачашки'
    $month_ago = ( Get-Date -UFormat %s ).ToInt32($null) - 30 * 24 * 60 * 60
    $stalleds = @()
    $clients_torrents | Where-Object { $_.state -in ( 'stalledDL', 'forcedDL' ) -and $_.added_on -le $month_ago } | ForEach-Object {
        $stalleds += @{ topic_id = $_.topic_id; hash = $_.infohash_v1; client_key = $_.client_key; trackers = $null }
    }
    if ( $stalleds.count -gt 0 ) {
        Write-Log ( 'Найдено ' + $stalleds.count + ' некачашек' )
        foreach ( $stalled in $stalleds ) {
            $params = @{ hash = $stalled.hash }
            $stalled.trackers = ( Invoke-WebRequest -Uri ( $settings.clients[$stalled.client_key].IP + ':' + $settings.clients[$stalled.client_key].port + '/api/v2/torrents/trackers' ) -WebSession $settings.clients[$stalled.client_key].sid -Body $params -TimeoutSec 120 ).Content | `
                ConvertFrom-Json | Where-Object { $_.status -ne 0 }
        }

        Write-Log 'Отсеиваем некачашки с ошибкой трекера'
        $stalleds = $stalleds | Where-Object { $_.status -ne 4 }
        Write-Log ( 'Осталось ' + $stalleds.count + ' некачашек' )

        $params = @{
            'help_load' = ( $stalleds.topic_id -join ',')
            'help_pwd'  = $stalled_pwd
        }
        Write-Log 'Отправляем список некачашек'
        Invoke-WebRequest -Method POST -Uri 'https://rutr.my.to/rto_api.php' -Body $params -ErrorVariable send_result | Out-Null
        if ( $send_result.count -eq 0 ) {
            Write-Log ( 'Отправлено ' + $stalleds.count + ' некачашек' )
        }
        else {
            Write-Log 'Не удалось отправить некачашки, проверьте пароль.'
        }
    }
    else { Write-Log 'Некачашек не обнаружено' }
}

If ( Test-Path -Path $report_flag_file ) {
    if ( $refreshed.Count -gt 0 -or $added.Count -gt 0 ) {
        # что-то добавилось, стоит подождать.
        Update-Stats -wait -send_report:( $send_reports -eq 'Y' -and ( $refreshed.Count -gt 0 -or $added.Count -gt 0 ) ) # с паузой.
    }
    else {
        Update-Stats -send_report:( $send_reports -eq 'Y' -and ( $refreshed.Count -gt 0 -or $added.Count -gt 0 ) ) # без паузы, так как это сработал флаг от предыдущего прогона.
    }
    Remove-Item -Path $report_flag_file -ErrorAction SilentlyContinue
}
