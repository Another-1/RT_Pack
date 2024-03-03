Write-Output 'Подгружаем настройки'

$use_timestamp = 'N'
$separator = $( $PSVersionTable.OS.ToLower().contains('windows') ? '\' : '/' )
try { . ( Join-Path $PSScriptRoot _settings.ps1 ) } catch { }

$str = 'Подгружаем функции'
if ( $use_timestamp -ne 'Y' ) { Write-Host $str } else { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) }
. ( Join-Path $PSScriptRoot _functions.ps1 )

Test-PSVersion
Test-Module 'PsIni' 'для чтения настроек TLO'
Test-Module 'PSSQLite' 'для работы с базой TLO'
Write-Log 'Проверяем актуальность скриптов' 
Test-Version ( $PSCommandPath | Split-Path -Leaf ) $alert_oldies
Test-Version ( '_functions.ps1' ) -alert $alert_oldies

try { . ( Join-Path $PSScriptRoot '_client_ssd.ps1' ) } catch { }
Write-Log 'Проверяем наличие всех нужных настроек'
$tg_token = Test-Setting 'tg_token'
if ( $tg_token -ne '') {
    $tg_chat = Test-Setting 'tg_chat' -required
}

$alert_oldies = Test-Setting 'alert_oldies'
$use_timestamp = Test-Setting 'use_timestamp'
$tlo_path = Test-Setting 'tlo_path' -required
$ini_path = Join-Path $tlo_path 'data' 'config.ini'
Write-Log 'Читаем настройки Web-TLO'
$ini_data = Get-IniContent $ini_path
$get_news = Test-Setting 'get_news'
$min_days = Test-Setting 'min_days' -default $ini_data.sections.rule_date_release
if (!$min_days ) { $min_days = 0 }
$get_blacklist = Test-Setting 'get_blacklist'
$max_seeds = Test-Setting -setting 'max_seeds' -default $ini_data.sections.rule_topics
$get_hidden = Test-Setting 'get_hidden'
$get_shown = Test-Setting 'get_shown'
$get_lows = Test-Setting 'get_lows'
$get_mids = Test-Setting 'get_mids'
$get_highs = Test-Setting 'get_highs'
$control = Test-Setting 'control'
$auto_update = Test-Setting 'auto_update'
if ( $tg_token -ne '') {
    $report_obsolete = Test-Setting 'report_obsolete'
}
$report_stalled = Test-Setting 'report_stalled'
$report_nowork = Test-Setting 'report_nowork'
$update_stats = Test-Setting 'update_stats'
if ( $update_stats -eq 'Y' ) {
    $update_obsolete = Test-Setting 'update_obsolete'
}

if ( $update_stats -eq 'Y') {
    if ( !$send_reports ) { Write-Log 'Для обновления БД TLO и отправки отчётов нужен интерпретатор php на этом же компе.' }
    $send_reports = Test-Setting 'send_reports'
    while ( $true ) {
        $php_path = Test-Setting 'php_path' -required
        If ( Test-Path $php_path ) { break }
        Write-Log 'Не нахожу такого файла, проверьте ввод' -ForegroundColor -Red
        Remove-Variable -Name $php_path
    }
}

$sections = Get-IniSections -useForced
Test-ForumWorkingHours -verbose

If ( Test-Path "$PSScriptRoot\_masks.ps1" ) {
    Write-Output 'Подтягиваем названия раздач из маскированных разделов'
    . "$PSScriptRoot\_masks.ps1"
    $masks_db = @{}
    $masks_db_plain = @{}
    $masks_like = @{}
    $conn = Open-TLODatabase
    $columnNames = Get-DB_ColumnNames $conn
    $masks.GetEnumerator() | ForEach-Object {
        $group_mask = $_.Value
        ( $_.Key -replace ( '\s*', '')).split(',') | ForEach-Object {
            $db_return = ( Invoke-SqliteQuery -Query ( 'SELECT id FROM Topics WHERE ' + $columnNames['forum_id'] + '=' + $_ + ' AND ' + $columnNames['name'] + ' NOT LIKE "%' + ( ($group_mask -replace ('\s', '%')) -join '%" AND ' + $columnNames['name'] + ' NOT LIKE "%' ) + '%"' ) -SQLiteConnection $conn )
            if ( $db_return ) {
                $masks_db[$_] = $db_return.GetEnumerator() | ForEach-Object { @{$_.id.ToString() = 1 } }
                Write-Output ( 'По разделу ' + $_ + ' найдено ' + $masks_db[$_].count + ' неподходящих раздач' )
            }
            $masks_like[$_] = $group_mask -replace ('^|$|\s', '*')
        }
    }
    $masks_db.Keys | ForEach-Object {
        $masks_db[$_].Keys | ForEach-Object {
            $masks_db_plain[$_] = 1
        }
    }
    $conn.Close()
}
else {
    Remove-Variable -Name masks_like -ErrorAction SilentlyContinue
    Remove-Variable -Name masks_db -ErrorAction SilentlyContinue
}

Write-Log 'Достаём из TLO данные о разделах'
$section_details = Get-IniSectionDetails $sections
$forum = Set-ForumDetails

if ( $get_blacklist -eq 'N' ) {
    $blacklist = Get-Blacklist -verbose
    if ( !$blacklist -or $blacklist.Count -eq 0 ) {
        $oldblacklist = Get-OldBlacklist
    }
    Write-Log ( 'Раздач в чёрных списках: ' + ( $blacklist.Count + $oldblacklist.Count ) )
}

if ( $debug -ne 1 -or $env:TERM_PROGRAM -ne 'vscode' -or $null -eq $tracker_torrents -or $tracker_torrents.count -eq 0 ) {
    $tracker_torrents = Get-TrackerTorrents $sections $max_seeds
}

if ( $debug -ne 1 -or $env:TERM_PROGRAM -ne 'vscode' -or $null -eq $clients_torrents -or $clients_torrents.count -eq 0 ) {
    $clients = Get-Clients
    $clients_torrents = Get-ClientsTorrents $clients
}

$hash_to_id = @{}
$id_to_info = @{}

Write-Log 'Сортируем таблицы'
$clients_torrents | Where-Object { $null -ne $_.topic_id } | ForEach-Object {
    if ( !$_.infohash_v1 -or $nul -eq $_.infohash_v1 -or $_.infohash_v1 -eq '' ) { $_.infohash_v1 = $_.hash }
    $hash_to_id[$_.infohash_v1] = $_.topic_id

    $id_to_info[$_.topic_id] = @{
        client_key = $_.client_key
        save_path  = $_.save_path
        category   = $_.category
        name       = $_.name
        hash       = $_.hash
        size       = $_.size
    }
}

Write-Log 'Ищем новые раздачи'

$new_torrents_keys = $tracker_torrents.keys | Where-Object { $null -eq $hash_to_id[$_] }
Write-Log ( 'Новых раздач: ' + $new_torrents_keys.count )

if ( $get_hidden -and $get_hidden -eq 'N' ) {
    Write-Log 'Отсеиваем раздачи из скрытых разделов'
    $new_torrents_keys = $new_torrents_keys | Where-Object { $tracker_torrents[$_].hidden_section -eq '0' }
    Write-Log ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

if ( $get_shown -and $get_shown -eq 'N' ) { 
    Write-Log 'Отсеиваем раздачи из видимых разделов'
    $new_torrents_keys = $new_torrents_keys | Where-Object { $tracker_torrents[$_].hidden_section -eq '1' }
    Write-Log ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

if ( $get_lows -and $get_lows.ToUpper() -eq 'N' ) {
    Write-Log 'Отсеиваем раздачи с низким приоритетом'
    $new_torrents_keys = $new_torrents_keys | Where-Object { $tracker_torrents[$_].priority -ne '0' }
    Write-Log ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

if ( $get_mids -and $get_mids.ToUpper() -eq 'N' ) {
    Write-Log 'Отсеиваем раздачи со средним приоритетом'
    $new_torrents_keys = $new_torrents_keys | Where-Object { $tracker_torrents[$_].priority -ne '1' }
    Write-Log ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

if ( $get_highs -and $get_highs.ToUpper() -eq 'N' ) {
    Write-Log 'Отсеиваем раздачи с высоким приоритетом'
    $new_torrents_keys = $new_torrents_keys | Where-Object { $tracker_torrents[$_].priority -ne '2' }
    Write-Log ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

if ( $nul -ne $get_blacklist -and $get_blacklist.ToUpper() -eq 'N' ) {
    Write-Log 'Отсеиваем раздачи из чёрного списка'
    if ( $blacklist.Count -ne 0 ) { $new_torrents_keys = $new_torrents_keys | Where-Object { $null -eq $blacklist[$_] } }
    if ( $oldblacklist -and $oldblacklist.Count -ne 0 ) { $new_torrents_keys = $new_torrents_keys | Where-Object { $null -eq $oldblacklist[$tracker_torrents[$_].id] } }
    Write-Log ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

if ( $masks_db ) {
    Write-Output 'Отфильтровываем раздачи по маскам'
    $new_torrents_keys = $new_torrents_keys | Where-Object { !$masks_db_plain[$tracker_torrents[$_].id] }
    Write-Output ( 'Осталось раздач: ' + $new_torrents_keys.count )
}

$added = @{}
$refreshed = @{}

if ( $new_torrents_keys ) {
    $ProgressPreference = 'SilentlyContinue' # чтобы не мелькать прогресс-барами от скачивания торрентов
    foreach ( $new_torrent_key in $new_torrents_keys ) {
        $new_tracker_data = $tracker_torrents[$new_torrent_key]
        $subfolder_kind = $section_details[$new_tracker_data.section].data_subfolder
        $existing_torrent = $id_to_info[ $new_tracker_data.id ]
        if ( $existing_torrent ) {
            $client = $clients[$existing_torrent.client_key]
            Write-Log ( "Раздача " + $new_tracker_data.id + ' обнаружена в клиенте ' + $client.Name )
        }
        else {
            $client = $clients[$section_details[$new_tracker_data.section].client]
            if (!$client) {
                $client = $clients[$section_details[$new_tracker_data.section].client]
            }
        }
        
        if ( $new_tracker_data.releaser -in $priority_releasers.keys ) {
            $min_secs = $priority_releasers[$new_tracker_data.releaser] * 86400
        }
        else {
            $min_secs = $min_days * 86400
        }
        if ( $existing_torrent ) {
            if ( !$forum.sid ) { Initialize-Forum $forum }
            $new_torrent_file = Get-ForumTorrentFile $new_tracker_data.id
            $on_ssd = ( $nul -ne $ssd -and $existing_torrent.save_path[0] -in $ssd[$existing_torrent.client_key] )
            $new_tracker_data.name = ( Get-TorrentInfo $new_tracker_data.id ).name
            $text = "Обновляем раздачу " + $new_tracker_data.id + " " + $new_tracker_data.name + ' в клиенте ' + $client.Name + ' (' + ( to_kmg $existing_torrent.size 1 ) + ' -> ' + ( to_kmg $new_tracker_data.size 1 ) + ')'
            Write-Log $text
            if ( $nul -ne $tg_token -and '' -ne $tg_token ) {
                if ( !$refreshed[ $client.Name ] ) { $refreshed[ $client.Name] = @{} }
                if ( !$refreshed[ $client.Name ][ $new_tracker_data.section] ) { $refreshed[ $client.Name ][ $new_tracker_data.section ] = [System.Collections.ArrayList]::new() }
                if ( $ssd ) {
                    $refreshed[ $client.Name][ $new_tracker_data.section ] += [PSCustomObject]@{
                        id       = $new_tracker_data.id
                        comment  = ( $on_ssd ? ' SSD' : ' HDD' ) + ' ' + $existing_torrent.save_path[0]
                        name     = $new_tracker_data.name
                        old_size = $existing_torrent.size
                        new_size = $new_tracker_data.size
                    }
                }
                else {
                    $refreshed[ $client.Name][ $new_tracker_data.section ] += [PSCustomObject]@{
                        id       = $new_tracker_data.id
                        comment  = ''
                        name     = $new_tracker_data.name
                        old_size = $existing_torrent.size
                        new_size = $new_tracker_data.size
                    }
                }
                $refreshed_ids += $new_tracker_data.id
            }
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
            Add-ClientTorrent $client $new_torrent_file $existing_torrent.save_path $existing_torrent.category
            While ($true) {
                Write-Log 'Ждём 5 секунд чтобы раздача точно "подхватилась"'
                Start-Sleep -Seconds 5
                $new_tracker_data.name = ( Get-ClientTorrents -client $client -hash $new_torrent_key ).name
                if ( $null -ne $new_tracker_data.name ) { break }
            }
            if ( $new_tracker_data.name -eq $existing_torrent.name -and $subfolder_kind -le '2') {
                Remove-ClientTorrent $client $existing_torrent.hash
            }
            else {
                Remove-ClientTorrent $client $existing_torrent.hash -deleteFiles
            }
            Start-Sleep -Milliseconds 100 
        }
        elseif ( !$existing_torrent -and $get_news -eq 'Y' -and ( ( $new_tracker_data.reg_time -lt ( ( Get-Date -UFormat %s  ).ToInt32($nul) - $min_secs ) ) -or $new_tracker_data.status -eq 2 ) ) {
            $is_ok = $true
            if ( $masks_db -and $masks_db[$new_tracker_data.section.ToString()] -and $masks_db[$new_tracker_data.section.ToString()][$new_tracker_data.id] ) { $is_ok = $false }
            else {
                if ( $masks_like -and $masks_like[$new_tracker_data.section.ToString()] ) {
                    $new_tracker_data.name = ( Get-TorrentInfo $new_tracker_data.id ).name
                    $is_ok = $false
                    $masks_like[$new_tracker_data.section.ToString()] | ForEach-Object {
                        if ( -not $is_ok -and $new_tracker_data.name -like $_ ) {
                            $is_ok = $true
                        }
                    }
                }
            }
            if ( -not $is_ok ) {
                Write-Log ( 'Раздача ' + $new_tracker_data.name + ' отброшена фильтрами' )
                continue
            }
            if ( $new_tracker_data.section -in $skip_sections ) {
                # Write-Log ( 'Раздача ' + $new_tracker_data.id + ' из необновляемого раздела' )
                continue
            }
            if ( !$forum.sid ) { Initialize-Forum $forum }
            $new_torrent_file = Get-ForumTorrentFile $new_tracker_data.id
            if ( $null -eq $new_tracker_data.name ) { $new_tracker_data.name = ( Get-ForumTorrentInfo $new_tracker_data.id ).name }
            $text = "Добавляем раздачу " + $new_tracker_data.id + " " + $new_tracker_data.name + ' в клиент ' + $client.Name + ' (' + ( to_kmg $new_tracker_data.size 1 ) + ')'
            Write-Log $text
            if ( $nul -ne $tg_token -and '' -ne $tg_token ) {
                if ( !$added[ $client.Name ] ) { $added[ $client.Name ] = @{} }
                if ( !$added[ $client.Name ][ $new_tracker_data.section ] ) { $added[ $client.Name ][ $new_tracker_data.section ] = [System.Collections.ArrayList]::new() }
                $added[ $client.Name][ $new_tracker_data.section ] += [PSCustomObject]@{ id = $new_tracker_data.id; name = $new_tracker_data.name; size = $new_tracker_data.size }
            }
            $save_path = $section_details[$new_tracker_data.section].data_folder
            if ( $subfolder_kind -eq '1' ) {
                $save_path = ( $save_path -replace ( '\\$', '') -replace ( '/$', '') ) + '/' + $new_tracker_data.id # добавляем ID к имени папки для сохранения
            }       
            elseif ( $subfolder_kind -eq '2' ) {
                $save_path = ( $save_path -replace ( '\\$', '') -replace ( '/$', '') ) + '/' + $new_torrent_key  # добавляем hash к имени папки для сохранения
            }
            $on_ssd = ( $ssd -and $save_path[0] -in $ssd[$section_details[$new_tracker_data.section].client] )
            if ( $ssd -and $ssd[$section_details[$new_tracker_data.section].client] ) {
                if ( $on_ssd -eq $false ) {
                    Set-ClientSetting $client 'temp_path' ( Join-Path ( $ssd[$section_details[$new_tracker_data.section].client][0] + $( $separator -eq '\' ? ':' : '' ) ) 'Incomplete' )
                    Set-ClientSetting $client 'temp_path_enabled' $true
                    Set-ClientSetting $client 'preallocate_all' $false
                }
                else {
                    Set-ClientSetting $client 'temp_path_enabled' $false
                    Set-ClientSetting $client 'preallocate_all' $false
                }
            }
            Add-ClientTorrent $client $new_torrent_file $save_path $section_details[$new_tracker_data.section].label
        }
        elseif ( !$existing_torrent -eq 'Y' -and $get_news -eq 'Y' -and $new_tracker_data.reg_time -ge ( ( Get-Date -UFormat %s ).ToInt32($nul) - $min_days * 86400 ) ) {
            Write-Log ( 'Раздача ' + $new_tracker_data.id + ' слишком новая.' )
        }
        elseif ( $get_news -ne 'Y') {
            # раздача новая, но выбрано не добавлять новые. Значит ничего и не делаем.
        }
        else {
            Write-Log ( 'Случилось что-то странное на раздаче ' + $new_tracker_data.id + ' лучше остановимся' ) -Red
            exit
        }
    }
} # по наличию новых раздач.

Remove-Variable -Name obsolete -ErrorAction SilentlyContinue
if ( $nul -ne $tg_token -and '' -ne $tg_token -and $report_obsolete -and $report_obsolete -eq 'Y' ) {
    Write-Log 'Ищем неактуальные раздачи.'
    $obsolete_keys = $hash_to_id.Keys | Where-Object { !$tracker_torrents[$_] } | Where-Object { $refreshed_ids -notcontains $hash_to_id[$_] } | `
        Where-Object { $tracker_torrents.Values.id -notcontains $hash_to_id[$_] } | Where-Object { !$ignored_obsolete -or $nul -eq $ignored_obsolete[$hash_to_id[$_]] }
    $obsolete_torrents = $clients_torrents | Where-Object { $_.hash -in $obsolete_keys } | Where-Object { $_.topic_id -ne '' }
    $obsolete_torrents | ForEach-Object {
        If ( !$obsolete ) { $obsolete = @{} }
        Write-Log ( "Левая раздача " + $_.topic_id + ' в клиенте ' + $clients[$_.client_key].Name )
        if ( !$obsolete[$clients[$_.client_key].Name] ) { $obsolete[ $clients[$_.client_key].Name] = [System.Collections.ArrayList]::new() }
        $obsolete[$clients[$_.client_key].Name] += ( $_.topic_id )
    }
}

if ( $control -eq 'Y' ) {
    Write-Log 'Запускаем встроенную регулировку'
    . "$PSScriptRoot\Controller.ps1"
}

$report_flag_file = "$PSScriptRoot\report_needed.flg"
if ( ( $refreshed.Count -gt 0 -or $added.Count -gt 0 -or ( $obsolete.Count -gt 0 -and $update_obsolete -eq 'Y' ) ) -and $update_stats -eq 'Y' -and $php_path ) {
    New-Item -Path $report_flag_file -ErrorAction SilentlyContinue | Out-Null
}
elseif ( $update_stats -ne 'Y' -or !$php_path ) {
    Remove-Item -Path $report_flag_file -ErrorAction SilentlyContinue | Out-Null
}

if ( ( $refreshed.Count -gt 0 -or $added.Count -gt 0 -or $obsolete.Count -gt 0 -or $notify_nowork -eq 'Y' ) -and $tg_token -ne '' -and $tg_chat -ne '' ) {
    Send-TGReport $refreshed $added $obsolete $tg_token $tg_chat
}
elseif ( $report_nowork -eq 'Y' -and $tg_token -ne '' -and $tg_chat -ne '' ) { 
    Send-TGMessage 'Adder отработал, ничего делать не пришлось.' $tg_token $tg_chat
}

if ( $report_stalled -eq 'Y' ) {
    Write-Log 'Отправляем список некачашек'
    $month_ago = ( Get-Date -UFormat %s ).ToInt32($null) - 30 * 24 * 60 * 60
    $stalleds = @()
    $clients_torrents | Where-Object { $_.state -eq 'stalledDL' -and $_.added_on -le $month_ago } | ForEach-Object {
        $stalleds += $_.topic_id 
    }
    if ( $stalleds.count -gt 0 ) {
        $params = @{'help_load' = ( $stalleds -join ',') }
        Invoke-WebRequest -Method POST -Uri 'https://rutr.my.to/rto_api.php' -Body $params | Out-Null
        Write-Log ( 'Отправлено ' + $stalleds.count + ' некачашек' )
        # if ( $tg_token -ne '' ) {
        #     Send-TGMessage ( 'Отправлено ' + $stalleds.count + ' некачашек' ) $tg_token $tg_chat
        # }
    }
    else { Write-Log 'Некачашек не обнаружено' }
}

If ( Test-Path -Path $report_flag_file ) {
    if ( $refreshed.Count -gt 0 -or $added.Count -gt 0 ) {
        # что-то добавилось, стоит подождать.
        # Update-Stats -wait -check -send_report:( $send_reports -eq 'Y' ) # с паузой и проверкой условия по чётному времени.
        Update-Stats -wait -send_report:( $send_reports -eq 'Y' -and ( $refreshed.Count -gt 0 -or $added.Count -gt 0 ) ) # с паузой.
    }
    else {
        # Update-Stats -check -send_reports:( $send_reports -eq 'Y' ) # без паузы, так как это сработал флаг от предыдущего прогона. Но с проверкой по чётному времени.
        Update-Stats -send_reports:( $send_reports -eq 'Y' -and ( $refreshed.Count -gt 0 -or $added.Count -gt 0 ) ) # без паузы, так как это сработал флаг от предыдущего прогона.
    }
    Remove-Item -Path $report_flag_file -ErrorAction SilentlyContinue
}
