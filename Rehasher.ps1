param ([switch]$offline, [switch]$verbos )

$window_title = 'Rehasher'
Write-Host "$([char]0x1B)]0;$window_title`a"

Write-Output 'Подгружаем настройки'
$separator = $separator = $( $PSVersionTable.OS.ToLower().contains('windows') ? '\' : '/' )
if ( Test-Path ( Join-Path $PSScriptRoot 'settings.json') ) {
    # $debug = 1
    $settings = Get-Content -Path ( Join-Path $PSScriptRoot 'settings.json') | ConvertFrom-Json -AsHashtable
    $standalone = $true
}
else {
    try {
        if ( !$settings ) {
            . ( Join-Path $PSScriptRoot _settings.ps1 )
            $settings = [ordered]@{}
            $settings.interface = @{}
            $settings.interface.use_timestamp = ( $use_timestamp -eq 'Y' ? 'Y' : 'N' )
        }
        $standalone = $false
    }
    catch { Write-Host ( 'Не найден файл настроек ' + ( Join-Path $PSScriptRoot _settings.ps1 ) + ', видимо это первый запуск.' ) }
}

$str = 'Подгружаем функции'
if ( $settings.interface.use_timestamp -ne 'Y' ) {
    if ( $mention_script_log -eq 'Y') {
        Write-Host "#$( ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') ) " -ForegroundColor Green -NoNewline
    }
    Write-Host "$str"
}
else {
    Write-Host "$( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) " -NoNewline
    if ( $mention_script_log -eq 'Y') {
        Write-Host "#$( ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') ) " -ForegroundColor Green -NoNewline
    }
    Write-Host "$str"
}

. ( Join-Path $PSScriptRoot _functions.ps1 )

Write-Log 'Проверяем версии скриптов на актуальность'
# Test-Version '_functions.ps1' 'Rehasher'
if ( ( Test-Version '_functions.ps1' 'Rehasher' ) -eq $true ) {
    Write-Log 'Запускаем новую версию  _functions.ps1'
    . ( Join-Path $PSScriptRoot '_functions.ps1' )
}

Test-Version ( $PSCommandPath | Split-Path -Leaf ) 'Rehasher'
Remove-Item ( Join-Path $PSScriptRoot '*.new' ) -ErrorAction SilentlyContinue
Test-PSVersion

$max_rehash_qty = Test-Setting 'max_rehash_qty'
$max_rehash_size_bytes = Test-Setting 'max_rehash_size_bytes'
$frequency = Test-Setting 'frequency'
$use_timestamp = Test-Setting 'use_timestamp'
$rehash_freshes = Test-Setting 'rehash_freshes'
if ( $rehash_freshes -eq 'N') {
    $freshes_delay = Test-Setting 'freshes_delay'
}
$wait_finish = Test-Setting 'wait_finish'
$mix_clients = Test-Setting 'mix_clients'
$check_state_delay = Test-Setting 'check_state_delay'
$start_errored = Test-Setting 'start_errored' 'Y'

if ( ( ( Get-Process | Where-Object { $_.ProcessName -eq 'pwsh' } ).CommandLine -like '*ehasher.ps1*').count -gt 1 ) {
    Write-Log 'Я и так уже выполняюсь, выходим' -Red
    exit
}

Test-Module 'PsIni' 'для чтения настроек TLO'
Test-Module 'PSSQLite' 'для работы с базой TLO'

if ( $standalone -eq $true ) { $settings.interface.use_timestamp = Test-Setting 'use_timestamp' -json_path 'interface' -required } else { $settings.interface.use_timestamp = Test-Setting 'use_timestamp' -required }
if ( $standalone -eq $false ) {
    $tlo_path = Test-Setting 'tlo_path' -required
    $ini_path = Join-Path $tlo_path 'data' 'config.ini'
    Write-Log 'Читаем настройки Web-TLO'
    $ini_data = Get-IniContent $ini_path
}

$min_repeat_epoch = ( Get-Date -UFormat %s ).ToInt32($null) - ( $frequency * 24 * 60 * 60 ) # количество секунд между повторными рехэшами одной раздачи
$min_freshes_epoch = ( Get-Date -UFormat %s ).ToInt32($null) - ( $freshes_delay * 24 * 60 * 60 ) # количество секунд до первого рехэша новых раздач

if ( $debug -ne 1 -or $env:TERM_PROGRAM -ne 'vscode' -or $null -eq $clients_torrents -or $clients_torrents.count -eq 0 ) {
    Get-Clients
    if ( $rss -and !$rss.client ) {
        $settings.clients['RSS'] = @{ IP = $rss.client_IP; port = $rss.client_port; login = $rss.client_login; password = $rss.client_password; name = 'RSS'; ssl = 0 }
        $rss.client = 'RSS'
    }
    $off = $offline.IsPresent
    # $off = $true
    if ( $off ) {
        $client = Select-Client
        Get-ClientApiVersions -clients @{ $client.name = $client }
        $clients_torrents = Get-ClientsTorrents -clients @{ $client.name = $client } -mess_sender 'Rehasher' -noIDs -completed
    }
    else {
        Get-ClientApiVersions $settings.clients
        $clients_torrents = Get-ClientsTorrents -mess_sender 'Rehasher' -noIDs -completed
    }
}

Write-Log 'Получаем из БД TLO комбинации ID - hash'
$conn = Open-TLODatabase
$db_hash_to_id = Get-DBHashToId -conn $conn # всё нормально, это нужно для Get-TopicIDs
$conn.Close( )

Write-Log 'Исключаем уже хэшируемые и стояшие в очереди на рехэш'
$before = $clients_torrents.count
$clients_torrents = $clients_torrents | Where-Object { $_.state -ne 'checkingUP' }
$already_hashing = $before - $clients_torrents.count
Write-Log ( "Исключено раздач: $already_hashing" )

$db_data = @{}
$database_path = $PSScriptRoot + $separator + 'rehashes.db'
Write-Log 'Подключаемся к БД'
$conn = Open-Database $database_path
Invoke-SqliteQuery -Query 'CREATE TABLE IF NOT EXISTS rehash_dates (hash VARCHAR PRIMARY KEY NOT NULL, rehash_date INT)' -SQLiteConnection $conn
Write-Log 'Выгружаем из БД даты рехэшей'
Invoke-SqliteQuery -Query 'SELECT * FROM rehash_dates' -SQLiteConnection $conn | ForEach-Object { $db_data[$_.hash] = $_.rehash_date }

$full_data_sorted = [System.Collections.ArrayList]::new()
Write-Log 'Ищем раздачи в БД рехэшей'
$clients_torrents | ForEach-Object {
    if ( !$_.infohash_v1 -or $nul -eq $_.infohash_v1 -or $_.infohash_v1 -eq '' ) { $_.infohash_v1 = $_.hash }
    if ($_.infohash_v1 -and ( $nul -ne $_.infohash_v1 ) -and ( $_.infohash_v1 -ne '' ) ) {
        $full_data_sorted.Add( [PSCustomObject]@{
                hash          = $_.infohash_v1
                rehash_date   = $( $null -ne $db_data[$_.infohash_v1] -and $db_data[$_.infohash_v1] -gt 0 ? $db_data[$_.infohash_v1] : 0 )
                client_key    = $_.client_key
                size          = $_.size
                name          = $_.name
                completion_on = $_.completion_on
            } ) | Out-Null
    }
}

Write-Log 'Ищем время ближайшего следующего рехэша'
$closest_rehash = (Get-Date -UFormat %s).ToInt32($null) + 3 * 365 * 24 * 60 * 60
$full_data_sorted | ForEach-Object {
    if ( $_.completion_on -gt $min_freshes_epoch -and ( $_.rehash_date -gt $min_repeat_epoch -or $_.rehash_date -eq 0 ) ) {
        $closest_rehash = (@( $closest_rehash; (@( ( $rehash_freshes -eq 'Y' ? 0 : $_.completion_on + $freshes_delay * 24 * 60 * 60 ); $_.rehash_date + $frequency * 24 * 60 * 60) | Measure-Object -Maximum).Maximum ) | Measure-Object -Minimum).Minimum
    }
}

$closest_datetime = [System.TimeZoneInfo]::ConvertTimeFromUtc(([System.DateTimeOffset]::FromUnixTimeSeconds( $closest_rehash ).DateTime ), $(Get-TimeZone))

if ( $rehash_freshes -ne 'Y') {
    $before = $full_data_sorted.count
    Write-Log 'Исключаем свежескачанные раздачи'
    $full_data_sorted = $full_data_sorted | Where-Object { $_.completion_on -lt $min_freshes_epoch }
    Write-Log ( 'Исключено раздач: ' + ( $before - $full_data_sorted.count ) )
}

Write-Log 'Исключаем раздачи, которые рано рехэшить'
$before = $full_data_sorted.count
$full_data_sorted = $full_data_sorted | Where-Object { $_.rehash_date -lt $min_repeat_epoch }
Write-Log ( 'Исключено раздач: ' + ( $before - $full_data_sorted.count ) )

if ( $max_rehash_size_bytes -and $max_rehash_size_bytes -gt 0 ) {
    $before = $full_data_sorted.count
    Write-Log "Исключаем явно слишком большие раздачи (больше $( to_kmg $max_rehash_size_bytes ))"
    $full_data_sorted = @( $full_data_sorted | Where-Object { $_.size -le $max_rehash_size_bytes } )
}
$was_count = $full_data_sorted.count
$was_sum_size = ( $full_data_sorted | Measure-Object -Property size -Sum ).Sum

Write-Log 'Сортируем всё по дате рехэша и размеру'
$full_data_sorted = $full_data_sorted | Sort-Object -Property size -Descending | Sort-Object -Property rehash_date -Stable

if ( $mix_clients -eq 'Y' -and !$off ) {
    Write-Log 'Тщательнейшим образом перемешиваем клиентов'
    if ( $full_data_sorted.count -gt 1 ) {
        $per_client = @{}
        $full_resorted = [System.Collections.ArrayList]::new()
        foreach ( $i in  1..( $full_data_sorted | ForEach-Object { $settings.clients[$_.client_key].seqno } | Measure-Object -Maximum ).Maximum ) {
            $this_client = ( $settings.clients.Keys | Where-Object { $settings.clients[$_].seqno -eq $i } ).ToString()
            $per_client[$i] = $full_data_sorted | Where-Object { $_.client_key -eq $this_client }
        }
    
        $done = 0
        $max_qty = ( $per_client.GetEnumerator() | ForEach-Object { $_.Value.count } | Measure-Object -Maximum ).Maximum
        for ( $j = 0; $j -lt $max_qty ; $j++) {
            foreach ( $k in 1..$i ) {
                try {
                    if ( $per_client[$k][$j] ) {
                        $full_resorted += $per_client[$k][$j]
                        $done ++ 
                    }
                }
                catch {}
                if ( $done -ge $max_rehash_qty ) { break }
            }
            if ( $done -ge $max_rehash_qty ) { break }
        }
        $full_data_sorted = $full_resorted
        Remove-Variable -Name full_resorted
    } 
}

$sum_cnt = 0
$sum_size = 0
if ( $full_data_sorted.count -gt 0 ) {
    Write-Log "Найдено $($full_data_sorted.count) раздач, которые пора рехэшить. Общий объём $(to_kmg( $full_data_sorted | Measure-Object -Property size -Sum ).Sum)"
}
else {
    Write-Log 'Рехэшить пока нечего, выходим'
}

foreach ( $torrent in $full_data_sorted ) {

    if ( $max_rehash_size_bytes - $sum_size -lt $torrent.size ) {
        # Write-Log 'Достигнут целевой объём раздач'
        # break
        $too_big = $true
        continue
    }
    if ( $sum_cnt -ge $max_rehash_qty ) {
        Write-Log 'Достигнуто целевое количество раздач'
        break
        # continue
    }
    $too_big = $false
    if ( ( Get-Process | Where-Object { $_.ProcessName -eq 'pwsh' } | Where-Object { $_.CommandLine -like '*Adder.ps1' -or $_.CommandLine -like '*Controller.ps1' } ).count -gt 0 ) {
        Write-Log 'Выполняется Adder или Controller, подождём...' -Red
        while ( ( Get-Process | Where-Object { $_.ProcessName -eq 'pwsh' } | Where-Object { $_.CommandLine -like '*Adder.ps1' -or $_.CommandLine -like '*Controller.ps1' } ).count -gt 0 ) {
            Start-Sleep -Seconds 10
        }
    }    
    if ( $wait_finish -eq 'Y' ) {
        Write-Log ( 'Будем рехэшить раздачу "' + $torrent.name + '" в клиенте ' + $torrent.client_key + ' размером ' + ( to_kmg $torrent.size 2 ) + ' и хэшем ' + $torrent.hash )
        $prev_state = ( Get-ClientTorrents $settings.clients[$torrent.client_key] -mess_sender 'Rehasher' -hash $torrent.hash ).state
        if ( $prev_state -eq $settings.clients[$torrent.client_key].stopped_state ) { Write-Log 'Раздача уже остановлена, так и запишем' } else { Write-Log 'Раздача запущена, предварительно остановим' }
        if ( $prev_state -ne $settings.clients[$torrent.client_key].stopped_state ) {
            Write-Log 'Останавливаем раздачу'
            Stop-Torrents $torrent.hash $settings.clients[$torrent.client_key]
        }
    }
    Write-Log 'Отправляем в рехэш'
    Start-Rehash -client $settings.clients[$torrent.client_key] -hash $torrent.hash # -move_up:($already_hashing -gt 0 )
    if ( !$db_data[$torrent.hash] ) {
        Invoke-SqliteQuery -Query "INSERT INTO rehash_dates (hash, rehash_date) VALUES (@hash, @epoch )" -SqlParameters @{ hash = $torrent.hash; epoch = ( Get-Date -UFormat %s ) }-SQLiteConnection $conn
    }
    else {
        Invoke-SqliteQuery -Query "UPDATE rehash_dates SET rehash_date = @epoch WHERE hash = @hash" -SqlParameters @{ hash = $torrent.hash; epoch = ( Get-Date -UFormat %s ) } -SQLiteConnection $conn
    }
    $sum_cnt += 1
    $sum_size += $torrent.size
    if ( $wait_finish -eq 'Y' ) {
        Start-Sleep -Seconds $check_state_delay
        Write-Log 'Подождём окончания рехэша'
        while ( ( Get-ClientTorrents -client $settings.clients[$torrent.client_key] -hash $torrent.hash -mess_sender 'Rehasher' -verbos:($verbos.IsPresent) ).state -like 'checking*' ) {
            if ( $verbos.IsPresent ) { Write-Log "Раздача пока рехэшится, ждём $check_state_delay секунд" }
            Start-Sleep -Seconds $check_state_delay
        }
        if ( $verbos.IsPresent ) { Write-Log 'Смотрим, на сколько процентов рехэш был успешен. Для этого опять-таки ' }
        $tor_info = Get-ClientTorrents -client $settings.clients[$torrent.client_key] -hash $torrent.hash -verbos:($verbos.IsPresent) -mess_sender 'Rehasher' -break
        $percentage = $tor_info[0].progress
        if ( $percentage -lt 1 ) {
            Write-Log ( 'Раздача "' + $torrent.name + '" битая! Полнота: ' + $percentage )
            if ( $start_errored -eq 'Y' ) {
                Start-Torrents $torrent.hash $settings.clients[$torrent.client_key]
            }
            $torrent | Add-Member -NotePropertyName topic_id -NotePropertyValue $null
            $torrents_list = @( $torrent )
            Get-TopicIDs -client $settings.clients[$torrent.client_key] -torrent_list $torrents_list
            $message = 'Битая раздача <b>' + $torrent.name + "`n</b>в клиенте <b>" + $settings.clients[$torrent.client_key].name + '</b> http://' + $settings.clients[$torrent.client_key].IP + ':' + $settings.clients[$torrent.client_key].port + `
                "`nполнота: " + [math]::Round($percentage * 100) + "%`nссылка: https://rutracker.org/forum/viewtopic.php?t=" + $torrent.topic_id 
            Send-TGMessage -message $message -token $tg_token -chat_id $tg_chat -mess_sender 'Rehasher'
            Set-Comment $settings.clients[$torrent.client_key] $torrent 'Битая'
            Set-MaxTorrentPriority -client $settings.clients[$torrent.client_key] -hash $torrent.hash
        }
        else {
            Write-Log ( 'Раздача "' + $torrent.name + '" в порядке' ) -Green
            if ( $prev_state -ne $settings.clients[$torrent.client_key].stopped_state ) { 
                Write-Log 'Запускаем раздачу обратно'
                Start-Torrents $torrent.hash $settings.clients[$torrent.client_key]
            }
            if ( $tor_info.tags -like '*Битая*' ) { 
                Remove-Comment $settings.clients[$torrent.client_key] $torrent 'Битая'
            }
        }
    }
}
if ( $too_big ) { Write-Log 'Достигнут целевой объём раздач' }

Write-Log 'Прогон завершён'
Write-Log ( "Отправлено в рехэш: $sum_cnt раздач объёмом " + ( $sum_size -eq 0 ? 0 : ( to_kmg $sum_size 1 ) ) )
Write-Log ( 'Осталось: ' + ( $was_count - $sum_cnt ) + ' раздач объёмом ' + ( ( $was_sum_size - $sum_size ) -eq 0 ? 0 : ( to_kmg( $was_sum_size - $sum_size ) 1 ) ) )

if ( $report_rehasher -eq 'Y' ) {
    $closest_span = Get-SpokenInterval (Get-Date) $closest_datetime 
    if ( $sum_cnt -gt 0 ) {
        $message = "Прогон завершён`nОтправлено в рехэш: $sum_cnt раздач объёмом " + ( $sum_size -eq 0 ? 0 : ( to_kmg $sum_size 1 ) ) + "`nОсталось: " + ( $was_count - $sum_cnt ) + ' раздач объёмом ' + ( ( $was_sum_size - $sum_size ) -eq 0 ? 0 : ( to_kmg( $was_sum_size - $sum_size ) 1 ) )
        if ( $rehash_prophet -eq 'Y' -and $sum_cnt -eq $was_count -and $closest_datetime -gt ( Get-Date ) ) {
            $message = $message + "`nБлижайший рехэш через $closest_span"
        }
        Send-TGMessage -message $message -mess_sender 'Rehasher' -chat_id $tg_chat -token $tg_token
    }
    else {
        Send-TGMessage -message ( ( $mention_script_tg -eq 'Y' ? 'Я' :'Rehasher' ) + ' отработал, ничего делать не пришлось.' + ( $rehash_prophet -eq 'Y' ? "`nБлижайший рехэш через $closest_span" : '' ) ) -token $tg_token -chat_id $tg_chat -mess_sender 'Rehasher'
    }
}

Write-Log 'Удаляем из БД рехэшей раздачи, которых нет в клиентах'
$ct_ht = @{}
$clients_torrents.hash | ForEach-Object { $ct_ht[$_] = 1 }
$db_data.Keys | Where-Object { !$ct_ht[$_] } | ForEach-Object { Invoke-SqliteQuery -Query "DELETE FROM rehash_dates WHERE hash = '$_'" -SQLiteConnection $conn }
$conn.Close()
