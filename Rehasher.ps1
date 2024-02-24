Write-Output 'Подгружаем настройки'
$separator = $separator = $( $PSVersionTable.OS.ToLower().contains('windows') ? '\' : '/' )
try { . ( $PSScriptRoot + $separator + '_settings.ps1' ) } catch {}

$str = 'Подгружаем функции' 
if ( $use_timestamp -ne 'Y' ) { Write-Output $str } else { Write-Output ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) }
. ( $PSScriptRoot + $separator + '_functions.ps1' )

Test-Version ( $PSCommandPath | Split-Path -Leaf )
Test-Version ( '_functions.ps1' )
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

$min_repeat_epoch = ( Get-Date -UFormat %s ).ToInt32($null) - ( $frequency * 24 * 60 * 60 ) # количество секунд между повторными рехэшами одной раздачи
$min_freshes_epoch = ( Get-Date -UFormat %s ).ToInt32($null) - ( $freshes_delay * 24 * 60 * 60 ) # количество секунд между повторными рехэшами одной раздачи

Write-Log 'Читаем настройки Web-TLO'

$ini_path = $tlo_path + $separator + 'data' + $separator + 'config.ini'
$ini_data = Get-IniContent $ini_path

if ( $debug -ne 1 -or $env:TERM_PROGRAM -ne 'vscode' -or $null -eq $clients_torrents -or $clients_torrents.count -eq 0 ) {
    $clients = Get-Clients
    $clients_torrents = Get-ClientsTorrents $clients -noIDs -completed
}

Write-Log 'Исключаем уже хэшируемые и стояшие в очереди на рехэш'
$before = $clients_torrents.count
$clients_torrents = $clients_torrents | Where-Object { $_.state -ne 'checkingUP' }
Write-Log ( 'Исключено раздач: ' + ( $before - $clients_torrents.count ) )

if ( $rehash_freshes -ne 'Y') {
    $before = $clients_torrents.count
    Write-Log 'Исключаем свежескачанные раздачи'
    $clients_torrents = $clients_torrents | Where-Object { $_.completion_on -le $min_freshes_epoch }
    Write-Log ( 'Исключено раздач: ' + ( $before - $clients_torrents.count ) )
}

$db_data = @{}
$database_path = $PSScriptRoot + $separator + 'rehashes.db'
Write-Log 'Подключаемся к БД'
$conn = Open-Database $database_path
Invoke-SqliteQuery -Query 'CREATE TABLE IF NOT EXISTS rehash_dates (hash VARCHAR PRIMARY KEY NOT NULL, rehash_date INT)' -SQLiteConnection $conn
Write-Log 'Выгружаем из БД даты рехэшей'
Invoke-SqliteQuery -Query 'SELECT * FROM rehash_dates' -SQLiteConnection $conn | ForEach-Object { $db_data[$_.hash] = $_.rehash_date } 

$full_data_sorted = [System.Collections.ArrayList]::new()
Write-Log 'Ищем раздачи из клиентов в БД рехэшей'
$clients_torrents | ForEach-Object {
    if ( !$_.infohash_v1 -or $nul -eq $_.infohash_v1 -or $_.infohash_v1 -eq '' ) { $_.infohash_v1 = $_.hash }
    if ($_.infohash_v1 -and ( $nul -ne $_.infohash_v1 ) -and ( $_.infohash_v1 -ne '' ) ) {
        $full_data_sorted.Add( [PSCustomObject]@{ hash = $_.infohash_v1; rehash_date = $( $null -ne $db_data[$_.infohash_v1] -and $db_data[$_.infohash_v1] -gt 0 ? $db_data[$_.infohash_v1] : 0 ); client_key = $_.client_key; size = $_.size; name = $_.name } ) | Out-Null
    }
}

Write-Log 'Исключаем раздачи, которые рано рехэшить'
$before = $full_data_sorted.count
$full_data_sorted = $full_data_sorted | Where-Object { $_.rehash_date -lt $min_repeat_epoch }
Write-Log ( 'Исключено раздач: ' + ( $before - $full_data_sorted.count ) )

$was_count = $full_data_sorted.count
$was_sum_size = ( $full_data_sorted | Measure-Object -Property size -Sum ).Sum

# if ( $max_rehash_qty -and $mix_clients -ne 'Y') {
#     Write-Log "Отбрасываем все раздачи кроме первых $max_rehash_qty"
#     $full_data_sorted = $full_data_sorted | Select-Object -First $max_rehash_qty
# }

Write-Log 'Сортируем всё по дате рехэша и размеру'
$full_data_sorted = $full_data_sorted | Sort-Object -Property size -Descending | Sort-Object -Property rehash_date -Stable

if ( $mix_clients -eq 'Y') {
    Write-Log 'Тщательнейшим образом перемешиваем клиентов'
    $per_client = @{}
    $full_resorted = [System.Collections.ArrayList]::new()
    foreach ( $i in  0..( $full_data_sorted | Measure-Object -Property client_key -Maximum ).maximum ) { $per_client[$i] = $full_data_sorted | Where-Object { $_.client_key -eq $i } }
    
    $done = 0
    $max_qty = ( $per_client.GetEnumerator() | ForEach-Object { $_.Value.count } | Measure-Object -Maximum ).Maximum
    for ( $j = 0; $j -lt $max_qty ; $j++) {
        foreach ( $k in 0..$i ) {
            try {
                $full_resorted += $per_client[$k][$j]
                $done ++ 
            }
            catch {}
            if ( $done -ge $max_rehash_qty ) { break }
        }
        if ( $done -ge $max_rehash_qty ) { break }
    }
    $full_data_sorted = $full_resorted
    Remove-Variable -Name full_resorted    
}

$sum_cnt = 0
$sum_size = 0
foreach ( $torrent in $full_data_sorted ) {
    if ( ( Get-Process | Where-Object { $_.ProcessName -eq 'pwsh' } | Where-Object { $_.CommandLine -like '*Adder.ps1' -or $_.CommandLine -like '*Controller.ps1' } ).count -gt 0 ) {
        Write-Log 'Выполняется Adder или Controller, подождём...' -Red
        while ( ( Get-Process | Where-Object { $_.ProcessName -eq 'pwsh' } | Where-Object { $_.CommandLine -like '*Adder.ps1' -or $_.CommandLine -like '*Controller.ps1' } ).count -gt 0 ) {
            Start-Sleep -Seconds 10
        }
    }    
    if ( $wait_finish -eq 'Y' ) {
        Write-Log ( 'Будем рехэшить раздачу "' + $torrent.name + '" в клиенте ' + $clients[$torrent.client_key].Name + ' размером ' + ( to_kmg $torrent.size 1 ))
        $prev_state = ( Get-ClientTorrents $clients[$torrent.client_key] '' $false $torrent.hash $null $false ).state
        if ( $prev_state -eq 'pausedUP') { Write-Log 'Раздача уже остановлена, так и запишем' } else { Write-Log 'Раздача запущена, предварительно остановим' }
        if ( $prev_state -ne 'pausedUP' ) {
            Write-Log ( 'Останавливаем ' + $torrent.name + ' в клиенте ' + $clients[$torrent.client_key].Name )
            Stop-Torrents $torrent.hash $clients[$torrent.client_key]
        }
    }
    Write-Log ( 'Отправляем в рехэш ' + $torrent.name + ' в клиенте ' + $clients[$torrent.client_key].Name )
    Start-Rehash $clients[$torrent.client_key] $torrent.hash
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
        while ( ( Get-ClientTorrents -client $clients[$torrent.client_key] -hash $torrent.hash ).state -like 'checking*' ) {
            Start-Sleep -Seconds $check_state_delay
        }
        if ( ( Get-ClientTorrents -client $clients[$torrent.client_key] -hash $torrent.hash ).progress -lt 1 ) {
            Write-Log ( 'Раздача ' + $torrent.name + ' битая! Полнота: ' + ( Get-ClientTorrents -client $clients[$torrent.client_key] -hash $torrent.hash ).progress )
            if ( $start_errored -eq 'Y' ) {
                Start-Torrents $torrent.hash $clients[$torrent.client_key]
            }
            Set-Comment $clients[$torrent.client_key] $torrent 'Битая'
            $message = 'Битая раздача ' + $torrent.name + ' в клиенте http://' + $clients[$torrent.client_key].IP + ':' + $clients[$torrent.client_key].Port + ' , Полнота: ' + ( Get-ClientTorrents -client $clients[$torrent.client_key] -hash $torrent.hash ).progress
            Send-TGMessage $message $tg_token $tg_chat
        }
        else {
            Write-Log ( 'Раздача ' + $torrent.name + ' в порядке' ) -Green
            if ( $prev_state -ne 'pausedUP' ) { 
                Write-Log 'Запускаем раздачу обратно'
                Start-Torrents $torrent.hash $clients[$torrent.client_key]
            }
        }
    }

    if ( $sum_cnt -ge $max_rehash_qty ) {
        Write-Log 'Достигнуто целевое количество раздач'
        break
    }
    elseif ( $sum_size -ge $max_rehash_size_bytes ) {
        Write-Log 'Достигнут целевой объём раздач'
        break
    }
}

Write-Log 'Прогон завершён'
Write-Log ( "Отправлено в рехэш: $sum_cnt раздач объёмом " + ( to_kmg $sum_size.size 1 ) ) 
Write-Log ( 'Осталось: ' + ( $was_count - $sum_cnt ) + ' раздач объёмом ' + ( to_kmg ( $was_sum_size - $sum_size ) 1 ) )

$conn.Close()
# Remove-Item -Path ( $PSScriptRoot + $separator + 'rehasher.lck') | Out-Null