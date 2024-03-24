function Write-Log ( $str, [switch]$Red, [switch]$Green, [switch]$NoNewLine, [switch]$skip_timestamp ) {
    if ( $use_timestamp -ne 'Y' -or $skip_timestamp ) {
        if ( $Red ) { Write-Host $str -ForegroundColor Red -NoNewline:$NoNewLine }
        elseif ( $Green ) { Write-Host $str -ForegroundColor Green -NoNewline:$NoNewLine }
        else { Write-Host $str -NoNewline:$NoNewLine }
    }
    else {
        if ( $Red ) { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) -ForegroundColor Red -NoNewline:$NoNewLine }
        elseif ( $Green ) { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) -ForegroundColor Green -NoNewline:$NoNewLine }
        else { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) -NoNewline:$NoNewLine } 
    }
}
 
function Test-PSVersion {
    Write-Log 'Проверяем версию Powershell...'
    if ( $PSVersionTable.PSVersion -lt [version]'7.1.0.0') {
        Write-Log 'У вас слишком древний Powershell, обновитесь с https://github.com/PowerShell/PowerShell#get-powershell ' -Red
        Pause
        Exit
    }
    else {
        Write-Log 'Версия достаточно свежая, продолжаем' -Green
    }
}

function Get-Separator {
    if ( $PSVersionTable.OS.ToLower().contains('windows')) { $separator = '\' } else { $separator = '/' }
    return $separator
}

function Test-Version ( $name ) {
    try {
        $old_hash = ( Get-FileHash -Path ( Join-Path $PSScriptRoot $name ) ).Hash
        $new_file_path = ( Join-Path $PSScriptRoot $name.replace( '.ps1', '.new' ) )
        Invoke-WebRequest -Uri ( 'https://raw.githubusercontent.com/Another-1/RT_Pack/main/' + $name ) -OutFile $new_file_path | Out-Null
        if ( Test-Path $new_file_path ) {
            $new_hash = ( Get-FileHash -Path $new_file_path ).Hash
            if ( $old_hash -ne $new_hash ) {
                if ( $auto_update -eq 'N' ) {
                    $text = "$name обновился! Рекомендуется скачать новую версию."
                    Write-Log $text -Red
                    if ( $alert_oldies -eq 'Y' -and $tg_token -ne '' ) { Send-TGMessage $text $tg_token $tg_chat }
                }
                if ( $auto_update -eq 'Y' -and $debug -ne 1 ) {
                    Write-Log 'Я обновился, запускаю нового себя'
                    Copy-Item -Path $new_file_path -Destination ( Join-Path $PSScriptRoot $name ) -Force
                    Unblock-File -Path ( Join-Path $PSScriptRoot $name )
                    if ( $name -ne '_functions.ps1' ) {
                        Start-Process pwsh ( Join-Path $PSScriptRoot $name )
                        exit
                    }
                    else { 
                        Write-Log 'Обновляем _functions'
                        . ( Join-Path $PSScriptRoot $name )
                    }
                }
            }
            Remove-Item $new_file_path -Force -ErrorAction SilentlyContinue
        } 
    }
    catch {}
}

function Test-Module ( $module, $description ) {
    Write-Log "Проверяем наличие модуля $module $description"
    if ( -not ( [bool](Get-InstalledModule -Name $module -ErrorAction SilentlyContinue) ) ) {
        Write-Log "Не установлен модуль $module $description, ставим" -Red
        Install-Module -Name $module -Scope CurrentUser -Force
        Import-Module $module
    }
    else {
        Write-Log "Модуль $module обнаружен" -Green
        Import-Module $module
    }
}

function Test-Setting ( $setting, [switch]$required, $default ) {
    $settings = @{
        'tg_token'              = @{ prompt = 'Токен бота Telegram, если нужна отправка событий в Telegram. Если не нужно, оставить пустым'; default = ''; type = 'string' }
        'tg_chat'               = @{ prompt = 'Номер чата для отправки сообщений Telegram'; default = ''; type = 'string' }
        'alert_oldies'          = @{ prompt = 'Уведомлять о новых версиях скриптов в Telegram?'; default = 'Y'; type = 'YN' }
        'use_timestamp'         = @{ prompt = 'Выводить дату-время в окне лога Adder?'; default = 'N'; type = 'YN' }
        'tlo_path'              = @{ prompt = 'Путь к папке Web-TLO'; default = 'C:\OpenServer\domains\webtlo.local'; type = 'string' }
        'get_blacklist'         = @{ prompt = 'Скачивать раздачи из чёрного списка Web-TLO?'; default = 'N'; type = 'YN' }
        'max_seeds'             = @{ prompt = 'Максимальное кол-во сидов для скачивания раздачи'; default = -1; type = 'number' }
        'min_days'              = @{ prompt = 'Минимальное количество дней с релиза (только для новых раздач)'; default = -1; type = 'number' }
        'get_hidden'            = @{ prompt = 'Скачивать раздачи со скрытых из общего списка разделов Web-TLO? (Y/N)'; default = 'N'; type = 'YN' }
        'get_shown'             = @{ prompt = 'Скачивать раздачи с НЕскрытых из общего списка разделов Web-TLO? (Y/N)'; default = 'Y'; type = 'YN' }
        'get_lows'              = @{ prompt = 'Скачивать раздачи c низким приоритетом? (Y/N)'; default = 'N'; type = 'YN' }
        'get_mids'              = @{ prompt = 'Скачивать раздачи cо средним приоритетом? (Y/N)'; default = 'Y'; type = 'YN' }
        'get_highs'             = @{ prompt = 'Скачивать раздачи c высоким приоритетом? (Y/N)'; default = 'Y'; type = 'YN' }
        'get_news'              = @{ prompt = 'Скачивать новые раздачи? (Y/N)'; default = 'Y'; type = 'YN' }
        'control'               = @{ prompt = 'Запускать встроенную регулировку по завершению? (Y/N)'; default = 'Y'; type = 'YN' }
        'update_stats'          = @{ prompt = 'Запускать обновление БД TLO если добавлены или обновлены раздачи? (Y/N)'; default = 'Y'; type = 'YN' }
        'update_obsolete'       = @{ prompt = 'Запускать обновление БД TLO даже если найдены только неактуальные раздачи? (Y/N)'; default = 'Y'; type = 'YN' }
        'send_reports'          = @{ prompt = 'Вызывать отправку отчётов если что-то изменилось? (Y/N)'; default = 'Y'; type = 'YN' }
        'php_path'              = @{ prompt = 'Путь к интерпретатору PHP'; default = ''; type = 'string' }
        'report_stalled'        = @{ prompt = 'Отправлять боту призыв о помощи по некачашкам более месяца? (Y/N)'; default = 'N'; type = 'YN' }
        'report_obsolete'       = @{ prompt = 'Сообщать в Telegram о неактуальных раздачах? (Y/N)'; default = 'Y'; type = 'YN' }
        'max_rehash_qty'        = @{ prompt = 'Максимальное количество отправляемых в рехэш раздач за один прогон?'; default = 10; type = 'number' }
        'max_rehash_size_bytes' = @{ prompt = 'максимальный объём отправляемых в рехэш раздач за один прогон в байтах?'; default = 10 * 1024 * 1024 * 1024; type = 'number' }
        'frequency'             = @{ prompt = 'Минимальное кол-во дней между рехэшами одной раздачи в днях?'; default = 365; type = 'number' }
        'rehash_freshes'        = @{ prompt = 'Игнорировать время завершения скачивания раздачи?'; default = 'Y'; type = 'YN' }
        'freshes_delay'         = @{ prompt = 'Минимальное кол-во дней c окончания скачивания раздачи до рехэша?'; default = 10; type = 'number' }
        'wait_finish'           = @{ prompt = 'Ожидать ли окончания рехэша раздач с отчётом в телеграм и в журнал о найденных битых и с простановкой им тега "Битая"?'; default = 'Y'; type = 'YN' }
        'mix_clients'           = @{ prompt = 'Перемешивать раздачи перед отправкой в рехэш для равномерной загрузки клиентов?'; default = 'N'; type = 'YN' }
        'check_state_delay'     = @{ prompt = 'Задержка в секундах перед опросом состояния после отправки в рехэш. Должнать быть больше или равна интервалу обновления интерфейса кубита.'; default = 5; type = 'number' }
        'start_errored'         = @{ prompt = 'Запускать на докачку раздачи с ошибкой рехэша?'; default = 'Y'; type = 'YN' }
        'ipfilter_path'         = @{ prompt = 'Имя файла блокировок? В клиентах должно быть указано аналогично'; default = 'C:\ipfiler.dat'; type = 'string' }
        'hours_to_stop'         = @{ prompt = 'Сколько минимум часов держать раздачу запущенной?'; default = 3; type = 'number' }
        'old_starts_per_run'    = @{ prompt = 'Количество запускаемых за раз давно стоящих раздач? '; default = 100; type = 'number' }
        'report_nowork'         = @{ prompt = 'Сообщать в Telegam если ничего не пришлось делать?'; default = 'Y'; type = 'YN' }
        'auto_update'           = @{ prompt = 'Автоматически обновлять версии скриптов?'; default = 'N'; type = 'YN' }
        'stalled_pwd'           = @{ prompt = 'Пароль для отправки некачашек (см. у бота в /about_me)'; type = 'string' }
    }
    $changed = $false
    $current_var = ( Get-Variable -Name $setting -ErrorAction SilentlyContinue )
    if ( $current_var ) { $current = $current_var.Value }
    else {
        if ( $default -and $default -ne '' ) { $settings[$setting].default = $default }
        do {
            $current = Read-Host -Prompt ( $settings[$setting].prompt + $( ( $settings[$setting].default -and $settings[$setting].default -ne '' ) ? ' [' + $settings[$setting].default + ']' : '' ) )
            if ( $settings[$setting].type -eq 'YN' ) {
                if ( $current -ne '' ) { $current = $current.ToUpper() }
            }
            if ( $current -eq '' -and $nul -ne $settings[$setting].default ) {
                $current = $settings[$setting].default
            }
            if ( $setting -eq 'tlo_path') {
                $ini_path = Join-Path $current 'data' 'config.ini'
                If ( -not ( Test-Path $ini_path ) ) {
                    Write-Log ( 'Не нахожу файла ' + ( $ini_path ) + ', проверьте ввод' ) -ForegroundColor -Red
                    $current = ''
                }
                else { 
                    $changed = $true
                }
            }
            elseif ( $setting -eq 'php_path' ) {
                If ( -not ( Test-Path $current ) ) {
                    Write-Log ( 'Не нахожу такого файла , проверьте ввод' ) -ForegroundColor -Red
                    $current = ''
                }
                else { 
                    $changed = $true
                }
            }
            else {
                $changed = $true
            }
        } while ( ( $current -eq '' -and $required ) -or ( $settings[$setting].type -eq 'YN' -and $current -notmatch '[YN]' ) )

        if ( $changed ) {
            if ( $settings[$setting].type -eq ( 'number' ) ) {
                $current = $current.ToInt64( $null )
            }
            Set-Variable -Name $setting -Value $current
            Add-Content -Path ( Join-Path $PSScriptRoot '_settings.ps1' ) `
                -Value ( '$' + $setting + ' = ' + $( ( $settings[$setting].type -in ( 'YN', 'string' ) ) ? "'" : '') + $current + $( ( $settings[$setting].type -in ( 'YN', 'string' ) ) ? "'" : '') + '   # ' + $settings[$setting].prompt )
        }
    }
    return $current
}

function Test-ForumWorkingHours ( [switch]$verbose ) {
    $MoscowTZ = [System.TimeZoneInfo]::FindSystemTimeZoneById("Russian Standard Time")
    $MoscowTime = [System.TimeZoneInfo]::ConvertTimeFromUtc((Get-Date).ToUniversalTime(), $MoscowTZ)
    if ($verbose) {
        Write-Log ( 'Московское время ' + ( Get-Date($MoscowTime) -UFormat %H ) + ' ч ' + ( Get-Date($MoscowTime) -UFormat %M ) + ' мин' )
        Write-Log 'Проверяем, что в Москве не 4 часа ночи (профилактика)'
    }
    if ( ( Get-Date($MoscowTime) -UFormat %H ) -eq '04' ) {
        Write-Log 'Профилактические работы на сервере' -ForegroundColor -Red
        exit
    }
}

Function Set-ForumDetails ( $forum ) {
    $forum = @{}
    If ( $ini_data.proxy.activate_forum -eq '1' -or $ini_data.proxy.activate_api -eq '1' ) {
        Write-Host ( 'Используем ' + $ini_data.proxy.type.Replace('socks5h', 'socks5') + ' прокси ' + $ini_data.proxy.hostname + ':' + $ini_data.proxy.port )
        $forum.ProxyIP = $ini_data.proxy.hostname
        $forum.ProxyPort = $ini_data.proxy.port
        $forum.ProxyURL = 'socks5://' + $ini_data.proxy.hostname + ':' + $ini_data.proxy.port
        $forum.ProxyLogin = $ini_data.proxy.login
        $forum.ProxyPassword = $ini_data.proxy.password
    }
    $forum.UseApiProxy = $ini_data.proxy.activate_api
    $forum.UseProxy = $ini_data.proxy.activate_forum
    if ( $forum.UseProxy -eq '1' -and $ini_data.proxy.type -notlike 'socks*' ) {
        Write-Log 'Выберите прокси типа SOCKS5 или SOCKS5H в настройках TLO' -Red
        Exit
    }
    $forum.Login = $ini_data.'torrent-tracker'.login
    $forum.Password = $ini_data.'torrent-tracker'.password
    $forum.url = $ini_data.'torrent-tracker'.forum_url
    $forum.UserID = $ini_data.'torrent-tracker'.user_id

    if ( $forum.ProxyURL -and $forum.ProxyPassword -and $forum.ProxyPassword -ne '') {
        $proxyPass = ConvertTo-SecureString $ini_data.proxy.password -AsPlainText -Force
        $forum.proxyCred = New-Object System.Management.Automation.PSCredential -ArgumentList $forum.ProxyLogin, $proxyPass
    }
    
    return $forum
}

function Open-Database( $db_path, [switch]$verbose ) {
    if ( $verbose ) { Write-Log ( 'Путь к базе данных: ' + $db_path ) }
    $conn = New-SQLiteConnection -DataSource $db_path
    return $conn
}

function Open-TLODatabase( [switch]$verbose ) {
    $database_path = Join-Path $tlo_path 'data' 'webtlo.db'
    $conn = Open-Database $database_path -verbose:$verbose.IsPresent
    return $conn
}

function Get-Blacklist( [switch]$verbose ) {
    Write-Log 'Запрашиваем чёрный список из БД Web-TLO'
    $blacklist = @{}
    if ( !$conn -or $conn.ConnectionString -notlike '*webtlo.db' ) { $conn = Open-TLODatabase -verbose:$verbose.IsPresent }
    $query = 'SELECT info_hash FROM TopicsExcluded'
    Invoke-SqliteQuery -Query $query -SQLiteConnection $conn -ErrorAction SilentlyContinue | ForEach-Object { $blacklist[$_.info_hash] = 1 }
    $conn.Close()
    return $blacklist
}
function Get-OldBlacklist( [switch]$verbose ) {
    Write-Log 'Запрашиваем старый чёрный список из БД Web-TLO'
    $oldblacklist = @{}
    if (!$conn) { $conn = Open-TLODatabase $verbose.IsPresent }
    $query = 'SELECT id FROM Blacklist'
    Invoke-SqliteQuery -Query $query -SQLiteConnection $conn -ErrorAction SilentlyContinue | ForEach-Object { $oldblacklist[$_.id.ToString()] = 1 }
    $conn.Close()
    return $oldblacklist
}

function Get-SectionTorrents ( $forum, $section ) {
    $i = 1
    Write-Log ('Получаем с трекера раздачи раздела ' + $section + '... ' ) -NoNewline
    while ( $true) {
        try {
            if ( [bool]$forum.ProxyURL -and $forum.UseApiProxy -eq 1 ) {
                if ( $forum.proxyCred ) { $tmp_torrents = ( ( Invoke-WebRequest -Uri "https://api.rutracker.cc/v1/static/pvc/f/$section" -Proxy $forum.ProxyURL -ProxyCredential $forum.proxyCred ).Content | ConvertFrom-Json -AsHashtable ).result }
                else { $tmp_torrents = ( ( Invoke-WebRequest -Uri "https://api.rutracker.cc/v1/static/pvc/f/$section" -Proxy $forum.ProxyURL ).Content | ConvertFrom-Json -AsHashtable ).result }
            }
            else { $tmp_torrents = ( ( Invoke-WebRequest -Uri "https://api.rutracker.cc/v1/static/pvc/f/$section" ).Content | ConvertFrom-Json -AsHashtable ).result }
            break
        }
        catch { Start-Sleep -Seconds 10; $i++; Write-Host "Попытка номер $i" -ForegroundColor Cyan }
    }
    Write-Log ( 'Получено раздач: ' + $tmp_torrents.count ) -skip_timestamp
    if ( !$tmp_torrents ) {
        Write-Host 'Не получилось' -ForegroundColor Red
        exit 
    }
    return $tmp_torrents
}

function Get-TrackerTorrents ( $sections ) {
    Write-Log 'Запрашиваем у трекера раздачи из хранимых разделов'
    $i = 1
    do {
        try {
            if ($i -gt 1 ) { Write-Log "Попытка номер $i" }
            if ( [bool]$forum.ProxyURL -and $forum.UseApiProxy -eq 1 ) {
                if ( $forum.proxyCred ) { $titles = (( Invoke-WebRequest -Uri 'https://api.rutracker.cc/v1/get_tor_status_titles' -Proxy $forum.ProxyURL -ProxyCredential $forum.proxyCred ).content | ConvertFrom-Json -AsHashtable ).result }
                else { $titles = (( Invoke-WebRequest -Uri 'https://api.rutracker.cc/v1/get_tor_status_titles' -Proxy $forum.ProxyURL ).content | ConvertFrom-Json -AsHashtable ).result }
            }
            else { $titles = (( Invoke-WebRequest -Uri 'https://api.rutracker.cc/v1/get_tor_status_titles' ).content | ConvertFrom-Json -AsHashtable ).result }
            if ( $titles ) { break }
        }
        catch { Start-Sleep -Seconds 10; $i++ }
    }
    until ( $i -ge 5 )
    if (!$titles) {
        Write-Log 'Нет связис API трекера, выходим' -Red
        exit
    }
    $ok_states = $titles.keys | Where-Object { $titles[$_] -in ( 'не проверено', 'проверено', 'недооформлено', 'сомнительно', 'временная') }
    $tracker_torrents = @{}
    foreach ( $section in $sections ) {
        $section_torrents = Get-SectionTorrents $forum $section
        $section_torrents.Keys | Where-Object { $section_torrents[$_][0] -in $ok_states } | ForEach-Object {
            $tracker_torrents[$section_torrents[$_][7]] = @{
                id             = $_
                section        = $section
                status         = $section_torrents[$_][0]
                name           = $null
                reg_time       = $section_torrents[$_][2]
                size           = $section_torrents[$_][3]
                priority       = $section_torrents[$_][4]
                seeders        = $section_torrents[$_][1]
                hidden_section = $section_details[$section].hide_topics
                releaser       = $section_torrents[$_][8].ToInt32($null)
            }
        }
    }
    return $tracker_torrents
}

function Get-Clients ( [switch]$LocalOnly ) {
    $clients = @{}
    Write-Log 'Получаем из TLO данные о клиентах'
    $client_count = $ini_data['other'].qt.ToInt16($null)
    $i = 1
    $ini_data.keys | Where-Object { $_ -match '^torrent-client' -and $ini_data[$_].client -eq 'qbittorrent' } | ForEach-Object {
        if ( ( $_ | Select-String ( '\d+$' ) ).matches.value.ToInt16($null) -le $client_count ) {
            $clients[$ini_data[$_].id] = @{ Login = $ini_data[$_].login; Password = $ini_data[$_].password; Name = $ini_data[$_].comment; IP = $ini_data[$_].hostname; Port = $ini_data[$_].port; }
            $i++
        }
    } 
    if ( $LocalOnly ) {
        Write-Log 'Получаем IP локального компа чтобы не пытаться архивировать то, чего на нём нет'
        $localIPs = ( Get-NetIPAddress ).IPAddress
        $local_clients = @{}
        $clients.keys | ForEach-Object {
            if ( $clients[$_].IP -in $localIPs ) { $local_clients[$_] = $clients[$_] }
        }
        $clients = $local_clients
    }
    Write-Log ( 'Актуальных клиентов к обработке: ' + $clients.count + ': ' + ( ( $clients.Keys | Sort-Object | ForEach-Object { $clients[$_].Name } ) -join ', ' ) )
    return $clients
}

function Initialize-Client ($client, [switch]$verbose, [switch]$force ) {
    if ( !$client.sid -or $force ) {
        $logindata = @{ username = $client.login; password = $client.password }
        $loginheader = @{ Referer = 'http://' + $client.IP + ':' + $client.Port }
        try {
            if ( $verbose ) { Write-Log ( 'Авторизуемся в клиенте ' + $client.Name ) }
            $url = $client.IP + ':' + $client.Port + '/api/v2/auth/login'
            $result = Invoke-WebRequest -Method POST -Uri $url -Headers $loginheader -Body $logindata -SessionVariable sid
            if ( $result.StatusCode -ne 200 ) {
                Write-Log 'You are banned.' -Red
                exit
            }
            if ( $result.Content.ToUpper() -ne 'OK.') {
                Write-Log ( 'Клиент вернул ошибку авторизации: ' + $result.Content ) -Red
                exit
            }
            Write-Log 'Успешная авторизация'
            $client.sid = $sid
        }
        catch {
            Write-Log ( '[client] Не удалось авторизоваться в клиенте, прерываем. Ошибка: {0}.' -f $Error[0] ) -Red
            if ( $tg_token -ne '' ) {
                Send-TGMessage ( 'Нет связи с клиентом ' + $client.Name + '. Процесс остановлен.' ) $tg_token $tg_chat
            }
            Exit
        }
    }
}

function  Get-ClientTorrents ( $client, $disk = '', [switch]$completed, $hash, $client_key, [switch]$verbose ) {
    $Params = @{}
    if ( $completed ) {
        $Params.filter = 'completed'
    }
    if ( $nul -ne $hash ) {
        $Params.hashes = $hash
        if ( $verbose -eq $true ) { Write-Log ( 'Получаем инфо о раздаче из клиента ' + $client.Name ) }
    }
    elseif ( $verbose -eq $true ) { Write-Log ( 'Получаем список раздач от клиента ' + $client.Name ) }
    if ( $null -ne $disk -and $disk -ne '') { $dsk = $disk + ':\\' } else { $dsk = '' }
    $i = 0
    while ( $true ) {
        try {
            $json_content = ( Invoke-WebRequest -Uri ( $client.ip + ':' + $client.Port + '/api/v2/torrents/info' ) -WebSession $client.sid -Body $params -TimeoutSec 120 ).Content
            $torrents_list = $json_content | ConvertFrom-Json | `
                Select-Object name, hash, save_path, content_path, category, state, uploaded, @{ N = 'topic_id'; E = { $nul } }, @{ N = 'client_key'; E = { $client_key } }, infohash_v1, size, completion_on, progress, tracker, added_on | `
                Where-Object { $_.save_path -match ('^' + $dsk ) }
        }
        catch {
            Initialize-Client $client -force -verbose $verbose
            $i++
        }
        if ( $json_content -or $i -gt 3 ) { break }
    }
    if ( !$json_content ) {
        if ( $tg_token -ne '' ) { 
            Send-TGMessage ( 'Не удалось получить список раздач от клиента ' + $client.Name. + ', Выполнение прервано.' ) $tg_token $tg_chat
        }
        Write-Log ( 'Не удалось получить список раздач от клиента ' + $client.Name )
    }
    if ( !$torrents_list ) { $torrents_list = @() }
    if ( $verbose ) { Write-Log ( 'Получено ' + $torrents_list.Count + ' раздач от клиента ' + $client.Name ) }
    return $torrents_list
}

function Get-ClientsTorrents ($clients, [switch]$completed, [switch]$noIDs) {
    $clients_torrents = @()
    foreach ($clientkey in $clients.Keys ) {
        $client = $clients[ $clientkey ]
        Initialize-Client( $client ) -verbose
        $client_torrents = Get-ClientTorrents -client $client -client_key $clientkey -verbose -completed:$completed
        if ( $noIDs.IsPresent -eq $false ) { Get-TopicIDs $client $client_torrents }
        $clients_torrents += $client_torrents
    }
    return $clients_torrents
}

function Get-TopicIDs ( $client, $torrent_list ) {
    Write-Log 'Ищем ID раздач по хэшам от клиента в данных от трекера'
    if ( $torrent_list.count -gt 0 ) {
        $torrent_list | ForEach-Object {
            if ( $null -ne $tracker_torrents ) { $_.topic_id = $tracker_torrents[$_.hash.toUpper()].id }
            if ( $null -eq $_.topic_id -or $_.topic_id -eq '' ) {
                # Write-Log ( 'Не нашлось информации по ID для раздачи ' + $_.hash.toUpper() + ', попробуем достать из клиента')
                $Params = @{ hash = $_.hash }
                try {
                    $comment = ( Invoke-WebRequest -Uri ( $client.IP + ':' + $client.Port + '/api/v2/torrents/properties' ) -WebSession $client.sid -Body $params ).Content | ConvertFrom-Json | Select-Object comment -ExpandProperty comment
                    Start-Sleep -Milliseconds 10
                }
                catch { }
                $_.topic_id = ( Select-String "\d*$" -InputObject $comment ).Matches.Value
                # if ( $_.topic_id -ne '' -and $null -ne $_.topic_id ) {
                #     Write-Log 'из клиента добыть ID получилось'
                # }
            }
        }
        $success = ( $torrent_list | Where-Object { $_.topic_id } ).count
        Write-Log ( 'Найдено ' + $success + ' штук ID' ) -Red:( $success -ne $torrent_list.Count )
    }
}

function Add-ClientTorrent ( $Client, $File, $Path, $Category, [switch]$Skip_checking ) {
    $Params = @{
        torrents      = Get-Item $File
        savepath      = $Path
        category      = $Category
        name          = 'torrents'
        root_folder   = 'false'
        paused        = $Paused
        skip_checking = $Skip_checking
    }

    # Добавляем раздачу в клиент.
    $url = $client.ip + ':' + $client.Port + '/api/v2/torrents/add'
    $added_ok = $false
    $abort = $false
    $i = 1
    while ( $added_ok -eq $false -and $abort -eq $false ) {
        if ( $i -gt 10) {
            Write-Log "Не удалось добавить раздачу" -Red
            $abort = $true
        }
        else {
            try {
                if ( $i -gt 1 ) { Write-Log "Попытка № $i" }
                Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
                $added_ok = $true
            }
            catch {
                $i++
                Initialize-Client $client -force
                Start-Sleep -Seconds 1
            }
        }
    }
    Remove-Item $File
}

Function Set-ClientSetting ( $client, $param, $value ) {
    $url = $client.ip + ':' + $client.Port + '/api/v2/app/setPreferences'
    $param = @{ json = ( @{ $param = $value } | ConvertTo-Json -Compress ) }
    Invoke-WebRequest -Uri $url -WebSession $client.sid -Body $param -Method POST | Out-Null

}

function Initialize-Forum () {
    if ( !$forum ) {
        Write-Log 'Не обнаружены данные для подключения к форуму. Проверьте настройки.' -ForegroundColor Red
        Exit
    }
    Write-Log 'Авторизуемся на форуме.'

    $login_url = 'https://' + $forum.url + '/forum/login.php'
    $headers = @{ 'User-Agent' = 'Mozilla/5.0' }
    $payload = @{ 'login_username' = $forum.login; 'login_password' = $forum.password; 'login' = '%E2%F5%EE%E4' }
    $i = 1

    while ($true) {
        try {
            if ( [bool]$forum.ProxyURL ) {
                if ( $forum.proxycred ) {
                    Invoke-WebRequest -Uri $login_url -Method Post -Headers $headers -Body $payload -SessionVariable sid -MaximumRedirection 999 -SkipHttpErrorCheck -Proxy $forum.ProxyURL -ProxyCredential $forum.proxyCred | Out-Null
                }
                else {
                    Invoke-WebRequest -Uri $login_url -Method Post -Headers $headers -Body $payload -SessionVariable sid -MaximumRedirection 999 -SkipHttpErrorCheck -Proxy $forum.ProxyURL | Out-Null
                }
            }
            else { Invoke-WebRequest -Uri $login_url -Method Post -Headers $headers -Body $payload -SessionVariable sid -MaximumRedirection 999 -SkipHttpErrorCheck | Out-Null }
            break
        }
        catch {
            Start-Sleep -Seconds 10; $i++; Write-Log "Попытка номер $i"
            If ( $i -gt 20 ) { break }
        }
    }
    if ( $sid.Cookies.Count -eq 0 ) {
        Write-Log 'Не удалось авторизоваться на форуме.' -Red
        Exit
    }
    $forum.sid = $sid
    Write-Log ( 'Успешно.' )
}

function Get-ForumTorrentFile ( [int]$Id, $save_path = $null) {
    if ( !$forum.sid ) { Initialize-Forum }
    $get_url = 'https://' + $forum.url + '/forum/dl.php?t=' + $Id
    if ( $null -eq $save_path ) { $Path = Join-Path $PSScriptRoot ( $Id.ToString() + '.torrent' ) } else { $path = Join-Path $save_path ( $Id.ToString() + '.torrent' ) }
    $i = 1
    while ( $i -le 30 ) {
        try { 
            if ( [bool]$forum.ProxyURL ) {
                if ( $forum.proxycred ) {
                    Invoke-WebRequest -Uri $get_url -WebSession $forum.sid -OutFile $Path -Proxy $forum.ProxyURL -MaximumRedirection 999 -SkipHttpErrorCheck -ProxyCredential $forum.proxyCred
                }
                else {
                    Invoke-WebRequest -Uri $get_url -WebSession $forum.sid -OutFile $Path -Proxy $forum.ProxyURL -MaximumRedirection 999 -SkipHttpErrorCheck
                }
                break
            }
            else {
                Invoke-WebRequest -Uri $get_url -WebSession $forum.sid -OutFile $Path -MaximumRedirection 999 -SkipHttpErrorCheck
                break
            }
        }
        catch { Start-Sleep -Seconds 10; $i++; Write-Host "Попытка номер $i" -ForegroundColor Cyan }
    }
    if ( $nul -eq $save_path ) { return Get-Item $Path }
}

function to_kmg ($bytes, [int]$precision = 0) {
    foreach ($i in ("Bytes", "KB", "MB", "GB", "TB")) {
        if (($bytes -lt 1024) -or ($i -eq "TB")) {
            $bytes = ($bytes).tostring("F0" + "$precision")
            return $bytes + " $i"
        }
        else {
            $bytes /= 1KB
        }
    }
}

function Get-ForumTorrentInfo ( $id ) {
    $params = @{ 
        by  = 'topic_id'
        val = $id 
    }

    while ( $true ) {
        try {
            if ( [bool]$forum.ProxyURL -and $forum.UseApiProxy -eq 1 ) {
                if ( $forum.proxyCred ) { $torinfo = ( ( Invoke-WebRequest -Uri ( 'https://api.rutracker.cc/v1/get_tor_topic_data' ) -Body $params -Proxy $forum.ProxyURL -ProxyCredential $forum.proxyCred ).Content | ConvertFrom-Json ).result.$id }
                else { $torinfo = ( ( Invoke-WebRequest -Uri ( 'https://api.rutracker.cc/v1/get_tor_topic_data' ) -Body $params -Proxy $forum.ProxyURL ).Content | ConvertFrom-Json ).result.$id }
            }
            else { $torinfo = ( ( Invoke-WebRequest -Uri ( 'https://api.rutracker.cc/v1/get_tor_topic_data' ) -Body $params ).Content | ConvertFrom-Json ).result.$id }
            $name = $torinfo.topic_title
            $size = $torinfo.size
            break
        }
        catch {
            Start-Sleep -Seconds 10; $i++; Write-Host "Попытка номер $i" -ForegroundColor Cyan
            If ( $i -gt 5 ) { break }
        }
    }
    if (!$name) {
        Write-Log 'Нет связис API трекера, выходим' -Red
        exit
    }
    
    return [PSCustomObject]@{ 'name' = $name; 'size' = $size }
}

function Update-Stats ( [switch]$wait, [switch]$check, [switch]$send_report ) {
    Test-ForumWorkingHours
    $MoscowTZ = [System.TimeZoneInfo]::FindSystemTimeZoneById("Russian Standard Time")
    $MoscowTime = [System.TimeZoneInfo]::ConvertTimeFromUtc((Get-Date).ToUniversalTime(), $MoscowTZ)
    $lock_file = "$PSScriptRoot\in_progress.lck"
    $in_progress = Test-Path -Path $lock_file
    If ( ( ( Get-Date($MoscowTime) -UFormat %H ).ToInt16( $nul ) + 2 ) % 2 -eq 0 -or ( $check -eq $false ) ) {
        if ( !$in_progress ) {
            if ( $wait ) {
                Write-Log 'Подождём 5 минут, вдруг быстро скачаются добавленные/обновлённые.'
                Start-Sleep -Seconds 300
            }
            New-Item -Path "$PSScriptRoot\in_progress.lck" | Out-Null
            try {
                Write-Log 'Обновляем БД TLO'
                . $php_path ( Join-Path $tlo_path 'cron' 'update.php' )
                Write-Log 'Обновляем списки других хранителей'
                . $php_path ( Join-Path $tlo_path 'cron' 'keepers.php' )
                if ( $send_report ) {
                    Send-Report
                }
            }
            finally {
                Remove-Item $lock_file -ErrorAction SilentlyContinue
            }
        }
        else {
            Write-Host "Обнаружен файл блокировки $lock_file. Вероятно, запущен параллельный процесс. Если это не так, удалите файл" -ForegroundColor Red
        }
    }
}

function Send-Report () {
    Write-Log 'Шлём отчёт'
    . $php_path "$tlo_path\cron\reports.php"
}

function Remove-ClientTorrent ( $client, $hash, [switch]$deleteFiles ) {
    try {
        if ( $deleteFiles -eq $true ) {
            $text = 'Удаляем из клиента ' + $client.Name + ' раздачу ' + $hash + ' вместе с файлами'
            Write-Host $text
        }
        else {
            $text = 'Удаляем из клиента ' + $client.Name + ' раздачу ' + $hash + ' без удаления файлов'
            Write-Host $text
        }
        $request_delete = @{
            hashes      = $hash
            deleteFiles = $deleteFiles
        }
        Invoke-WebRequest -Uri ( $client.ip + ':' + $client.Port + '/api/v2/torrents/delete' ) -WebSession $client.sid -Body $request_delete -Method POST | Out-Null
    }
    catch {
        Write-Host ( '[delete] Почему-то не получилось удалить раздачу {0}.' -f $torrent_id )
    }
}

function Send-TGMessage ( $message, $token, $chat_id ) {
    if ( $token -ne '' ) {
        $payload = @{
            "chat_id"                  = $chat_id
            "parse_mode"               = 'html'
            "disable_web_page_preview" = $true
            "text"                     = $message
        }
    }
    Invoke-WebRequest -Uri ( "https://api.telegram.org/bot$token/sendMessage" ) -Method Post -ContentType "application/json; charset=utf-8" -Body (ConvertTo-Json -Compress -InputObject $payload) | Out-Null
}

function Send-TGReport ( $refreshed, $added, $obsolete, $token, $chat_id ) {
    if ( $refreshed.Count -gt 0 -or $added.Count -gt 0 -or $obsolete.Count -gt 0 ) {
        if ( $brief_reports -ne 'Y') {
            # полная сводка в ТГ
            $message = ''
            $first = $true
            foreach ( $client in $refreshed.Keys ) {
                if ( !$first ) { $message += "`n" }
                $first = $false
                $message += "Обновлены в клиенте <b>$client</b>`n"
                $refreshed[$client].keys | Sort-Object | ForEach-Object {
                    # $message += "<i>Раздел $_</i>`n"
                    $refreshed[$client][$_] | ForEach-Object { $message += ( 'https://rutracker.org/forum/viewtopic.php?t=' + $_.id + $_.comment + "`n" + $_.name + ' (' + ( to_kmg $_.old_size 2 ) + ' -> ' + ( to_kmg $_.new_size 2 ) + ")`n`n" ) }
                }
            }

            if ( $message -ne '' ) { $message += "`n`n" }

            $first = $true
            foreach ( $client in $added.Keys ) {
                if ( !$first ) { $message += "`n" }
                $first = $false
                $message += "Добавлены в клиент <b>$client</b>`n"
                $added[$client].keys | Sort-Object | ForEach-Object {
                    # $message += "<i>Раздел $_</i>`n"
                    $added[$client][$_] | ForEach-Object { $message += ( 'https://rutracker.org/forum/viewtopic.php?t=' + $_.id + "`n" + $_.name + ' (' + ( to_kmg $_.size 1 ) + ')' + "`n`n") }
                }
            }

            if ( $message -ne '' ) { $message += "`n" }
            $first = $true
            foreach ( $client in $obsolete.Keys ) {
                if ( !$first ) { $message += "`n" }
                $first = $false
                $message += "Лишние в клиенте $client :`n"
                $obsolete[$client] | ForEach-Object {
                    $message += "https://rutracker.org/forum/viewtopic.php?t=$_`n"
                    if ( $id_to_info[$_].name ) {
                        $message += ( $id_to_info[$_].name + ', ' + ( to_kmg $id_to_info[$_].size 2 ) + "`n" )
                    }
                }
            }
        }
        else {
            # краткая сводка в ТГ
            $message = ''
            $keys = (  $refrehed.keys + $added.keys + $obsolete.Keys ) | Sort-Object -Unique
            foreach ( $client in $keys ) {
                if ( $message -ne '' ) { $message += "`n" }
                $message += "<u>Клиент <b>$client</b></u>`n"
                if ( $refreshed -and $refreshed[$client] ) {
                    # $first = $true
                    $refreshed[$client].keys | Sort-Object | ForEach-Object {
                        if ( $message -ne '' ) { $message += "`n" }
                        # $message += "<i>Раздел $_</i>`n"
                        $message += ( "Обновлено: " + $refreshed[$client][$_].count + "`n")
                    }
                }
                # if ( !$first ) { $message += "`n" }
                if ( $added -and $added[$client] ) {
                    # $first = $true
                    $added[$client].keys | Sort-Object | ForEach-Object {
                        # if ( $message -ne '' ) { $message += "`n" }
                        # $message += "<i>Раздел $_</i>`n"
                        $message += ( "Добавлено: " + $added[$client][$_].count + "`n")
                    }
                }
                # if ( !$first ) { $message += "`n" }
                if ( $obsolete -and $obsolete[$client] ) {
                    $message += ( "Лишних: " + $obsolete[$client].count + "`n" )
                }
            }
        }
        Send-TGMessage $message $token $chat_id
    }
    else {
        $message = 'Ничего делать не понадобилось'
        Send-TGMessage $message $token $chat_id
    }
}

function Start-Torrents( $hashes, $client) {
    $Params = @{ hashes = ( $hashes -join '|' ) }
    $url = $client.ip + ':' + $client.Port + '/api/v2/torrents/resume'
    Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
}

function Stop-Torrents( $hashes, $client) {
    $Params = @{ hashes = ( $hashes -join '|' ) }
    $url = $client.ip + ':' + $client.Port + '/api/v2/torrents/pause'
    Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
}

function Set-StartStop ( $keys ) {
    $now_epoch = ( Get-Date -UFormat %s ).ToInt32($null)
    $new_keys = $keys | Where-Object { $states[$_].start_date -eq 0 }
    $existing_keys = $keys | Where-Object { $states[$_].start_date -ne 0 }

    if ( $new_keys -and $new_keys.count -gt 0 ) {
        $sql_values = '(' + ( $hash_to_id[ $new_keys ] -join ", $now_epoch ), (") + ", $now_epoch )"
        try {
            Invoke-SqliteQuery -Query "INSERT INTO start_dates (id,start_date) VALUES $sql_values" -SQLiteConnection $conn
        }
        catch { 
            Write-Log 'Что-то пошло не так при записи даты запуска/остановки в БД, этого не должно было случиться' -Red
            Pause
        }
    }
    if ( $existing_keys -and $existing_keys.count -gt 0 ) {
        try {
            Invoke-SqliteQuery -Query "UPDATE start_dates SET start_date = @st_date WHERE id IN (@id)" -SqlParameters @{ id = ( $hash_to_id[$existing_keys] -join ',' ) ; st_date = $now_epoch } -SQLiteConnection $conn
        }
        catch {
            Write-Log 'Что-то пошло не так при обновлении даты запуска/остановки в БД, этого не должно было случиться' -Red
            Pause
        }
    }
}

function Get-IniSections ( [switch]$useForced ) {
    $result = @()
    if ( $forced_sections -and $useForced ) {
        Write-Log 'Анализируем forced_sections'
        $forced_sections = $forced_sections.Replace(' ', '')
        $result = $forced_sections.split(',')
    }
    else {
        $result = $ini_data.sections.subsections.split( ',' )
    }
    return $result
}

function Get-IniSectionDetails ( $sections ) {
    $section_details = @{}
    $sections | ForEach-Object {
        if ( $ini_data[ $_ ].client -ne '' -and $null -ne $ini_data[ $_ ].client ) {
            $section_details[$_] = [PSCustomObject]@{
                client         = $ini_data[ $_ ].client
                data_folder    = $ini_data[ $_ ].'data-folder'
                data_subfolder = $ini_data[ $_ ].'data-sub-folder'
                hide_topics    = $ini_data[ $_ ].'hide-topics'
                label          = $ini_data[ $_ ].'label'
                control_peers  = $ini_data[ $_ ].'control-peers'
            }
        }
        else {
            Write-Log "У раздела $_ не указан клиент, пропускаем" -Red
        }
    }
    return $section_details    
}

function Start-Rehash ( $client, $hash ) {
    $Params = @{ hashes = $hash }
    $url = $client.ip + ':' + $client.Port + '/api/v2/torrents/recheck'
    Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
}

Function DeGZip-File {
    Param(
        $infile,
        $outfile = ($infile -replace '\.gz$', '')
    )

    $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
    $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
    $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)

    $buffer = New-Object byte[](1024)
    while ($true) {
        $read = $gzipstream.Read($buffer, 0, 1024)
        if ($read -le 0) { break }
        $output.Write($buffer, 0, $read)
    }

    $gzipStream.Close()
    $output.Close()
    $input.Close()
}

function Set-Comment ( $client, $torrent, $label ) {
    Write-Output ( 'Метим раздачу ' + $torrent.topic_id + ' меткой ' + $label )
    $tag_url = $client.IP + ':' + $client.Port + '/api/v2/torrents/addTags'
    $tag_body = @{ hashes = $torrent.hash; tags = $label }
    Invoke-WebRequest -Method POST -Uri $tag_url -Headers $loginheader -Body $tag_body -WebSession $client.sid | Out-Null
}

function Switch-Filtering ( $client, $enable = $true ) {
    Set-ClientSetting $client 'ip_filter_enabled' $enable
}
