function Write-Log ( $str, [switch]$Red, [switch]$Green, [switch]$NoNewLine, [switch]$skip_timestamp, [switch]$nologfile) {
    if ( $settings.interface.use_timestamp -ne 'Y' -or $skip_timestamp ) {
        if ( $Red ) { Write-Host $str -ForegroundColor Red -NoNewline:$NoNewLine }
        elseif ( $Green ) { Write-Host $str -ForegroundColor Green -NoNewline:$NoNewLine }
        else { Write-Host $str -NoNewline:$NoNewLine }
        if ( $log_path -and -not $nologfile.IsPresent) { Write-Output $str.Replace('...', '') | Out-File $log_path -Append -Encoding utf8 | Out-Null }
    }
    else {
        if ( $Red ) { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) -ForegroundColor Red -NoNewline:$NoNewLine }
        elseif ( $Green ) { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) -ForegroundColor Green -NoNewline:$NoNewLine }
        else { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) -NoNewline:$NoNewLine } 
        if ( $log_path -and -not $nologfile.IsPresent ) { Write-Output ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str.Replace('...', '') ) | Out-File $log_path -Append -Encoding utf8 | Out-Null }
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

function Test-Version ( $name, $mess_sender = '') {
    try {
        $old_hash = ( Get-FileHash -Path ( Join-Path $PSScriptRoot $name ) ).Hash
        $new_file_path = ( Join-Path $PSScriptRoot $name.replace( '.ps1', '.new' ) )
        Invoke-WebRequest -Uri ( 'https://raw.githubusercontent.com/Another-1/RT_Pack/main/' + $name ) -OutFile $new_file_path | Out-Null
        if ( Test-Path $new_file_path ) {
            $new_hash = ( Get-FileHash -Path $new_file_path ).Hash
            if ( $old_hash -ne $new_hash ) {
                if ( $auto_update -eq 'N' -or $settings.others.auto_update -eq 'N') {
                    $text = "$name обновился! Рекомендуется скачать новую версию."
                    Write-Log $text -Red
                    if ( $alert_oldies -eq 'Y' -and $tg_token -ne '' ) { Send-TGMessage -message $text -token $tg_token -chat_id $tg_chat -mess_sender $mess_sender }
                }
                if ( ( $auto_update -eq 'Y' -or $settings.others.auto_update -eq 'Y' ) -and $debug -ne 1 ) {
                    Write-Log "$name обновился, сохраняю новую версию"
                    Copy-Item -Path $new_file_path -Destination ( Join-Path $PSScriptRoot $name ) -Force
                    Write-Log "Снимаю блокировку с запуска $name"
                    Unblock-File -Path ( Join-Path $PSScriptRoot $name )
                    if ( $name -ne '_functions.ps1' ) {
                        Write-Log "Запускаем новую версию $name в отдельном окне, а тут выходим"
                        Start-Process pwsh ( ( Join-Path $PSScriptRoot $name ) + ' -delay' )
                        Remove-Item $new_file_path
                        exit
                    }
                    else { 
                        Remove-Item $new_file_path
                        return $true
                    }
                }
                else { 
                    Write-Log "В режиме отладки обновление $name отключено"
                }
            }
            Remove-Item $new_file_path -ErrorAction SilentlyContinue
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

function Test-Setting ( $setting, [switch]$required, $default, [switch]$no_ini_write, $json_section ) {
    $set_names = @{
        'tg_token'              = @{ prompt = 'Токен бота Telegram, если нужна отправка событий в Telegram. Если не нужно, оставить пустым'; default = ''; type = 'string' }
        'tg_chat'               = @{ prompt = 'Номер чата для отправки сообщений Telegram'; default = ''; type = 'string' }
        'alert_oldies'          = @{ prompt = 'Уведомлять о новых версиях скриптов в Telegram? (нужен свой бот ТГ!)'; default = 'Y'; type = 'YN' }
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
        'php_path'              = @{ prompt = 'Путь к интерпретатору PHP (вместе с именем исполняемого файла)'; default = ''; type = 'string' }
        'report_stalled'        = @{ prompt = 'Отправлять боту призыв о помощи по некачашкам более месяца? (Y/N)'; default = 'N'; type = 'YN' }
        'report_obsolete'       = @{ prompt = 'Сообщать в Telegram о неактуальных раздачах? (Y/N) (нужен свой бот ТГ!)'; default = 'Y'; type = 'YN' }
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
        # 'hours_to_stop'         = @{ prompt = 'Сколько минимум часов держать раздачу запущенной?'; default = 3; type = 'number' }
        'old_starts_per_run'    = @{ prompt = 'Максимальное количество запускаемых за раз давно стоящих раздач? '; default = 100; type = 'number' }
        'min_stop_to_start'     = @{ prompt = 'Через сколько дней простоя обязательно запускать раздачу? '; default = 21; type = 'number' }
        'report_nowork'         = @{ prompt = 'Сообщать в Telegam если ничего не пришлось делать? (нужен свой бот ТГ!)'; default = 'Y'; type = 'YN' }
        'auto_update'           = @{ prompt = 'Автоматически обновлять версии скриптов?'; default = 'N'; type = 'YN' }
        'down_tag'              = @{ prompt = 'Тэг для скачиваемых раздач'; type = 'string' }
        'seed_tag'              = @{ prompt = 'Тег для завершённых раздач'; type = 'string' }
        'stalled_pwd'           = @{ prompt = 'Пароль для отправки некачашек (см. у бота Кузи в /about_me)'; type = 'string' }
        'id_subfolder'          = @{ prompt = 'Создавать папки по ID если нет?'; type = 'YN' }
    }
    $changed = $false
    # if ( $json_section ) {
    #     $setting = '$settings.' + "$json_section.$setting"
    # }
    if ( $json_section -and $json_section -ne '' ) {
        try { $current_var = $settings.$json_section.$setting } catch {}
    }
    else {
        $current_var = ( Get-Variable -Name $setting -ErrorAction SilentlyContinue )
    }
    if ( $current_var ) { $current = $current_var.Value }
    else {
        if ( $default -and $default -ne '' ) { $set_names[$setting].default = $default }
        do {
            $current = Read-Host -Prompt ( $set_names[$setting].prompt + $( ( $set_names[$setting].default -and $set_names[$setting].default -ne '' ) ? ' [' + $set_names[$setting].default + ']' : '' ) )
            if ( $set_names[$setting].type -eq 'YN' ) {
                if ( $current -ne '' ) { $current = $current.ToUpper() }
            }
            if ( $current -eq '' -and $nul -ne $set_names[$setting].default ) {
                $current = $set_names[$setting].default
            }
            if ( $setting -like '*tlo_path') {
                $ini_path = Join-Path $current 'data' 'config.ini'
                If ( -not ( Test-Path $ini_path ) ) {
                    Write-Log ( 'Не нахожу файла ' + ( $ini_path ) + ', проверьте ввод' ) -ForegroundColor -Red
                    $current = ''
                }
                else { 
                    $changed = $true
                }
            }
            elseif ( $setting -like '*php_path' ) {
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
        } while ( ( $current -eq '' -and $required ) -or ( $set_names[$setting].type -eq 'YN' -and $current -notmatch '[YN]' ) )

        if ( $changed ) {
            if ( $set_names[$setting].type -eq ( 'number' ) ) {
                $current = $current.ToInt64( $null )
            }
            Set-Variable -Name $setting -Value $current
            if ( $no_ini_write.IsPresent -eq $false -and $standalone -eq $false ) {
                Add-Content -Path ( Join-Path $PSScriptRoot '_settings.ps1' ) `
                    -Value ( '$' + $setting + ' = ' + $( ( $set_names[$setting].type -in ( 'YN', 'string' ) ) ? "'" : '') + $current + $( ( $set_names[$setting].type -in ( 'YN', 'string' ) ) ? "'" : '') + '   # ' + $set_names[$setting].prompt )
            }
        }
    }
    return $current
}

function Test-ForumWorkingHours ( [switch]$verbose ) {
    $MoscowTZ = [System.TimeZoneInfo]::FindSystemTimeZoneById("Russian Standard Time")
    $MoscowTime = [System.TimeZoneInfo]::ConvertTimeFromUtc((Get-Date).ToUniversalTime(), $MoscowTZ)
    if ($verbose) {
        Write-Log 'Проверяем, что в Москве не 4 часа ночи (профилактика)'
        Write-Log ( 'Московское время ' + ( Get-Date($MoscowTime) -UFormat %H ) + ' ч ' + ( Get-Date($MoscowTime) -UFormat %M ) + ' мин' )
    }
    if ( ( Get-Date($MoscowTime) -UFormat %H ) -eq '04' ) {
        Write-Log 'Профилактические работы на сервере' -ForegroundColor -Red
        exit
    }
}

Function Set-ConnectDetails ( $settings ) {

    if ( !$settings.connection ) { $settings.connection = [ordered]@{} }
    $settings.connection.login = $ini_data.'torrent-tracker'.login
    $settings.connection.password = $ini_data.'torrent-tracker'.password
    $settings.connection.forum_url = $ini_data.'torrent-tracker'.forum_url
    $settings.connection.forum_ssl = ( $ini_data.'torrent-tracker'.forum_ssl -eq '1' ? 'Y' : 'N' )
    $settings.connection.user_id = $ini_data.'torrent-tracker'.user_id
    $settings.connection.api_url = $ini_data.'torrent-tracker'.api_url
    $settings.connection.api_ssl = ( $ini_data.'torrent-tracker'.api_ssl -eq '1' ? 'Y' : 'N' )
    $settings.connection.report_url = $ini_data.'torrent-tracker'.report_url
    $settings.connection.report_ssl = ( $ini_data.'torrent-tracker'.report_ssl -eq '1' ? 'Y' : 'N' )
    $settings.connection.api_key = $ini_data.'torrent-tracker'.api_key
    if ( !$settings.connection.report_url -or $settings.connection.report_url -eq '' ) {
        $settings.connection.report_url = 'rep.rutracker.cc'
        # $settings.connection.proxy.use_for_rep = $settings.connection.proxy.use_for_api
    }

    If ( $ini_data.proxy.activate_forum -eq '1' -or $ini_data.proxy.activate_api -eq '1' -or $ini_data.proxy.activate_report -eq '1' ) {
        Write-Log ( 'Используем ' + $ini_data.proxy.type.Replace('socks5h', 'socks5') + ' прокси ' + $ini_data.proxy.hostname + ':' + $ini_data.proxy.port )
    }
    $settings.connection.proxy = [ordered]@{}
    $settings.connection.proxy.ip = $ini_data.proxy.hostname
    $settings.connection.proxy.port = $ini_data.proxy.port
    $settings.connection.proxy.type = $ini_data.proxy.type
    # if ( $ini_data.proxy.type -like 'socks*' ) { $settings.connection.proxy_url = 'socks5://' + $ini_data.proxy.hostname + ':' + $ini_data.proxy.port }
    # else { $ConnectDetails.ProxyURL = 'http://' + $ini_data.proxy.hostname + ':' + $ini_data.proxy.port }
    $settings.connection.proxy.login = $ini_data.proxy.login
    $settings.connection.proxy.password = $ini_data.proxy.password
    $settings.connection.proxy.use_for_forum = ( $ini_data.proxy.activate_forum -eq '1' ? 'Y' : 'N' )
    $settings.connection.proxy.use_for_api = ( $ini_data.proxy.activate_api -eq '1' ? 'Y' : 'N' )
    $settings.connection.proxy.use_for_rep = ( $ini_data.proxy.activate_report -eq '1' ? 'Y' : 'N' )
    if ( !$settings.connection.use_for_rep ) {
        $settings.connection.use_for_rep = $settings.connection.proxy.use_for_api
    }

    # if ( $settings.connection.proxy.ip -and $settings.connection.password -and $settings.connection.password -ne '') {
    #     $proxyPass = ConvertTo-SecureString $settings.connection.password -AsPlainText -Force
    #     $settings.connection.proxy.credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $settings.connection.login, $proxyPass
    # }
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

function Get-Clients ( [switch]$LocalOnly ) {
    if ( !$settings ) { $settings = [ordered]@{} }
    $settings.clients = [ordered]@{}
    Write-Log 'Получаем из TLO данные о клиентах'
    $client_count = $ini_data['other'].qt.ToInt16($null)
    $i = 1
    $ini_data.keys | Where-Object { $_ -match '^torrent-client' -and $ini_data[$_].client -eq 'qbittorrent' } | ForEach-Object {
        if ( ( $_ | Select-String ( '\d+$' ) ).matches.value.ToInt16($null) -le $client_count ) {
            $settings.clients[$ini_data[$_].comment] = [ordered]@{ IP = $ini_data[$_].hostname; port = $ini_data[$_].port; login = $ini_data[$_].login; password = $ini_data[$_].password; id = $ini_data[$_].id; seqno = $i; name = $ini_data[$_].comment }
            $i++
        }
    } 
    if ( $LocalOnly ) {
        Write-Log 'Получаем IP локального компа чтобы не пытаться архивировать то, чего на нём нет'
        $localIPs = ( Get-NetIPAddress ).IPAddress
        $local_clients = [ordered]@{}
        $settings.clients.keys | ForEach-Object {
            if ( $settings.clients[$_].IP -in $localIPs ) { $local_clients[$_] = $settings.clients[$_] }
        }
        $settings.clients = $local_clients
    }
    Write-Log ( 'Актуальных клиентов к обработке: ' + $settings.clients.count + ': ' + ( ( $settings.clients.Keys | Sort-Object | ForEach-Object { $_ } ) -join ', ' ) )

    if ( ( $settings.clients.Keys | Sort-Object -Unique ).count -lt $settings.clients.count ) { Write-Log 'Клиенты должны называться по-разному, поправьте в настройках TLO' -Red; exit }
}

function Initialize-Client ( $client, $mess_sender = '', [switch]$verbose, [switch]$force ) {
    if ( !$client.sid -or $force ) {
        $logindata = @{ username = $client.login; password = $client.password }
        $loginheader = @{ Referer = 'http://' + $client.IP + ':' + $client.port }
        try {
            if ( $verbose ) { Write-Log ( 'Авторизуемся в клиенте ' + $client.Name ) }
            $url = $client.IP + ':' + $client.port + '/api/v2/auth/login'
            $result = Invoke-WebRequest -Method POST -Uri $url -Headers $loginheader -Body $logindata -SessionVariable sid
            if ( $result.StatusCode -ne 200 ) {
                Write-Log 'You are banned.' -Red
                exit
            }
            if ( $result.Content.ToUpper() -ne 'OK.') {
                Write-Log ( 'Клиент вернул ошибку авторизации: ' + $result.Content ) -Red
                exit
            }
            if ( $verbose ) { Write-Log 'Успешная авторизация' }
            $client.sid = $sid
        }
        catch {
            Write-Log ( '[client] Не удалось авторизоваться в клиенте, прерываем. Ошибка: {0}.' -f $Error[0] ) -Red
            if ( $tg_token -ne '' ) {
                Send-TGMessage "Нет связи с клиентом $( $client.Name ) при вызыве из $( (Get-PSCallStack)[(( Get-PSCallStack ).count - 1 )..0].Command | Where-Object { $null -ne $_ } | Join-String -Separator ' → ' ). Процесс остановлен." $tg_token $tg_chat $mess_sender
            }
            Exit
        }
    }
}

# function  Get-ClientTorrents ( $client, $disk = '', $mess_sender = '', [switch]$completed, $hash, $client_key, [switch]$verbose ) {
function  Get-ClientTorrents ( $client, $disk = '', $mess_sender = '', [switch]$completed, $hash, [switch]$verbose ) {
    $Params = @{}
    if ( $completed ) {
        $Params.filter = 'completed'
    }
    if ( $nul -ne $hash ) {
        $Params.hashes = $hash
        # if ( $verbose -eq $true ) { Write-Log ( 'Получаем инфо о раздаче из клиента ' + $client_key ) }
        if ( $verbose -eq $true ) { Write-Log ( 'Получаем инфо о раздаче из клиента ' + $client.name ) }
    }
    # elseif ( $verbose -eq $true ) { Write-Log ( 'Получаем список раздач от клиента ' + $client_key ) }
    elseif ( $verbose -eq $true ) { Write-Log ( 'Получаем список раздач от клиента ' + $client.name ) }
    if ( $null -ne $disk -and $disk -ne '') { $dsk = $disk + ':\\' } else { $dsk = '' }
    $i = 0
    while ( $true ) {
        try {
            $json_content = ( Invoke-WebRequest -Uri ( $client.IP + ':' + $client.port + '/api/v2/torrents/info' ) -WebSession $client.sid -Body $params -TimeoutSec 120 ).Content
            $torrents_list = $json_content | ConvertFrom-Json | `
                # Select-Object name, hash, save_path, content_path, category, state, uploaded, @{ N = 'topic_id'; E = { $nul } }, @{ N = 'client_key'; E = { $client_key } }, infohash_v1, size, completion_on, progress, tracker, added_on, tags | `
                Select-Object name, hash, save_path, content_path, category, state, uploaded, @{ N = 'topic_id'; E = { $nul } }, @{ N = 'client_key'; E = { $client.name } }, infohash_v1, size, completion_on, progress, tracker, added_on, tags | `
                Where-Object { $_.save_path -match ('^' + $dsk ) }
        }
        catch {
            Initialize-Client $client $mess_sender -force -verbose $verbose
            $i++
        }
        if ( $json_content -or $i -gt 3 ) { break }
    }
    if ( !$json_content ) {
        if ( $tg_token -ne '' ) { 
            Send-TGMessage -message ( 'Не удалось получить список раздач от клиента ' + $client.Name. + ', Выполнение прервано.' ) -token $tg_token -chat_id $tg_chat -mess_sender $mess_sender
        }
        Write-Log ( 'Не удалось получить список раздач от клиента ' + $client.Name )
    }
    if ( !$torrents_list ) { $torrents_list = @() }
    if ( $verbose ) { Write-Log ( 'Получено ' + $torrents_list.Count + ' раздач от клиента ' + $client.Name ) }
    return $torrents_list
}

function Get-ClientsTorrents ( $mess_sender = '', [switch]$completed, [switch]$noIDs) {
    $clients_torrents = @()
    foreach ($clientkey in $settings.clients.Keys ) {
        $client = $settings.clients[ $clientkey ]
        Initialize-Client $client $mess_sender -verbose
        $client_torrents = Get-ClientTorrents -client $client -client_key $clientkey -verbose -completed:$completed -mess_sender $mess_sender
        if ( $noIDs.IsPresent -eq $false ) { Get-TopicIDs $client $client_torrents }
        $clients_torrents += $client_torrents
    }
    return $clients_torrents
}

function Get-TopicIDs ( $client, $torrent_list ) {
    Write-Log 'Ищем ID раздач по хэшам от клиента в данных от трекера'
    if ( $torrent_list.count -gt 0 ) {
        $torrent_list | ForEach-Object {
            if ( $null -ne $tracker_torrents ) { $_.topic_id = [Int64]$tracker_torrents[$_.hash.toUpper()].topic_id }
            if ( $null -eq $_.topic_id -or $_.topic_id -eq '' ) {
                $Params = @{ hash = $_.hash }
                try {
                    $comment = ( Invoke-WebRequest -Uri ( $client.IP + ':' + $client.port + '/api/v2/torrents/properties' ) -WebSession $client.sid -Body $params ).Content | ConvertFrom-Json | Select-Object comment -ExpandProperty comment
                    Start-Sleep -Milliseconds 10
                }
                catch { }
                $ending = ( Select-String "\d*$" -InputObject $comment ).Matches.Value
                $_.topic_id = $( $ending -ne '' ? $ending.ToInt64($null) : $null )
            }
        }
        $success = ( $torrent_list | Where-Object { $_.topic_id } ).count
        Write-Log ( 'Найдено ' + $success + ' штук ID' ) -Red:( $success -ne $torrent_list.Count )
    }
}

function Add-ClientTorrent ( $Client, $file, $path, $category, $mess_sender = '', [switch]$Skip_checking ) {
    $Params = @{
        torrents      = Get-Item $file
        savepath      = $path
        category      = $category
        name          = 'torrents'
        root_folder   = 'false'
        paused        = $Paused
        skip_checking = $Skip_checking
    }

    Write-Log 'Отправляем скачанный torrent-файл в клиент'
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
                Initialize-Client -client $client -mess_sender $mess_sender -force -verbose
                Start-Sleep -Seconds 1
            }
        }
    }
    Remove-Item $File
}

Function Set-ClientSetting ( $client, $param, $value, $mess_sender ) {
    $url = $client.ip + ':' + $client.Port + '/api/v2/app/setPreferences'
    $param = @{ json = ( @{ $param = $value } | ConvertTo-Json -Compress ) }
    try { Invoke-WebRequest -Uri $url -WebSession $client.sid -Body $param -Method POST | Out-Null }
    catch {
        Initialize-Client -client $client -mess_sender $mess_sender -verbose
        Invoke-WebRequest -Uri $url -WebSession $client.sid -Body $param -Method POST | Out-Null 
    }
}

function Initialize-Forum () {
    if ( !$settings.connection ) {
        Write-Log 'Не обнаружены данные для подключения к форуму. Проверьте настройки.' -ForegroundColor Red
        Exit
    }
    Write-Log 'Авторизуемся на форуме.'

    $login_url = $( $settings.connection.forum_ssl -eq 'Y' ? 'https://' : 'http://' ) + $settings.connection.forum_url + '/forum/login.php'
    $headers = @{ 'User-Agent' = 'Mozilla/5.0' }
    $payload = @{ 'login_username' = $settings.connection.login; 'login_password' = $settings.connection.password; 'login' = '%E2%F5%EE%E4' }
    $i = 1

    while ($true) {
        try {
            if ( $settings.connection.proxy.use_for_forum.ToUpper() -eq 'Y' -and $settings.connection.proxy.ip -and $settings.connection.proxy.ip -ne '' ) {
                if ( $request_details -eq 'Y' ) { Write-Log "Идём на $url используя прокси $($settings.connection.proxy.url )" }
                if ( $settings.connection.proxy.credentials ) {
                    $answer = ( Invoke-WebRequest -Uri $login_url -Method Post -Headers $headers -Body $payload -SessionVariable sid -MaximumRedirection 999 -SkipHttpErrorCheck -Proxy $settings.connection.proxy.url -ProxyCredential $settings.connection.proxy.credentials )
                }
                else {
                    $answer = ( Invoke-WebRequest -Uri $login_url -Method Post -Headers $headers -Body $payload -SessionVariable sid -MaximumRedirection 999 -SkipHttpErrorCheck -Proxy $settings.connection.proxy.url )
                }
            }
            else {
                if ( $request_details -eq 'Y' ) { Write-Log "Идём на $login_url без прокси, напрямую" }
                $answer = ( Invoke-WebRequest -Uri $login_url -Method Post -Headers $headers -Body $payload -SessionVariable sid -MaximumRedirection 999 -SkipHttpErrorCheck )
            }
            if ( $request_details -eq 'Y' ) { Write-Log 'Ответ получен' }
            break
        }
        catch {
            Write-Log 'Не удалось соединиться с форумом' -Red
            Start-Sleep -Seconds 10; $i++; Write-Log "Попытка номер $i"
            If ( $i -gt 10 ) { break }
        }
        if ( $answer.StatusCode -ne 200 ) {
            Write-Log "Форум вернул ответ $($answer.StatusCode)" -Red
            Start-Sleep -Seconds 10; $i++; Write-Log "Попытка номер $i"
            If ( $i -gt 10 ) { break }
        }
        if ( $sid.Cookies.Count -eq 0 ) {
            Write-Log 'Форум не вернул cookie' -Red
            Start-Sleep -Seconds 10; $i++; Write-Log "Попытка номер $i"
            If ( $i -gt 10 ) { break }
        }
        else { break }
    }
    if ( $answer.StatusCode -ne 200 ) {
        Write-Log "Форум вернул ответ $($answer.StatusCode)" -Red
        Start-Sleep -Seconds 10; $i++; Write-Log "Попытка номер $i"
        If ( $i -gt 10 ) { break }
    }
    if ( $sid.Cookies.Count -eq 0 ) {
        Write-Log 'Форум не вернул cookie' -Red
        Start-Sleep -Seconds 10; $i++; Write-Log "Попытка номер $i"
        If ( $i -gt 10 ) { break }
    }

    $token = ( ( Select-String -InputObject $answer.Content -Pattern "\tform_token ?: '(.+?)'," ).matches[0].value.Replace("',", '')) -replace ( "\s*form_token: '", '')
    if ($token -and $token -ne '' ) { $settings.connection.token = $token }
    $settings.connection.sid = $sid
    Write-Log ( 'Успешно.' )
}

function ConvertTo-1251 ( $inp ) {
    $sourceEncoding = [System.Text.Encoding]::GetEncoding("Windows-1251")
    return [System.Web.HttpUtility]::UrlEncode($sourceEncoding.GetBytes($inp)) #.ToUpper()
}

function Send-Forum ( $mess, $post_id ) {
    if ( !$settings.connection ) {
        Write-Log 'Не обнаружены данные для подключения к форуму. Проверьте настройки.' -ForegroundColor Red
        Exit
    }
    if ( !$settings.connection.sid ) { Initialize-Forum }

    $pos_url = "$( $settings.connection.forum_ssl -eq 'Y' ? 'https://' : 'http://' )$($settings.connection.forum_url)/forum/posting.php"
    $headers = @{ 'User-Agent' = 'Mozilla/5.0' }
    $body = "mode=editpost&p=$post_id&message=$mess&submit_mode=submit&form_token=$($settings.connection.token)"
    $i = 1

    while ($true) {
        try {
            if ( $request_details -eq 'Y' ) {
                Write-Log "Идём на $url используя прокси $($settings.connection.proxy.url )"
                if ( $settings.connection.proxy.credentials ) {
                    Invoke-WebRequest -Uri $pos_url -Method POST -WebSession $settings.connection.sid -Headers $headers -Body $body -Proxy $settings.connection.proxy.url -MaximumRedirection 999 -SkipHttpErrorCheck -ProxyCredential $settings.connection.proxy.credentials
                }
                else { Invoke-WebRequest -Uri $pos_url -Method POST -WebSession $settings.connection.sid -Headers $headers -Body $body -Proxy $settings.connection.proxy.url -MaximumRedirection 999 -SkipHttpErrorCheck }
                break
            }
            else {
                Invoke-WebRequest -Uri $pos_url -Method POST -WebSession $settings.connection.sid -Headers $headers -Body $body -MaximumRedirection 999 -SkipHttpErrorCheck -ContentType "application/x-www-form-urlencoded"
                break
            }
        }
        catch {
            Start-Sleep -Seconds 10; $i++; Write-Log "Попытка номер $i"
            If ( $i -gt 20 ) { break }
        }
    }
}


function Get-ForumTorrentFile ( [int]$Id, $save_path = $null) {
    if ( !$settings.connection.sid ) { Initialize-Forum }
    $get_url = $( $settings.connection.forum_ssl -eq 'Y' ? 'https://' : 'http://' ) + $settings.connection.forum_url + '/forum/dl.php?t=' + $Id
    if ( $null -eq $save_path ) { $Path = Join-Path $PSScriptRoot ( $Id.ToString() + '.torrent' ) } else { $path = Join-Path $save_path ( $Id.ToString() + '.torrent' ) }
    $i = 1
    Write-Log 'Скачиваем torrent-файл с форума'
    while ( $i -le 10 ) {
        try { 
            if ( $settings.connection.proxy.use_for_forum.ToUpper() -eq 'Y' -and $settings.connection.proxy.ip -and $settings.connection.proxy.ip -ne '' ) {
                if ( $request_details -eq 'Y' ) { Write-Log "Идём на $url используя прокси $($settings.connection.proxy.url )" }
                if ( $settings.connection.proxy.credentials ) {
                    Invoke-WebRequest -Uri $get_url -WebSession $settings.connection.sid -OutFile $Path -Proxy $settings.connection.proxy.url -MaximumRedirection 999 -SkipHttpErrorCheck -ProxyCredential $settings.connection.proxy.credentials
                }
                else {
                    Invoke-WebRequest -Uri $get_url -WebSession $settings.connection.sid -OutFile $Path -Proxy $settings.connection.proxy.url -MaximumRedirection 999 -SkipHttpErrorCheck
                }
                break
            }
            else { Invoke-WebRequest -Uri $get_url -WebSession $settings.connection.sid -OutFile $Path -MaximumRedirection 999 -SkipHttpErrorCheck; break }
        }
        catch { Start-Sleep -Seconds 10; $i++; Write-Log "Попытка номер $i" }
    }
    if ( $null -eq $save_path ) { return Get-Item $Path }
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

function Get-ForumTorrentInfo ( $id, $call_from ) {
    $params = @{ 
        by  = 'topic_id'
        val = $id 
    }

    $content = Get-HTTP 'https://api.rutracker.cc/v1/get_tor_topic_data' -Body $params -call_from $call_from -use_proxy $settings.connection.proxy.use_for_api
    $torinfo = ( $content | ConvertFrom-Json ).result.$id 
    $name = $torinfo.topic_title
    $size = $torinfo.size

    if (!$name) {
        Write-Log 'Нет связи с API трекера, выходим' -Red
        exit
    }
    
    return [PSCustomObject]@{ 'topic_title' = $name; 'size' = $size }
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
            Write-Log "Обнаружен файл блокировки $lock_file. Вероятно, запущен параллельный процесс. Если это не так, удалите файл" -ForegroundColor Red
        }
    }
}

function Send-Report () {
    Write-Log 'Шлём отчёт'
    . $php_path ( Join-Path $tlo_path 'cron' 'reports.php' )
}

function Remove-ClientTorrent ( $client, $hash, [switch]$deleteFiles ) {
    try {
        if ( $deleteFiles -eq $true ) {
            $text = 'Удаляем из клиента ' + $client.Name + ' раздачу ' + $hash + ' вместе с файлами'
            Write-Log $text
        }
        else {
            $text = 'Удаляем из клиента ' + $client.Name + ' раздачу ' + $hash + ' без удаления файлов'
            Write-Log $text
        }
        $request_delete = @{
            hashes      = $hash
            deleteFiles = $deleteFiles
        }
        Invoke-WebRequest -Uri ( $client.ip + ':' + $client.Port + '/api/v2/torrents/delete' ) -WebSession $client.sid -Body $request_delete -Method POST | Out-Null
    }
    catch {
        Write-Log "[delete] Почему-то не получилось удалить раздачу $torrent_id." -Red
    }
}

function Send-TGMessage ( $message, $token, $chat_id, $mess_sender = '' ) {
    if ( $token -ne '' ) {
        if ( $mention_script_tg -eq 'Y' -and $mess_sender -ne '' ) { $message = "<b>$mess_sender" + $( $RT_Pack_name ? " $RT_Pack_name" : '' ) + "</b> имеет сообщить:`n`n" + $message }
        $payload = @{
            "chat_id"                  = $chat_id
            "parse_mode"               = 'html'
            "disable_web_page_preview" = $true
            "text"                     = $message
        }
    }
    Invoke-WebRequest -Uri ( "https://api.telegram.org/bot$token/sendMessage" ) -Method Post -ContentType "application/json; charset=utf-8" -Body (ConvertTo-Json -Compress -InputObject $payload) | Out-Null
}

function Add-TGMessage ( $tg_data ) {
    if ( $tg_data.message.Length -gt 3500 ) {
        $tg_data.messages += $message
        $tg_data.message = ''
    }
    $tg_data.message += $tg_data.line
}

function Send-TGReport ( $refreshed, $added, $obsolete, $broken, $token, $chat_id, $mess_sender ) {
    $tg_data = @{}
    $tg_data.messages = [System.Collections.ArrayList]::new()
    if ( $refreshed.Count -gt 0 -or $added.Count -gt 0 -or $obsolete.Count -gt 0 -or $broken.Count -gt 0 ) {
        if ( $brief_reports -ne 'Y') {
            $tg_data.message = ''
            $first = $true
            foreach ( $client in $refreshed.Keys ) {
                if ( !$first ) { $tg_data.message += "`n" }
                $first = $false
                $tg_data.$line = "Обновлены в клиенте <b>$client</b>`n"
                Add-TGMessage $tg_data
                $refreshed[$client].keys | Sort-Object | ForEach-Object {
                    $refreshed[$client][$_] | ForEach-Object {
                        # Add-TGMessage ( 'https://rutracker.org/forum/viewtopic.php?t=' + $_.id + $_.comment + "`n" + $_.name + ' (' + ( to_kmg $_.old_size 2 ) + ' -> ' + ( to_kmg $_.new_size 2 ) + ")`n`n" )
                        $tg_data.line + ( 'https://rutracker.org/forum/viewtopic.php?t=' + $_.id + $_.comment + "`n" + $_.name + ' (' + ( to_kmg $_.old_size 2 ) + ' -> ' + ( to_kmg $_.new_size 2 ) + ")`n`n" )
                        Add-TGMessage $tg_data
                    }
                }
            }

            if ( $tg_data.message -ne '' ) { $tg_data.message += "`n`n" }
            # if ( $message -ne '' ) { Add-TGMessage $messages $message "`n`n" }

            $first = $true
            foreach ( $client in $added.Keys ) {
                if ( !$first ) { $tg_data.message += "`n" }
                $first = $false
                $tg_data.line = "Добавлены в клиент <b>$client</b>`n"
                Add-TGMessage $tg_data
                # Add-TGMessage "Добавлены в клиент <b>$client</b>`n"
                $added[$client].keys | Sort-Object | ForEach-Object {
                    $added[$client][$_] | ForEach-Object {
                        $tg_data.line = ( 'https://rutracker.org/forum/viewtopic.php?t=' + $_.id + "`n" + $_.name + ' (' + ( to_kmg $_.size 1 ) + ')' + "`n`n")
                        Add-TGMessage $tg_data
                        # Add-TGMessage ( 'https://rutracker.org/forum/viewtopic.php?t=' + $_.id + "`n" + $_.name + ' (' + ( to_kmg $_.size 1 ) + ')' + "`n`n" )
                    }
                }
            }

            if ( $tg_data.message -ne '' -and $obsolete.count -gt 0 ) { $tg_data.message += "`n" }
            $first = $true
            foreach ( $client in $obsolete.Keys ) {
                if ( !$first ) { $tg_data.message += "`n" }
                $first = $false
                $tg_data.line = "Лишние в клиенте $($client.name) :`n"
                Add-TGMessage $tg_data
                # Add-TGMessage "Лишние в клиенте $($client.name) :`n"
                $obsolete[$client] | ForEach-Object {
                    $tg_data.line = "https://rutracker.org/forum/viewtopic.php?t=$_`n"
                    Add-TGMessage $tg_data
                    # Add-TGMessage "https://rutracker.org/forum/viewtopic.php?t=$_`n"
                    if ( $id_to_info[$_].name ) {
                        $tg_data.line = ( $id_to_info[$_].name + ', ' + ( to_kmg $id_to_info[$_].size 2 ) + "`n" )
                        Add-TGMessage $tg_data
                        # Add-TGMessage ( $id_to_info[$_].name + ', ' + ( to_kmg $id_to_info[$_].size 2 ) + "`n" )
                    }
                }
            }

            if ( $tg_data.message -ne '' -and $broken.count -gt 0 ) { $tg_data.message += "`n" }
            $first = $true
            foreach ( $client in $broken.Keys ) {
                if ( !$first ) { $tg_data.message += "`n" }
                $first = $false
                $tg_data.message += "Проблемные в клиенте $($client.name) :`n"
                $broken[$client] | ForEach-Object {
                    $tg_data.line = "https://rutracker.org/forum/viewtopic.php?t=$_`n"
                    Add-TGMessage $tg_data
                    # Add-TGMessage "https://rutracker.org/forum/viewtopic.php?t=$_`n"
                    if ( $id_to_info[$_].name ) {
                        # Add-TGMessage ( $id_to_info[$_].name + ', ' + ( to_kmg $id_to_info[$_].size 2 ) + "`n" )
                        $tg_data.line = $id_to_info[$_].name + ', ' + ( to_kmg $id_to_info[$_].size 2 ) + "`n"
                        Add-TGMessage $tg_data
                    }
                }
            }
        }
        else {
            $tg_data.message = ''
            $keys = (  $refreshed.keys + $added.keys + $obsolete.Keys ) | Sort-Object -Unique
            [double]$added_b = 0
            [double]$refreshed_b = 0
            foreach ( $client in $keys ) {
                if ( $tg_data.message -ne '' ) { $tg_data.message += "`n" }
                # Add-TGMessage "<u>Клиент <b>$client</b></u>`n"
                $tg_data.line = "<u>Клиент <b>$client</b></u>`n"
                Add-TGMessage $tg_data
                if ( $refreshed -and $refreshed[$client] ) {
                    $stat = ( $refreshed[$client].keys | ForEach-Object { $refreshed[$client][$_] }) | Measure-Object -Property new_size -Sum
                    $stat_was = ( $refreshed[$client].keys | ForEach-Object { $refreshed[$client][$_] }) | Measure-Object -Property old_size -Sum
                    $tg_data.line = "Обновлено: $( Get-Spell -qty $stat.Count -spelling 1 -entity 'torrents' ), $( to_kmg $stat.Sum 2 ) `n"
                    Add-TGMessage $tg_data
                    # Add-TGMessage "Обновлено: $( Get-Spell -qty $stat.Count -spelling 1 -entity 'torrents' ), $( to_kmg $stat.Sum 2 ) `n"
                    $refreshed_b += ( $stat.Sum - $stat_was.Sum )
                }
                if ( $added -and $added[$client] ) {
                    $stat = ( $added[$client].keys | ForEach-Object { $added[$client][$_] }) | Measure-Object -Property size -Sum
                    # Add-TGMessage "Добавлено: $( Get-Spell -qty $stat.Count -spelling 1 -entity 'torrents' ), $( to_kmg $stat.Sum 2 ) `n"
                    $tg_data.line = "Добавлено: $( Get-Spell -qty $stat.Count -spelling 1 -entity 'torrents' ), $( to_kmg $stat.Sum 2 ) `n"
                    Add-TGMessage $tg_data
                    $added_b += $stat.Sum
                }
                if ( $obsolete -and $obsolete[$client] ) {
                    $tg_data.line = "Лишних: " + $obsolete[$client].count + "`n"
                    Add-TGMessage $tg_data
                }
            }
            $was = ( $clients_torrents | Measure-Object -Property size -Sum ).Sum
            $now = $was + $refreshed_b + $added_b
            # Add-TGMessage "`n<u><b>Итого</b></u>`nБыло: $(to_kmg $was 3 )`nСтало: $( to_kmg $now 3 )"
            $tg_data.line = "`n<u><b>Итого</b></u>`nБыло: $(to_kmg $was 3 )`nСтало: $( to_kmg $now 3 )"
            Add-TGMessage $tg_data
        }
        # Send-TGMessage -message $message -token $token -chat_id $chat_id -mess_sender $mess_sender
    }
    else {
        $tg_data.message = 'Ничего делать не понадобилось'
    }
    $tg_data.messages += $tg_data.message
    $tg_data.messages | ForEach-Object {
        Send-TGMessage -message $_ -token $token -chat_id $chat_id -mess_sender $mess_sender
    }
}

function Start-Torrents( $hashes, $client, $mess_sender ) {
    $Params = @{ hashes = ( $hashes -join '|' ) }
    $url = $client.IP + ':' + $client.port + '/api/v2/torrents/' + $client.start_command
    try {
        Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
    }
    catch {
        Initialize-Client -client $client -force -mess_sender $mess_sender -verbose
        Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
    }
}

function Stop-Torrents( $hashes, $client, $mess_sender ) {
    $Params = @{ hashes = ( $hashes -join '|' ) }
    $url = $client.IP + ':' + $client.port + '/api/v2/torrents/' + $client.stop_command
    try {
        Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
    }
    catch {
        Initialize-Client -client $client -force -mess_sender $mess_sender -verbose
        Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
    }

}

function Get-IniSections {
    $result = @()
    # if ( $forced_sections -and $useForced ) {
    #     Write-Log 'Анализируем forced_sections'
    #     $forced_sections = $forced_sections.Replace(' ', '')
    #     $result = $forced_sections.split(',')
    # }
    # else {
    $result = $ini_data.sections.subsections.split( ',' )
    # }
    return $result
}

function Get-IniSectionDetails ( $settings, $sections ) {
    $settings.sections = [ordered]@{}
    foreach ( $section in $sections ) {
        if ( $ini_data[$section].client -ne '' -and $null -ne $ini_data[$section].client ) {
            $settings.sections[$section] = [PSCustomObject]@{
                # client         = $settings.clients[$ini_data[$_].client].Name
                client         = $settings.clients.keys | Where-Object { $settings.clients[$_].id -eq $ini_data[$section].client }
                data_folder    = $ini_data[$section].'data-folder' -replace ( '\\+', '\') -replace ( '//+', '/')
                data_subfolder = $ini_data[$section].'data-sub-folder'
                hide_topics    = ( $ini_data[$section].'hide-topics' -eq '1' ? 'Y' : 'N' )
                label          = $ini_data[$section].'label'
                control_peers  = ( $ini_data[$section].'control-peers' -eq '' ? -2 : $ini_data[$section].'control-peers'.ToInt16($null) )
            }
        }
        else {
            Write-Log "У раздела $_ не указан клиент, пропускаем" -Red
        }
    }
}

function Start-Rehash ( $client, $hash, [switch]$move_up ) {
    $Params = @{ hashes = $hash }
    $url = $client.ip + ':' + $client.Port + '/api/v2/torrents/recheck'
    Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
    if ( $move_up.IsPresent) {
        Start-Sleep -Seconds 1
        Write-Log 'Поднимаем раздачу в начало очереди'
        $url = $client.ip + ':' + $client.Port + '/api/v2/torrents/topPrio'
        Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
    }
}

Function DeGZip-File {
    Param(
        $infile,
        $outfile = ($infile -replace '\.gz$', '')
    )

    $inp = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
    $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
    $gzipStream = New-Object System.IO.Compression.GzipStream $inp, ([IO.Compression.CompressionMode]::Decompress)

    $buffer = New-Object byte[](1024)
    while ($true) {
        $read = $gzipstream.Read($buffer, 0, 1024)
        if ($read -le 0) { break }
        $output.Write($buffer, 0, $read)
    }

    $gzipStream.Close()
    $output.Close()
    $inp.Close()
}

function Set-Comment ( $client, $torrent, $label, [switch]$silent, $mess_sender ) {
    if (!$silent) {
        Write-Log ( "Метим раздачу меткой '$label'" )
    }
    $tag_url = $client.IP + ':' + $client.Port + '/api/v2/torrents/addTags'
    $tag_body = @{ hashes = $torrent.hash; tags = $label }
    try {
        Invoke-WebRequest -Method POST -Uri $tag_url -Headers $loginheader -Body $tag_body -WebSession $client.sid | Out-Null
    }
    catch {
        Initialize-Client -client $client -force -mess_sender $mess_sender
    }
}

function Remove-Comment ( $client, $torrent, $label, [switch]$silent ) {
    if (!$silent) {
        Write-Log ( 'Снимаем метку ' + $label )
    }
    $tag_url = $client.IP + ':' + $client.Port + '/api/v2/torrents/removeTags'
    $tag_body = @{ hashes = $torrent.hash; tags = $label }
    Invoke-WebRequest -Method POST -Uri $tag_url -Headers $loginheader -Body $tag_body -WebSession $client.sid | Out-Null
}

function Switch-Filtering ( $client, $enable = $true, $mess_sender ) {
    Set-ClientSetting $client 'ip_filter_enabled' $enable -mess_sender $mess_sender
}

function Get-DB_ColumnNames ($conn) {
    if ( ( ( Invoke-SqliteQuery -Query ( "PRAGMA table_info('topics')" ) -SQLiteConnection $conn ) | Select-Object name -ExpandProperty name | Where-Object { $_ -eq 'ss' } ).count -eq 0 ) {
        # 2.5.1 и выше
        $table_names = @{
            'id'                    = 'id'
            'forum_id'              = 'forum_id'
            'name'                  = 'name'
            'info_hash'             = 'info_hash'
            'seeders'               = 'seeders'
            'size'                  = 'size'
            'status'                = 'status'
            'reg_time'              = 'reg_time'
            'seeders_updates_today' = 'seeders_updates_today'
            'seeders_updates_days'  = 'seeders_updates_days'
            'keeping_priority'      = 'keeping_priority'
            'poster'                = 'poster'
            'seeder_last_seen'      = 'seeder_last_seen'
        }
    }
    else {
        # до 2.5.1
        $table_names = @{
            'id'                    = 'id'
            'forum_id'              = 'ss'
            'name'                  = 'na'
            'info_hash'             = 'hs'
            'seeders'               = 'se'
            'size'                  = 'si'
            'status'                = 'st'
            'reg_time'              = 'rt'
            'seeders_updates_today' = 'qt'
            'seeders_updates_days'  = 'ds'
            'keeping_priority'      = 'pt'
            'poster'                = 'ps'
            'seeder_last_seen'      = 'ls'
        }
    }
    return $table_names
}

function Get-Spell( $qty, $spelling = 1, $entity = 'torrents' ) {
    switch ( $qty % 100 ) {
        { $PSItem -in ( 5..20 ) } { return ( $entity -eq 'torrents' ? "$qty раздач" : "$qty дней" ) }
        Default {
            switch ( $qty % 10 ) {
                { $PSItem -eq 1 } { if ( $spelling -eq 1 ) { return ( $entity -eq 'torrents' ? "$qty раздача" : "$qty день" ) } else { return ( $entity -eq 'torrents' ? "$qty раздачу" : "$qty день" ) } }
                { $PSItem -in ( 2..4 ) } { return ( $entity -eq 'torrents' ? "$qty раздачи" : "$qty дня" ) }
                Default { return ( $entity -eq 'torrents' ? "$qty раздач" : "$qty дней" ) }
            }
        }
    }
}

function Get-APISeeding ( $seding_days, $call_from ) {
    $seed_dates = @{}
    foreach ( $section in $settings.sections.keys ) {
        Write-Log "Запрашиваем историю сидирования по разделу $section"
        $url = "/krs/api/v1/keeper/$($settings.connection.user_id)/reports?only_subforums_marked_as_kept=true&last_seeded_limit_days=$min_stop_to_start&last_update_limit_days=60&columns=last_seeded_time&subforum_id=$section"

        ( ( Get-RepHTTP -url $url -headers $headers -call_from $call_from ) | ConvertFrom-Json ).kept_releases | ForEach-Object {
            if ( $null -ne $_ ) { $seed_dates[$_[0]] = $_[1] }
        } 
    }
    return $seed_dates
}

function Get-RepTorrents ( $sections, $call_from, [switch]$avg_seeds, $min_avg, $min_release_days, $min_seeders ) {
    if ( $min_release_days ) { $min_release_date = (Get-Date).AddDays( 0 - $min_release_days ) }
    Write-Log 'Запрашиваем у трекера раздачи из хранимых разделов'
    $content = Get-ApiHTTP '/v1/get_tor_status_titles' -call_from $call_from
    $titles = ($content | ConvertFrom-Json -AsHashtable ).result

    if (!$titles) {
        Write-Log 'Нет связи с API трекера, выходим' -Red
        exit
    }
    $ok_states = $titles.keys | Where-Object { $titles[$_] -in ( 'не проверено', 'проверено', 'недооформлено', 'сомнительно', 'временная') }
    $tracker_torrents = @{}
    $counter = 0
    while ( $counter -lt 10 ) {
        try {
            foreach ( $section in $sections ) {
                $section_torrents = Get-RepSectionTorrents -section $section -ok_states $ok_states -call_from $call_from -avg_seeds:$avg_seeds.IsPresent -min_avg $min_avg -min_seeders $min_seeders -min_release_date $min_release_date
                $section_torrents.keys | Where-Object { $null -eq $tracker_torrents[$_] } | ForEach-Object { $tracker_torrents[$_] = $section_torrents[$_] }
                # Start-Sleep -Seconds 1
            }
            break
        }
        catch {
            Write-Log 'Похоже, наткнулись на обновление API, подождём минуту и начнём заново' -Red
            $counter++
            Start-Sleep -Seconds 60
            Write-Log "Попытка $counter"
            Remove-Variable -Name $tracker_torrents -ErrorAction SilentlyContinue
        }
    }
    return $tracker_torrents
}

function GetRepSectionKeepers( $section, $call_from ) {
    Write-Log "Выгружаем отчёты по подразделу $section"
    $url = "/krs/api/v1/subforum/$section/reports?columns=status"
    $content = ( Get-RepHTTP -url $url -headers $headers -call_from $call_from ) | ConvertFrom-Json | Select-Object kept_releases -ExpandProperty kept_releases
    return $content
}

function GetRepKeptTorrents( $sections, $call_from, $max_keepers ) {
    $keepers = @{}
    foreach ( $section in $sections ) {
        $section_keepers = GetRepSectionKeepers( $section )
        $section_keepers | Where-Object { -bnot ( $_[1] -band 0b10 ) } | ForEach-Object {
            $id = $_[0].ToInt32($null)
            if ( !$keepers[$id] ) { $keepers[$id] = 0 }
            $keepers[$id]++
        }
    }
    if ( $null -ne $max_keepers ) { $kept_ids = $keepers.keys | Where-Object { $keepers[$_] -gt $max_keepers } }
    else { $kept_ids = $keepers.keys }
    return $kept_ids
}

function Get-RepSectionTorrents( $section, $ok_states, $call_from, [switch]$avg_seeds, $min_avg, $min_release_date, $min_seeders ) {
    $use_avg_seeds = ( $avg_seeds.IsPresent ? $true : ( $ini_data.sections.avg_seeders -eq '1' ) )
    $avg_days = $ini_data.sections.avg_seeders_period
    $subst = $( $use_avg_seeds -eq 'Y' ? ',average_seeds_sum,average_seeds_count' : '')
    $url = "/krs/api/v1/subforum/$section/pvc?columns=tor_status,reg_time,topic_poster,info_hash,tor_size_bytes,keeping_priority,seeder_last_seen,seeders,topic_title,keeper_seeders$subst"
    $content = ( Get-RepHTTP -url $url -headers $headers -call_from $call_from )
    $json = $content | ConvertFrom-Json
    $columns = @{}
    $i = 0
    $json.columns | ForEach-Object { $columns[$i] = $_; $i++ }
    $line = @{}
    $line.section = $section
    $lines = @{}
    $hash_column = $columns.keys | Where-Object { $columns[$_] -eq 'info_hash' }
    $status_column = $columns.keys | Where-Object { $columns[$_] -eq 'tor_status' }
    foreach ( $release in $json.releases | Where-Object { $_[$status_column] -in $ok_states } ) {
        $j = 0
        foreach ( $field in $release ) {
            if ( $j -ne $hash_column) { $line[$columns[$j]] = $field }
            $j++
        }
        try {
            if ( $use_avg_seeds -eq 'Y' ) {
                $line.avg_seeders = ( $line.average_seeds_sum | Select-Object -First $avg_days | Measure-Object -Sum ).Sum / ( $line.average_seeds_count | Select-Object -First $avg_days | Measure-Object -Sum ).Sum
            }
            else {
                $line.avg_seeders = $line.seeders
            }
        }
        catch { $line.seeders = 0 }
        if (
                ( !$min_avg -or ( $min_avg -ge $line.avg_seeders ) ) `
                -and ( !$min_release_date -or ( $min_release_date -and $line.reg_time -le $min_release_date ) ) `
                -and ( !$min_seeders -or ( $min_seeders -and $line.seeders -ge $min_seeders ) )
        ) {
            $lines[$release[$hash_column]] = $line | Select-Object tor_status, reg_time, topic_poster, tor_size_bytes, keeping_priority, seeder_last_seen, seeders, topic_title, section, topic_id, avg_seeders, keeper_seeders
        }
    }
    Write-Log ( "По разделу $section получено раздач: $($lines.count)" ) # -skip_timestamp -nologfile
    # if ( !$lines.count ) {
    #     Write-Log 'Не получилось' -Red
    #     exit 
    # }
    return $lines
}

function Get-RepTopics( $call_from ) {
    # $headers = @{ Authorization = 'Basic ' + [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes( $id + ':' + $api_key )) }
    $url = "/krs/api/v1//subforum/report_topics"
    # return ( Get-RepHTTP -url $url -headers $headers -call_from $call_from ) | ConvertFrom-Json -AsHashtable
    return ( Get-RepHTTP -url $url -call_from $call_from ) | ConvertFrom-Json -AsHashtable
}
function Get-ForumHTTP ( $url, $body, $headers, $call_from ) {
    return Get-HTTP -url "$( $settings.connection.forum_ssl -eq 'Y' ? 'https://' : 'http://' )$($settings.connection.api_url)$url" -body $body -headers $headers -call_from $call_from -use_proxy $settings.connection.proxy.use_for_forum
}

function Get-ApiHTTP ( $url, $body, $headers, $call_from ) {
    return Get-HTTP -url "$( $settings.connection.api_ssl -eq 'Y' ? 'https://' : 'http://' )$($settings.connection.api_url)$url" -body $body -headers $headers -call_from $call_from -use_proxy $settings.connection.proxy.use_for_api
}

function Get-RepHTTP ( $url, $body, $call_from ) {
    $headers = @{}
    # if ( !$settings.connection.rep_auth ) { $settings.connection.rep_auth = @{ Authorization = 'Basic ' + [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes( $settings.connection.user_id + ':' + $settings.connection.api_key )) } }
    $headers.'Authorization' = 'Basic ' + [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes( $settings.connection.user_id + ':' + $settings.connection.api_key ))
    # $headers.'accept-encoding' = 'br'

    # return Get-HTTP -url "$( $settings.connection.report_ssl -eq 'Y' ? 'https://' : 'http://' )$($settings.connection.report_url)$url" -body $body -headers $settings.connection.rep_auth -call_from $call_from -use_proxy $settings.connection.proxy.use_for_rep
    return Get-HTTP -url "$( $settings.connection.report_ssl -eq 'Y' ? 'https://' : 'http://' )$($settings.connection.report_url)$url" -body $body -headers $headers -call_from $call_from -use_proxy $settings.connection.proxy.use_for_rep
}

function Set-Proxy( $settings ) {
    if ( $settings.connection.proxy.use_for_forum -eq 'Y' -or $settings.connection.proxy.use_for_api -eq 'Y' -or $settings.connection.proxy.use_for_rep -eq 'Y' ) {
        $settings.connection.proxy.url = ( $settings.connection.proxy.type -like 'socks*' ? 'socks5://' : 'http://' ) + $settings.connection.proxy.ip + ':' + $settings.connection.proxy.port
        if ( $settings.connection.proxy.ip -and $settings.connection.proxy.password -and $settings.connection.proxy.password -ne '') {
            $proxy_pass = ConvertTo-SecureString $settings.connection.proxy.password -AsPlainText -Force
            $settings.connection.proxy.credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $settings.connection.proxy.login, $proxy_pass
        }
    }
}

function Get-HTTP ( $url, $body, $headers, $call_from, $use_proxy ) {
    $retry_cnt = 1
    while ( $true ) {
        try {
            if ( $use_proxy -eq "Y" ) {
                if ( $request_details -eq 'Y' ) { Write-Log "Идём на $url используя прокси $($settings.connection.proxy.url )" }
                if ( $settings.connection.proxy.credentials ) {
                    $result = ( Invoke-WebRequest -Uri $url -Headers $headers -Proxy $settings.connection.proxy.url -ProxyCredential $settings.connection.proxy.credentials -Body $body `
                            -UserAgent "PowerShell/$($PSVersionTable.PSVersion)-$call_from-on-$($PSVersionTable.Platform)" -OperationTimeoutSeconds 20 ).Content
                    return $result
                }
                else {
                    $result = ( Invoke-WebRequest -Uri $url -Headers $headers -Proxy $settings.connection.proxy.url -Body $body `
                            -UserAgent "PowerShell/$($PSVersionTable.PSVersion)-$call_from-on-$($PSVersionTable.Platform)" -OperationTimeoutSeconds 20 ).Content
                    return $result
                }
            }
            else {
                if ( $request_details -eq 'Y' ) { Write-Log "Идём на $url без прокси" }
                $result = ( Invoke-WebRequest -Uri $url -Headers $headers -Body $body -UserAgent "PowerShell/$($PSVersionTable.PSVersion)-$call_from-on-$($PSVersionTable.Platform)" -OperationTimeoutSeconds 20 ).Content 
                return $result
            }
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
    Write-Log 'Не удалось получить данные, выходим досрочно' -Red
}

function Get-DiskTypes {
    Write-Log 'Получаем типы физических накопителей'
    $disk_hash = @{}
    Get-PhysicalDisk | ForEach-Object {
        $physicalDisk = $_
        $physicalDisk | Get-Disk | Get-Partition | Where-Object DriveLetter | ForEach-Object {
            $disk_hash[$_.DriveLetter] = $physicalDisk.MediaType
        }
    }
    return $disk_hash
}

function  Get-SpokenInterval ( $start_date, $end_date ) {
    
    $Duration = New-TimeSpan -Start $start_date -End $end_date
    $day_cnt = [Math]::Round( $duration.Days)
    $Day = ( Get-Spell -qty $day_cnt -spelling 1 -entity 'days' )
    return $Day
}

function Send-HTTP ( $url, $body, $headers, $call_from ) {
    $retry_cnt = 1
    while ( $true ) {
        try {
            if ( [bool]$ConnectDetails.ProxyURL -and $ConnectDetails.UseApiProxy -eq 1 ) {
                if ( $ConnectDetails.proxyCred ) {
                    Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Proxy $ConnectDetails.ProxyURL -ProxyCredential $ConnectDetails.proxyCred -Body $body `
                        -UserAgent "PowerShell/$($PSVersionTable.PSVersion)-$call_from-on-$($PSVersionTable.Platform)" | Out-Null
                    return
                }
                else {
                    Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Proxy $ConnectDetails.ProxyURL -Body $body -UserAgent "PowerShell/$($PSVersionTable.PSVersion)-$call_from-on-$($PSVersionTable.Platform)" | Out-Null
                    return
                }
            }
            else {
                Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -UserAgent "PowerShell/$($PSVersionTable.PSVersion)-$call_from-on-$($PSVersionTable.Platform)" | Out-Null
                return
            }
        }
        catch {
            Start-Sleep -Seconds 10; $retry_cnt++; Write-Log "Попытка номер $retry_cnt"
            If ( $retry_cnt -gt 10 ) { return }
        }
    }
    Write-Log 'Не удалось отправить данные, выходим досрочно' -Red
}
    
function Send-APIReport ( $sections, $id, $api_key, $call_from) {
    Write-Log 'Отправляем список хранимых подразделов'
    $headers = @{
        Authorization = 'Basic ' + [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes( $id + ':' + $api_key ))
    }
    $sections | ForEach-Object { 
        $body = @{
            'keeper_id'   = $id
            'subforum_id' = $_
            'status'      = 1
        }
    
        Send-HTTP -url "https://rep.rutracker.cc/krs/api/v1/subforum/set_status?keeper_id=$id&subforum_id=$_&status=1" -headers $headers -call_from $call_from
    }
    Write-Log 'Отправлям список хранимых раздач'
}

function Select-Client {
    $backmap = @{}
    $settings.clients.keys | ForEach-Object {
        $backmap[$settings.clients[$_].seqno] = $_
        Write-Host "$( $settings.clients[$_].seqno ) . $_"
    }
    $ok2 = $false
    while ( !$ok2 ) {
        $choice = Read-Host Выберите клиент
        if (  $backmap[$choice.ToInt32($null )] ) { $ok2 = $true }
    }
    return $settings.clients[$backmap[$choice.ToInt32($null )]]
}

function Select-Path ( $direction ) {
    if ( $direction -eq 'from' ) {
        $default = 'Хранимое'
        $str = "Выберите исходный кусок пути [$default]"
    }
    else {
        $default = 'Хранимые'
        $str = "Выберите целевой кусок пути [$default]"
    } 
    $choice = Read-Host $str
    $result = ( $default, $choice )[[bool]$choice]
    return $result
}

function Get-String ( [switch]$obligatory, $prompt ) { 
    while ( $true ) {
        $choice = ( Read-Host $prompt )
        if ( $nul -ne $choice -and $choice -ne '') { break }
        elseif ( !$obligatory ) { break }
    }
    if ( $choice ) { return $choice } else { return '' }
}

function  Set-SaveLocation ( $client, $torrent, $new_path, $verbose = $false, $mess_sender ) {
    if ( $verbose ) { Write-Host ( 'Перемещаем ' + $torrent.name + ' в ' + $new_path) }
    $data = @{
        hashes   = $torrent.hash
        location = $new_path
    }
    try {
        Invoke-WebRequest -Uri ( $client.ip + ':' + $client.Port + '/api/v2/torrents/setLocation' ) -WebSession $client.sid -Body $data -Method POST | Out-Null
    }
    catch {
        $client.sid = $null
        Initialize-Client -client $client -mess_sender $mess_sender -force -verbose
        Invoke-WebRequest -Uri ( $client.ip + ':' + $client.Port + '/api/v2/torrents/setLocation' ) -WebSession $client.sid -Body $data -Method POST | Out-Null
    }
}

function Get-ClientApiVersions ( $clients, $mess_sender ) {
    Write-Log 'Получаем версии API клиентов для правильной работы с ними'
    foreach ( $client_key in ( $clients.keys | Where-Object { $null -eq $clients[$_].api_verion } ) ) {
        $client = $clients[$client_key]
        Initialize-Client $client -mess_sender $mess_sender -verbose
        $client.api_version = [version]( Invoke-WebRequest -Uri ( $client.IP + ':' + $client.port + '/api/v2/app/webapiVersion' ) -WebSession $client.sid ).content
        Write-Log "У клиента $( $client.name ) версия API $($client.api_version.ToString())"
        if ( $client.api_version -lt [version]'2.11.0' ) {
            $client.start_command = 'resume'
            $client.stop_command = 'pause'
            $client.stopped_state = 'pausedUP'
            $client.stopped_state_dl = 'pausedDL'
        }
        else {
            $client.start_command = 'start'
            $client.stop_command = 'stop'
            $client.stopped_state = 'stoppedUP'
            $client.stopped_state_dl = 'stoppedDL'
        }
    }
}