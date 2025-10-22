function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$str,
        [switch]$Red,
        [switch]$Green,
        [switch]$Yellow,
        [switch]$NoNewLine,
        [switch]$skip_timestamp,
        [switch]$nologfile
    )

    $color = $( $Red.IsPresent ? [System.ConsoleColor]::Red : $( $Green.IsPresent ? [System.ConsoleColor]::Green : $( $Yellow.IsPresent ? [System.ConsoleColor]::Yellow : $null ) ) )
    $log_str = ''
    if ( $settings.interface.use_timestamp -eq 'Y' ) {
        $log_str = "$( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) "
        if ( $color ) { Write-Host $log_str -NoNewline -ForegroundColor $color }
        else { Write-Host "$( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) " -NoNewline }
    }
    
    if ( $mention_script_log -eq 'Y') {
        $call_stack = Get-PSCallStack
        $script_name = "#$($call_stack[$call_stack.length - 1].command.replace( '.ps1', '')) "
        if ( $script_name -eq '#<ScriptBlock> ' ) {
            $script_name = "#$($call_stack[$call_stack.length - 2].command.replace( '.ps1', '')) "
        }
        $log_str += $script_name
        Write-Host $script_name -ForegroundColor Green -NoNewline
    }
    $log_str += $str
    if ( $color ) { Write-Host $str -NoNewline:$NoNewLine -ForegroundColor $color }
    else { Write-Host $str -NoNewline:$NoNewLine }
    if ( $log_path -and -not $nologfile.IsPresent ) { Write-Output ( $log_str.Replace('...', '') | Out-File $log_path -Append -Encoding utf8 ) | Out-Null }
}


function Test-PSVersion {
    param(
        [version]$MinimumVersion = [version]'7.1.0.0'
    )
    Write-Log 'Проверяем версию Powershell...'
    if ( $PSVersionTable.PSVersion -lt $MinimumVersion ) {
        Write-Log "У вас слишком древний Powershell, обновитесь с https://github.com/PowerShell/PowerShell#get-powershell " -Red
        Read-Host -Prompt "Нажмите Enter для выхода"
        exit
    }
    else {
        Write-Log "Версия достаточно свежая ( $($PSVersionTable.PSVersion) >= $MinimumVersion ), продолжаем" -Green
    }
}

function Get-Separator {
    return [IO.Path]::DirectorySeparatorChar
}

function Test-Version {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("\.ps1$")]
        [string]$name,
        [string]$mess_sender = ''
    )
    try {
        $old_hash = ( Get-FileHash -Path ( Join-Path $PSScriptRoot $name ) ).Hash
        $new_file_path = ( Join-Path $PSScriptRoot $name.replace( '.ps1', '.new' ) )
        Invoke-WebRequest -Uri ( 'https://raw.githubusercontent.com/Another-1/RT_Pack/main/' + $name ) -OutFile $new_file_path -TimeoutSec 30 | Out-Null
        # if ( req.StatusCode -eq 200 ) {
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
        # }
    }
    catch {
        Write-Log "[Test-Version] Ошибка: $($_.Exception.Message) при обновлении $name" -Red
    }
}

function Test-Module {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$module,
        [string]$description = ''
    )
    Write-Log "Проверяем наличие модуля $module $description"
    try {
        if ( -not ( [bool](Get-InstalledModule -Name $module -ErrorAction SilentlyContinue) ) ) {
            Write-Log "Не установлен модуль $module $description, ставим" -Red
            if ( $module -eq 'PsIni') {
                Install-Module -Name $module -MaximumVersion 3.6.3 -Scope CurrentUser -Force
            }
            else {
                Install-Module -Name $module -Scope CurrentUser -Force
            }
        }
        Write-Log "Модуль $module обнаружен" -Green
        Import-Module $module -ErrorAction Stop
    }
    catch {
        Write-Log "[Test-Module] Ошибка при установке или импорте модуля $($module): $($_.Exception.Message)" -Red
    }
}

function Test-Setting {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$setting,
        [switch]$required,
        $default = $null,
        [switch]$no_ini_write,
        $json_section = $null
    )
    $set_names = @{
        'tg_token'              = @{ prompt = 'Токен бота Telegram, если нужна отправка событий в Telegram. Если не нужно, оставить пустым'; default = ''; type = 'string' }
        'tg_chat'               = @{ prompt = 'Номер чата для отправки сообщений Telegram'; default = ''; type = 'string' }
        'alert_oldies'          = @{ prompt = 'Уведомлять о новых версиях скриптов в Telegram? (нужен свой бот ТГ!)'; default = 'Y'; type = 'YN' }
        'use_timestamp'         = @{ prompt = 'Выводить дату-время в окне лога Adder?'; default = 'N'; type = 'YN' }
        'tlo_path'              = @{ prompt = 'Путь к папке Web-TLO'; default = 'C:\OpenServer\domains\webtlo.local'; type = 'string' }
        'get_blacklist'         = @{ prompt = 'Скачивать раздачи из чёрного списка Web-TLO?'; default = 'N'; type = 'YN' }
        'max_seeds'             = @{ prompt = 'Максимальное кол-во сидов для скачивания раздачи'; default = -1; type = 'float' }
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
        'error_tag'             = @{ prompt = 'Тег для ошибочных раздач'; type = 'string' }
        'stalled_pwd'           = @{ prompt = 'Пароль для отправки некачашек (см. у бота Кузи в /about_me)'; type = 'string' }
        'id_subfolder'          = @{ prompt = 'Создавать папки по ID если нет?'; type = 'YN' }
    }
    if (-not $set_names.ContainsKey($setting)) {
        Write-Log "[Test-Setting] Ошибка: '$setting' не является допустимым параметром настройки." -Red
        return $null
    }
    $changed = $false
    if ( $json_section -and $json_section -ne '' ) {
        try { $current_var = $settings.$json_section.$setting } catch { Write-Log "[Test-Setting] Ошибка доступа к $($json_section).$($setting): $($_.Exception.Message)" -Red }
    }
    else {
        try { $current_var = ( Get-Variable -Name $setting -ErrorAction SilentlyContinue ) } catch { Write-Log "[Test-Setting] Ошибка доступа к переменной $($setting): $($_.Exception.Message)" -Red }
    }
    if ( $current_var -and $null -ne $current_var.Value ) { $current = $current_var.Value }
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
                if ( -not ( Test-Path $ini_path ) ) {
                    Write-Log ( 'Не нахожу файла ' + ( $ini_path ) + ', проверьте ввод' ) -Red
                    $current = ''
                }
                else { 
                    $changed = $true
                }
            }
            elseif ( $setting -like '*php_path' ) {
                if ( -not ( Test-Path $current ) ) {
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
            if ( $set_names[$setting].type -eq ( 'number' ) -or $set_names[$setting].type -eq ( 'float' ) ) {
                if ( $set_names[$setting].type -eq ( 'float' ) ) {
                    try { 
                        $current = $current.replace(',', '.').ToSingle( $null )
                    }
                    catch {
                        $current = $current.replace('.', ',').ToSingle( $null )
                    }
                }
                else {
                    $current = $current.ToInt64( $null )
                }
            }
            try {
                Set-Variable -Name $setting -Value $current
            }
            catch { Write-Log "[Test-Setting] Ошибка при установке переменной $($setting): $($_.Exception.Message)" -Red }
            if ( $no_ini_write.IsPresent -eq $false -and $standalone -eq $false ) {
                try {
                    Add-Content -Path ( Join-Path $PSScriptRoot '_settings.ps1' ) `
                        -Value ( '$' + $setting + ' = ' + $( ( $set_names[$setting].type -in ( 'YN', 'string' ) ) ? "'" : '') + $current + $( ( $set_names[$setting].type -in ( 'YN', 'string' ) ) ? "'" : '') + '   # ' + $set_names[$setting].prompt )
                }
                catch { Write-Log "[Test-Setting] Ошибка при записи в _settings.ps1: $($_.Exception.Message)" -Red }
            }
        }
    }
    return $current
}

function Test-ForumWorkingHours ( [switch]$verbose, [switch]$break ) {
    try {
        $MoscowTZ = [System.TimeZoneInfo]::FindSystemTimeZoneById("Russian Standard Time")
    }
    catch {
        Write-Log "[Test-ForumWorkingHours] Ошибка: Не удалось найти часовой пояс 'Russian Standard Time': $($_.Exception.Message)" -Red
        if ($break.IsPresent) { exit }
        # return $false
    }
    $MoscowTime = [System.TimeZoneInfo]::ConvertTimeFromUtc((Get-Date).ToUniversalTime(), $MoscowTZ)
    if ($verbose) {
        Write-Log 'Проверяем, что в Москве не 4 часа ночи (профилактика)'
        Write-Log ( 'Московское время ' + ( Get-Date($MoscowTime) -UFormat %H ) + ' ч ' + ( Get-Date($MoscowTime) -UFormat %M ) + ' мин' )
    }
    if ( ( Get-Date($MoscowTime) -UFormat %H ) -eq '04' ) {
        if ( $use_working_minutes -ne 'Y' -or ( Get-Date($MoscowTime) -UFormat %M ) -in 35..45 ) {
            Write-Log 'Профилактические работы на сервере' -Red
            if ( $break.IsPresent ) {
                exit
            }
            else { return $false }
        }
    }
    if ( -not $break.IsPresent ) { return $true }
}

function Set-ConnectDetails ( $settings ) {

    if ( !$settings.connection ) { $settings.connection = [ordered]@{} }
    $settings.connection.login = $ini_data.'torrent-tracker'.login
    $settings.connection.password = $ini_data.'torrent-tracker'.password.replace( '\\', '\' )
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

    if ( $ini_data.proxy.activate_forum -eq '1' -or $ini_data.proxy.activate_api -eq '1' -or $ini_data.proxy.activate_report -eq '1' ) {
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
    $ini_data.keys | Where-Object { $_ -match '^torrent-client' -and $ini_data[$_].client -eq 'qbittorrent' } | Sort-Object -Property { $ini_data[$_].comment } | ForEach-Object {
        if ( ( $_ | Select-String ( '\d+$' ) ).matches.value.ToInt16($null) -le $client_count ) {
            $settings.clients[$ini_data[$_].comment] = [ordered]@{
                IP            = $ini_data[$_].hostname
                port          = $ini_data[$_].port
                login         = $ini_data[$_].login
                password      = $ini_data[$_].password
                id            = $ini_data[$_].id
                seqno         = $i
                name          = $ini_data[$_].comment
                ssl           = $ini_data[$_].ssl
                control_peers = $ini_data[$_].control_peers ? $ini_data[$_].control_peers.ToInt32($null) : -2
            }
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

function Initialize-Client ( $client, $mess_sender = '', [switch]$verbos, [switch]$force ) {
    if ( !$client.sid -or $force ) {
        $logindata = @{ username = $client.login; password = $client.password }
        $loginheader = @{ Referer = 'http://' + $client.IP + ':' + $client.port }
        try {
            if ( $verbos ) { Write-Log ( 'Авторизуемся в клиенте ' + $client.Name ) }
            $url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.port + '/api/v2/auth/login'
            $result = Invoke-WebRequest -Method POST -Uri $url -Headers $loginheader -Body $logindata -SessionVariable sid
            if ( $result.StatusCode -ne 200 ) {
                Write-Log 'You are banned.' -Red
                exit
            }
            if ( $result.Content.ToUpper() -ne 'OK.') {
                Write-Log ( 'Клиент вернул ошибку авторизации: ' + $result.Content ) -Red
                exit
            }
            if ( $verbos ) { Write-Log 'Успешная авторизация' }
            $client.sid = $sid
        }
        catch {
            Write-Log ( '[client] Не удалось авторизоваться в клиенте, прерываем. Ошибка: {0}.' -f $Error[0] ) -Red
            if ( $tg_token -ne '' ) {
                $( (Get-PSCallStack)[(( Get-PSCallStack ).count - 1 )..0].Command | Where-Object { $null -ne $_ } | Join-String -Separator ' → ' )
                Send-TGMessage "Нет связи с клиентом $( $client.Name ) при вызыве из $( (Get-PSCallStack)[(( Get-PSCallStack ).count - 1 )..0].Command | Where-Object { $null -ne $_ -and $_ -ne '<ScriptBlock>'} | `
                    Join-String -Separator ' → ' ). Процесс остановлен." $tg_token $tg_chat $mess_sender
            }
            exit
        }
    }
}

function Export-ClientTorrentFile ( $client, $hash, $save_path ) {
    if ( !$client.sid -or $force ) {
        Initialize-Client $client
    }
    $data = @{ hash = $hash }
    Write-Log "Экспортируем торрент из клиента $($client.name) в файл $save_path"
    $uri = ( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.port + '/api/v2/torrents/export'
    Invoke-WebRequest -Uri $uri -Body $data -WebSession $client.sid -OutFile $save_path
}


function Get-ClientTorrents {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$client,
        [string]$disk = '',
        [string]$mess_sender = '',
        [switch]$completed,
        $hash = $null,
        [switch]$verbos,
        [switch]$break
    )
    # Validate required client properties
    # foreach ($prop in @('IP','port','sid','name')) {
    #     if (-not $client.PSObject.Properties[$prop]) {
    #         Write-Log "[Get-ClientTorrents] Ошибка: client не содержит свойство '$prop'" -Red
    #         return @()
    #     }
    # }
    $Params = @{}
    if ( $completed ) {
        $Params.filter = 'completed'
    }
    if ( $null -ne $hash ) {
        $Params.hashes = $hash
        if ( $verbos ) { Write-Log ( "Получаем инфо о раздаче $hash из клиента " + $client.name ) }
    }
    elseif ( $verbos ) { Write-Log ( 'Получаем список раздач от клиента ' + $client.name ) }
    if ( $null -ne $disk -and $disk -ne '') { $dsk = $disk + ':\\' } else { $dsk = '' }
    $i = 0
    while ( $true ) {
        try {
            $json_content = ( Invoke-WebRequest -Uri ( $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.port + '/api/v2/torrents/info' ) -WebSession $client.sid -Body $params -TimeoutSec 120 ).Content
            $torrents_list = $json_content | ConvertFrom-Json | `
                Select-Object name, hash, save_path, content_path, category, state, uploaded, @{ N = 'topic_id'; E = { $nul } }, @{ N = 'client_key'; E = { $client.name } }, infohash_v1, size, completion_on, progress, tracker, added_on, tags, download_path, last_activity | `
                Where-Object { $_.save_path -match ('^' + $dsk ) }
        }
        catch {
            Write-Log "[Get-ClientTorrents] Ошибка при получении списка раздач: $($_.Exception.Message)" -Red
            if ( $verbos.IsPresent ) {
                Initialize-Client $client $mess_sender -force -verbos
            }
            else {
                Initialize-Client $client $mess_sender -force
            }
            $i++
        }
        if ( $json_content -or $i -gt 3 ) { break }
    }
    if ( !$json_content -and !$hash ) {
        if ( $tg_token -ne '' ) { 
            Send-TGMessage -message ( 'Не удалось получить список раздач от клиента ' + $client.Name + ', Выполнение прервано.' ) -token $tg_token -chat_id $tg_chat -mess_sender $mess_sender
        }
        Write-Log ( 'Не удалось получить список раздач от клиента ' + $client.Name ) -Red
        if ( $break.IsPresent ) {
            exit
        }
    }
    if ( !$torrents_list ) { $torrents_list = @() }
    if ( $verbos.IsPresent ) {
        if ( !$hash ) { Write-Log ( 'Получено от клиента ' + $client.Name + ': ' + ( Get-Spell -qty $torrents_list.Count ) ) }
    }
    return $torrents_list
}

function Get-ClientsTorrents ( $mess_sender = '', [switch]$completed, [switch]$noIDs, [switch]$break, $clients ) {
    $clients_torrents = @()
    if ( !$clients ) { $clients = $settings.clients }
    foreach ($clientkey in $settings.clients.Keys ) {
        $client = $settings.clients[ $clientkey ]
        Initialize-Client $client $mess_sender -verbos
        $client_torrents = Get-ClientTorrents -client $client -verbos -completed:$completed -mess_sender $mess_sender -break:$break.IsPresent
        if ( $noIDs.IsPresent -eq $false -and $client_torrents.count -gt 0 ) {
            Get-TopicIDs -client $client -torrent_list $client_torrents # -conn $db_conn
        }
        $clients_torrents += $client_torrents
    }
    if ( $db_conn ) { $db_conn.Close() }
    return $clients_torrents
}

function Get-ClientTorrentInfo( $client, $hash ) {
    $Params = @{ hash = $hash }
    return ( Invoke-WebRequest -Uri ( $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.port + '/api/v2/torrents/properties' ) -WebSession $client.sid -Body $params ).Content | ConvertFrom-Json
}

function Get-DBHashToId ( $conn ) {
    $db_hash_to_id = @{}
    $query = 'SELECT info_hash, topic_id FROM Torrents'
    Invoke-SqliteQuery -Query $query -SQLiteConnection $conn -ErrorAction SilentlyContinue | ForEach-Object { $db_hash_to_id[$_.info_hash] = $_.topic_id }
    return $db_hash_to_id
}
function Get-DBHashToClient ( $conn ) {
    $db_hash_to_client = @{}
    $query = 'SELECT info_hash, client_id FROM Torrents'
    Invoke-SqliteQuery -Query $query -SQLiteConnection $conn -ErrorAction SilentlyContinue | ForEach-Object { $db_hash_to_client[$_.info_hash] = $_.client_id }
    return $db_hash_to_client
}
function Get-TopicIDs {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$client,
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [array]$torrent_list,
        [switch]$verbos
    )
    # Validate required client property
    # if (-not $client.PSObject.Properties['name']) {
    #     Write-Log "[Get-TopicIDs] Ошибка: client не содержит свойство 'name'" -Red
    #     return
    # }
    # # Validate torrent_list items
    # foreach ($t in $torrent_list) {
    #     if (-not $t.PSObject.Properties['hash']) {
    #         Write-Log "[Get-TopicIDs] Ошибка: элемент списка не содержит свойство 'hash'" -Red
    #         return
    #     }
    # }
    if ( $torrent_list.count -gt 0 ) {
        if ( $verbos.IsPresent ) {
            Write-Log "Ищем ID раздач по $( $torrent_list.count -gt 1 ? 'хэшам' : 'хэшу ' + $torrent_list[0].hash ) от клиента $( $client.name ) в данных от трекера"
        }
        $torrent_list | ForEach-Object {
            if ( $null -ne $tracker_torrents ) { $_.topic_id = [Int64]$tracker_torrents[$_.hash.toUpper()].topic_id }
            if ( ( $null -eq $_.topic_id -or $_.topic_id -eq '' ) -and $null -ne $db_hash_to_id ) {
                $_.topic_id = $db_hash_to_id[$_.hash]  
            }
            if ( $null -eq $_.topic_id -or $_.topic_id -eq '' ) {
                try {
                    $comment = ( Get-ClientTorrentInfo -client $client -hash $_.hash ) | Select-Object comment -ExpandProperty comment
                    Start-Sleep -Milliseconds 10
                }
                catch {
                    Write-Log "[Get-TopicIDs] Ошибка при получении комментария для $_.hash: $($_.Exception.Message)" -Red
                }
                $ending = ( Select-String "\d*$" -InputObject $comment ).Matches.Value
                $_.topic_id = $( $ending -ne '' ? $ending.ToInt64($null) : $null )
            }
        }
        $success = ( $torrent_list | Where-Object { $_.topic_id } ).count
        if ( $verbos.IsPresent ) {
            Write-Log ( 'Найдено ' + $success + ' штук ID' ) -Red:( $success -ne $torrent_list.Count )
        }
    }
}

function Get-TorrentsContent ( $client, $hashes ) {
    $arr = [System.Collections.ArrayList]::new()
    $i = 0
    $batch_size = [math]::ceiling( $hashes.count / 100 )
    for ( $j = 0; $j -lt $hashes.count; $j += $batch_size ) {
        Write-Progress -Activity 'Scanning' -Status $j -PercentComplete ( $i )
        $batch_arr = [System.Collections.ArrayList]::new()
        $batch_hashes = $hashes[ $j.. ( $j + $batch_size - 1 ) ]
        $batch_hashes | ForEach-Object {
            $Params = @{ hash = $_ }
            try {
                $save_path = ( ( Invoke-WebRequest -Uri ( $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.port + '/api/v2/torrents/properties' ) -WebSession $client.sid -Body $params ).Content | ConvertFrom-Json ).save_path
                $files = ( Invoke-WebRequest -Uri ( $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.port + '/api/v2/torrents/files' ) -WebSession $client.sid -Body $params ).Content | ConvertFrom-Json
                $files | ForEach-Object { $batch_arr += ( Join-Path $save_path $_.name ) }
            }
            catch { }
        }
        # $arr += $batch_arr.GetEnumerator()
        $arr += $batch_arr
        $i++
    }
    Write-Progress -Activity 'Scanning' -Completed
    return $arr
}

function Get-TorrentPeers ( $client, $hash, [switch]$force ) {
    if ( !$client.sid -or $force ) {
        Initialize-Client $client
    }
    $data = @{ hash = $hash }
    $uri = ( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.port + '/api/v2/sync/torrentPeers'
    return Invoke-WebRequest -Uri $uri -Body $data -WebSession $client.sid
}

function Lock-IP ( $client, $ip ) {
    if ( !$client.sid -or $force ) {
        Initialize-Client $client
    }
    $data = @{ peers = "$($ip):1000" }
    $uri = ( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.port + '/api/v2/transfer/banPeers'
    Invoke-WebRequest -Uri $uri -Body $data -WebSession $client.sid -Method Post | Out-Null
}

function Get-ClientTrackerStatus ( $client, $torrent_list, [switch]$verbose ) {
    if ( $torrent_list.count -gt 0 ) {
        if ( $verbose.IsPresent ) {
            Write-Log "Ищем трекеры раздач по $( $torrent_list.count -gt 1 ? 'хэшам' : 'хэшу ' + $torrent_list[0].hash ) в клиенте $( $client.name )"
        }
        $torrent_list | ForEach-Object {
            $Params = @{ hash = $_.hash }
            try {
                # $_.tracker_status = `
                $tracker = ( Invoke-WebRequest -Uri ( $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.port + '/api/v2/torrents/trackers' ) -WebSession $client.sid -Body $params ).Content | ConvertFrom-Json | Where-Object { $_.url -like '*rutracker.cx*' }
                if ( $tracker.status -eq 4 -and $tracker.msg -eq 'Torrent not registered') {
                    $_ | Add-Member -NotePropertyName tracker_status -Force -NotePropertyValue $tracker.status
                    Start-Sleep -Milliseconds 10
                }
            }
            catch { }
            # $ending = ( Select-String "\d*$" -InputObject $comment ).Matches.Value
        }
    }
}

function Add-ClientTorrent ( $Client, $file, $path, $category, $mess_sender = '', [switch]$Skip_checking, [switch]$addToTop, [switch]$paused, $hash = $null ) {
    $Params = @{
        category        = $category
        name            = 'torrents'
        root_folder     = 'false'
        paused          = $Paused
        stopped         = $Paused
        skip_checking   = $Skip_checking
        addToTopOfQueue = $addToTop
    }

    if ( $path -and $null -ne $path ) { $Params.savepath = $path }
    if ( $null -ne $file ) {
        $params.torrents = Get-Item $file
        Write-Log "Отправляем скачанный torrent-файл раздачи $( $file.basename ) в клиент $( $client.name )"
    }
    elseif ( $null -ne $hash ) {
        $params.urls = "magnet:?xt=urn:btih:$hash&tr=http%3A%2F%2Fbt.t-ru.org%2Fann%3Fmagnet&tr=http%3A%2F%2Fbt2.t-ru.org%2Fann%3Fmagnet&tr=http%3A%2F%2Fbt3.t-ru.org%2Fann%3Fmagnet&tr=http%3A%2F%2Fbt4.t-ru.org%2Fann%3Fmagnet"
        Write-Log "Отправляем хэш раздачи $hash в клиент $( $client.name )"
    }

    $url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.ip + ':' + $client.Port + '/api/v2/torrents/add'
    $added_ok = $false
    $abort = $false
    $i = 1
    while ( $added_ok -eq $false -and $abort -eq $false ) {
        if ( $i -gt 1 ) {
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
                Write-Log "Ошибка при добавлении раздачи в клиент $($client.name): $($error[0]) " -Red
                if (  $error[0] -like '*is not a valid torrent file*' -or $error[0] -like '*допустимым торрент-файлом*') {
                    $badTorrFolder = Join-Path $PSScriptRoot 'BadTorrents'
                    New-Item -Path $badTorrFolder -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
                    Copy-Item $file $badTorrFolder -Force -ErrorAction SilentlyContinue
                    Write-Log "Торрент-файл $($file.name) перемещён в папку $badTorrFolder для анализа"
                }
                continue
                # Initialize-Client -client $client -mess_sender $mess_sender -force -verbose
                # Start-Sleep -Seconds 1
            }
        }
    }
    if ( $file ) { Remove-Item $File -ErrorAction SilentlyContinue | Out-Null }
    return $added_ok
}

function Set-ClientSetting ( $client, $param, $value, $mess_sender ) {
    $url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.ip + ':' + $client.Port + '/api/v2/app/setPreferences'
    $param = @{ json = ( @{ $param = $value } | ConvertTo-Json -Compress ) }
    try { Invoke-WebRequest -Uri $url -WebSession $client.sid -Body $param -Method POST | Out-Null }
    catch {
        Initialize-Client -client $client -mess_sender $mess_sender -verbos
        Invoke-WebRequest -Uri $url -WebSession $client.sid -Body $param -Method POST | Out-Null 
    }
}

function Set-MaxTorrentPriority ( $client, $hash ) {
    $param = @{ hashes = $hash }
    $url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.ip + ':' + $client.Port + '/api/v2/torrents/topPrio'
    try { Invoke-WebRequest -Uri $url -WebSession $client.sid -Body $param -Method POST | Out-Null }
    catch {
        Initialize-Client -client $client -mess_sender $mess_sender -verbos
        Invoke-WebRequest -Uri $url -WebSession $client.sid -Body $param -Method POST | Out-Null 
    }
}

function Set-DlSpeedLimit ( $client, $hash, $limit ) {
    $param = @{ hashes = $hash; limit = $limit }
    $url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.ip + ':' + $client.Port + '/api/v2/torrents/setDownloadLimit'
    try { Invoke-WebRequest -Uri $url -WebSession $client.sid -Body $param -Method POST | Out-Null }
    catch {
        Initialize-Client -client $client -mess_sender $mess_sender -verbos
        Invoke-WebRequest -Uri $url -WebSession $client.sid -Body $param -Method POST | Out-Null 
    }
}
function Initialize-Forum {
    param(
        [string]$login = $null,
        [string]$password = $null,
        [switch]$noretry
    )
    # Check for required connection settings
    if ( !$settings.connection ) {
        Write-Log 'Не обнаружены данные для подключения к форуму. Проверьте настройки.' -ForegroundColor Red
        exit
    }
    Write-Log "Авторизуемся на форуме под пользователем $login."

    $login_url = $( $settings.connection.forum_ssl -eq 'Y' ? 'https://' : 'http://' ) + $settings.connection.forum_url + '/forum/login.php'
    $headers = @{ 'User-Agent' = 'Mozilla/5.0' }
    if ( !$login ) {
        $payload = @{ 'login_username' = $settings.connection.login; 'login_password' = $settings.connection.password; 'login' = '%E2%F5%EE%E4' }
    }
    else {
        $payload = @{ 'login_username' = $login; 'login_password' = $password; 'login' = '%E2%F5%EE%E4' }
    }
    $i = 1
    $max_tries = $noretry.IsPresent ? 1 : 10
    $answer = $null
    while ($i -le $max_tries) {
        if ( $i -gt 1 ) { Write-Log "Попытка номер $i" }
        try {
            if ( $settings.connection.proxy.use_for_forum.ToUpper() -eq 'Y' -and $settings.connection.proxy.ip -and $settings.connection.proxy.ip -ne '' ) {
                if ( $request_details -eq 'Y' ) { Write-Log "Идём на $login_url используя прокси $($settings.connection.proxy.url )" }
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
        }
        catch {
            Write-Log "[Initialize-Forum] Не удалось соединиться с форумом: $($_.Exception.Message)" -Red
            Start-Sleep -Seconds 10; $i++
            if ( $i -gt $max_tries ) { return }
            continue
        }
        if ( -not $answer ) {
            Write-Log '[Initialize-Forum] Нет ответа от форума.' -Red
            Start-Sleep -Seconds 10; $i++
            if ( $i -gt $max_tries ) { return }
            continue
        }
        if ( $answer.StatusCode -ne 200 ) {
            Write-Log "Форум вернул ответ $($answer.StatusCode)" -Red
            Start-Sleep -Seconds 10; $i++
            if ( $i -gt $max_tries ) { return }
            continue
        }
        if ( $sid.Cookies.Count -eq 0 ) {
            Write-Log 'Форум не вернул cookie' -Red
            Start-Sleep -Seconds 10; $i++
            if ( $i -gt $max_tries ) { return }
            continue
        }
        if ( $answer.content -like '*Вы ввели неверное*' -or $answer.content -like '*введите код подтверждения*' ) {
            Write-Log 'Неверный пароль' -Red
            return
        }
        # Success
        break
    }
    if ( -not $answer -or $answer.StatusCode -ne 200 ) {
        Write-Log '[Initialize-Forum] Не удалось авторизоваться на форуме.' -Red
        return
    }
    if ( $sid.Cookies.Count -eq 0 ) {
        Write-Log '[Initialize-Forum] Не удалось получить cookie после авторизации.' -Red
        return
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

function Send-Forum ( $mess, $post_id, $topic_id = $null ) {
    if ( !$settings.connection ) {
        Write-Log 'Не обнаружены данные для подключения к форуму. Проверьте настройки.' -ForegroundColor Red
        exit
    }
    if ( !$settings.connection.sid ) { Initialize-Forum }
    $pos_url = "$( $settings.connection.forum_ssl -eq 'Y' ? 'https://' : 'http://' )$($settings.connection.forum_url)/forum/posting.php"
    $headers = @{ 'User-Agent' = 'Mozilla/5.0' }
    if ( !$topic_id ) {
        $body = "mode=editpost&p=$post_id&message=$mess&submit_mode=submit&form_token=$($settings.connection.token)"
    }
    else {
        $body = "mode=reply&t=$topic_id&message=$mess&submit_mode=submit&form_token=$($settings.connection.token)"
    }
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
            if ( $i -gt 20 ) { break }
        }
    }
}

function Get-File ( $uri, $save_path, $user_agent, $headers = $null, $from ) {
    $i = 1
    while ( $i -le 10 ) {
        $use_proxy = ( $from -eq 'forum' ? $settings.connection.proxy.use_for_forum.ToUpper() -eq 'Y' : ( $from -eq 'api' ? $settings.connection.proxy.use_for_api.ToUpper() -eq 'Y' : $settings.connection.proxy.use_for_rep.ToUpper() -eq 'Y' ) )
        try { 
            if ( $use_proxy -eq $true -and $settings.connection.proxy.ip -and $settings.connection.proxy.ip -ne '' ) {
                if ( $request_details -eq 'Y' ) { Write-Log "Идём на $uri используя прокси $($settings.connection.proxy.url )" }
                if ( $settings.connection.proxy.credentials ) {
                    Invoke-WebRequest -Uri $uri -WebSession $settings.connection.sid -OutFile $save_path -Proxy $settings.connection.proxy.url -MaximumRedirection 999 -ConnectionTimeoutSeconds 30 -SkipHttpErrorCheck -ProxyCredential $settings.connection.proxy.credentials -UserAgent $user_agent -Headers $headers
                }
                else {
                    Invoke-WebRequest -Uri $uri -WebSession $settings.connection.sid -OutFile $save_path -Proxy $settings.connection.proxy.url -MaximumRedirection 999 -ConnectionTimeoutSeconds 30 -SkipHttpErrorCheck -UserAgent $user_agent -Headers $headers
                }
                break
            }
            else { Invoke-WebRequest -Uri $uri -WebSession $settings.connection.sid -OutFile $save_path -MaximumRedirection 999 -ConnectionTimeoutSeconds 30 -SkipHttpErrorCheck -UserAgent $user_agent -Headers $headers; break }
        }
        catch { Start-Sleep -Seconds 10; $i++; Write-Log "Попытка номер $i" }
    }
    
}

function Get-ForumTorrentFile ( [int]$Id, $save_path = $null) {
    # if ( !$settings.connection.sid ) { Initialize-Forum }
    $get_url = $( $settings.connection.forum_ssl -eq 'Y' ? 'https://' : 'http://' ) + $settings.connection.forum_url + '/forum/dl.php?t=' + $Id + '&keeper_user_id=' + $settings.connection.user_id + '&keeper_api_key=' + $settings.connection.api_key
    if ( $null -eq $save_path ) { $Path = Join-Path $PSScriptRoot ( $Id.ToString() + '.torrent' ) } else { $path = Join-Path $save_path ( $Id.ToString() + '.torrent' ) }
    Write-Log 'Скачиваем torrent-файл с форума'
    $user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0'
    Get-File -Uri $get_url -save_path $Path -user_agent $user_agent -from 'forum'
    # if ( $null -eq $save_path ) {
    return Get-Item $Path
    # }
}

function Get-ForumPost ( [int]$post ) {
    # if ( !$settings.connection.sid ) { Initialize-Forum }
    $get_url = $( $settings.connection.forum_ssl -eq 'Y' ? 'https://' : 'http://' ) + $settings.connection.forum_url + '/forum/viewtopic.php?p=' + $post
    $i = 1
    Write-Host "`n$get_url"
    while ( $i -le 10 ) {
        try { 
            if ( $settings.connection.proxy.use_for_forum.ToUpper() -eq 'Y' -and $settings.connection.proxy.ip -and $settings.connection.proxy.ip -ne '' ) {
                if ( $request_details -eq 'Y' ) { Write-Log "Идём на $get_url используя прокси $($settings.connection.proxy.url )" }
                if ( $settings.connection.proxy.credentials ) {
                    # return ( Invoke-WebRequest -Uri $get_url -WebSession $settings.connection.sid -Proxy $settings.connection.proxy.url -MaximumRedirection 999 -SkipHttpErrorCheck -ProxyCredential $settings.connection.proxy.credentials ).content
                    return ( Invoke-WebRequest -Uri $get_url -Proxy $settings.connection.proxy.url -MaximumRedirection 999 -SkipHttpErrorCheck -ProxyCredential $settings.connection.proxy.credentials ).content
                }
                else {
                    # return ( Invoke-WebRequest -Uri $get_url -WebSession $settings.connection.sid -Proxy $settings.connection.proxy.url -MaximumRedirection 999 -SkipHttpErrorCheck ).content
                    return ( Invoke-WebRequest -Uri $get_url -Proxy $settings.connection.proxy.url -MaximumRedirection 999 -SkipHttpErrorCheck ).content
                }
            }
            # else { return ( Invoke-WebRequest -Uri $get_url -WebSession $settings.connection.sid -MaximumRedirection 999 -SkipHttpErrorCheck ).content }
            else { return ( Invoke-WebRequest -Uri $get_url -MaximumRedirection 999 -SkipHttpErrorCheck ).content }
        }
        catch { Start-Sleep -Seconds 10; $i++; Write-Log "Попытка номер $i" }
    }
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
    # Test-ForumWorkingHours
    # $MoscowTZ = [System.TimeZoneInfo]::FindSystemTimeZoneById("Russian Standard Time")
    # $MoscowTime = [System.TimeZoneInfo]::ConvertTimeFromUtc((Get-Date).ToUniversalTime(), $MoscowTZ)
    $lock_file = "$PSScriptRoot\in_progress.lck"
    $in_progress = Test-Path -Path $lock_file
    # If ( ( ( Get-Date($MoscowTime) -UFormat %H ).ToInt16( $nul ) + 2 ) % 2 -eq 0 -or ( $check -eq $false ) ) {
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
        Write-Log "Обнаружен файл блокировки $lock_file. Вероятно, запущен параллельный процесс. Если это не так, удалите файл" -Red
    }
    # }
}

function Send-Report () {
    Write-Log 'Шлём отчёт'
    . $php_path ( Join-Path $tlo_path 'cron' 'reports.php' )
}

function Remove-ClientTorrent ( $client, $hash, [switch]$deleteFiles, $torrent = $null ) {
    if ( $null -ne $torrent ) { $hash = $torrent.hash }
    $text = ( $null -eq $torrent ? $hash : $( $torrent.topic_id ? "$($torrent.topic_id) - $($torrent.name)" : $torrent.name ) )
    try {
        if ( $deleteFiles -eq $true ) {
            $text = 'Удаляем из клиента ' + $client.Name + ' раздачу ' + $text + ' вместе с файлами'
            Write-Log $text
        }
        else {
            $text = 'Удаляем из клиента ' + $client.Name + ' раздачу ' + $text + ' без удаления файлов'
            Write-Log $text
        }
        $request_delete = @{
            hashes      = $hash
            deleteFiles = $deleteFiles
        }
        Invoke-WebRequest -Uri ( $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.ip + ':' + $client.Port + '/api/v2/torrents/delete' ) -WebSession $client.sid -Body $request_delete -Method POST | Out-Null
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
        $tg_data.messages += $tg_data.message.Clone() 
        $tg_data.message = ''
    }
    $tg_data.message += $tg_data.line
}

function Send-TGReport ( $refreshed, $added, $obsolete, $broken, $rss_add_cnt, $rss_del_cnt, $token, $chat_id, $mess_sender ) {
    $tg_data = @{}
    $tg_data.messages = [System.Collections.ArrayList]::new()
    if ( $refreshed.Count -gt 0 -or $added.Count -gt 0 -or $obsolete.Count -gt 0 -or $broken.Count -gt 0 -or $rss_add_cnt -gt 0 -or $rss_del_cnt -gt 0 ) {
        if ( $brief_reports -ne 'Y') {
            # полная форма
            $tg_data.message = ''
            $first = $true
            foreach ( $client in $refreshed.Keys ) {
                if ( !$first ) { $tg_data.message += "`n" }
                $first = $false
                $tg_data.line = "Обновлены в клиенте <b>$client</b>`n"
                Add-TGMessage $tg_data
                $refreshed[$client].keys | Sort-Object | ForEach-Object {
                    $refreshed[$client][$_] | ForEach-Object {
                        # Add-TGMessage ( 'https://rutracker.org/forum/viewtopic.php?t=' + $_.id + $_.comment + "`n" + $_.name + ' (' + ( to_kmg $_.old_size 2 ) + ' -> ' + ( to_kmg $_.new_size 2 ) + ")`n`n" )
                        $tg_data.line = ( 'https://rutracker.org/forum/viewtopic.php?t=' + $_.id + $_.comment + "`n" + $_.name + ' (' + ( to_kmg $_.old_size 2 ) + ' -> ' + ( to_kmg $_.new_size 2 ) + ")`n`n" )
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

            # if ( $tg_data.message -ne '' -and $obsolete.count -gt 0 ) { $tg_data.message += "`n" }
            # $first = $true
            # foreach ( $client in $obsolete.Keys ) {
            #     if ( !$first ) { $tg_data.message += "`n" }
            #     $first = $false
            #     $tg_data.line = "Лишние в клиенте $client :`n"
            #     Add-TGMessage $tg_data
            #     # Add-TGMessage "Лишние в клиенте $($client.name) :`n"
            #     $obsolete[$client] | ForEach-Object {
            #         $tg_data.line = "https://rutracker.org/forum/viewtopic.php?t=$_`n"
            #         Add-TGMessage $tg_data
            #         # Add-TGMessage "https://rutracker.org/forum/viewtopic.php?t=$_`n"
            #         if ( $id_to_info[$_].name ) {
            #             $tg_data.line = ( $id_to_info[$_].name + ', ' + ( to_kmg $id_to_info[$_].size 2 ) + "`n" )
            #             Add-TGMessage $tg_data
            #             # Add-TGMessage ( $id_to_info[$_].name + ', ' + ( to_kmg $id_to_info[$_].size 2 ) + "`n" )
            #         }
            #     }
            # }

        }
        else {
            # краткая форма
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
                    $refreshed_b += ( $stat.Sum - $stat_was.Sum )
                }
                if ( $added -and $added[$client] ) {
                    $stat = ( $added[$client].keys | ForEach-Object { $added[$client][$_] }) | Measure-Object -Property size -Sum
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
        if ( $rss_add_cnt -gt 0 ) {
            if ( $tg_data.message -ne '' ) { $tg_data.message += "`n" }
            $tg_data.line = "Добавлено из RSS: $( Get-Spell -qty $rss_add_cnt -spelling 1 -entity 'torrents' )`n"
            Add-TGMessage $tg_data
        }
        if ( $rss_del_cnt -gt 0 ) {
            if ( $tg_data.message -ne '' ) { $tg_data.message += "`n" }
            $tg_data.line = "Удалено из RSS: $( Get-Spell -qty $rss_del_cnt -spelling 1 -entity 'torrents' )`n"
            Add-TGMessage $tg_data

        }
        # Send-TGMessage -message $message -token $token -chat_id $chat_id -mess_sender $mess_sender
        if ( $tg_data.message -ne '' -and $obsolete.count -gt 0 ) { $tg_data.message += "`n" }
        $first = $true
        foreach ( $client in $obsolete.Keys ) {
            if ( !$first ) { $tg_data.message += "`n" }
            $first = $false
            $tg_data.line = "Лишние в клиенте $client :`n"
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
            $tg_data.message += "Ошибки в клиенте $($client.name) :`n"
            ($broken[$client]).keys | ForEach-Object {
                $tg_data.line = "https://rutracker.org/forum/viewtopic.php?t=$_`n$($broken[$client][$_])`n"
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
        $tg_data.message = 'Ничего делать не понадобилось'
    }
    $tg_data.messages += $tg_data.message
    $first_post = $true
    $tg_data.messages | ForEach-Object {
        Send-TGMessage -message $_ -token $token -chat_id $chat_id -mess_sender ( $first_post -eq $true ? $mess_sender : '' )
        $first_post = $false
    }
}

function Start-Torrents( $hashes, $client, $mess_sender, [switch]$force ) {
    $Params = @{ hashes = ( $hashes -join '|' ) }
    if ( $force.IsPresent ) {
        $url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.port + '/api/v2/torrents/setForceStart'
        $Params.value = $true
    }
    else {
        $url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.port + '/api/v2/torrents/' + $client.start_command
    }
    try {
        Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
    }
    catch {
        Initialize-Client -client $client -force -mess_sender $mess_sender -verbos
        Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
    }
}

function Stop-Torrents( $hashes, $client, $mess_sender ) {
    $Params = @{ hashes = ( $hashes -join '|' ) }
    $url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.port + '/api/v2/torrents/' + $client.stop_command
    try {
        Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
    }
    catch {
        Initialize-Client -client $client -force -mess_sender $mess_sender -verbos
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

function Start-Rehash ( $client, $hash ) {
    # Write-Log "Привет, я процедура рехэша, мне передан хэш $hash"
    $Params = @{ hashes = $hash }
    $url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.ip + ':' + $client.Port + '/api/v2/torrents/recheck'
    $statusCode = ( Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' ).StatusCode # | Out-Null
    Write-Log "Клиент на запрос рехэша ответил кодом $statusCode"
    # if ( $move_up.IsPresent) {
    #     Start-Sleep -Seconds 1
    #     Write-Log 'Поднимаем раздачу в начало очереди'
    #     $url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.ip + ':' + $client.Port + '/api/v2/torrents/topPrio'
    #     Invoke-WebRequest -Method POST -Uri $url -WebSession $client.sid -Form $Params -ContentType 'application/x-bittorrent' | Out-Null
    # }
}

function DeGZip-File {
    param(
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
    $tag_url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.Port + '/api/v2/torrents/addTags'
    $tag_body = @{ hashes = $torrent.hash; tags = $label }
    try {
        $req = ( Invoke-WebRequest -Method POST -Uri $tag_url -Headers $loginheader -Body $tag_body -WebSession $client.sid )
        # Write-Log ( 'Клиент ответил: ' + $req.StatusCode.ToString( ) + ' ' + $req.StatusDescription + $req.Content )
    }
    catch {
        Initialize-Client -client $client -force -mess_sender $mess_sender
        Invoke-WebRequest -Method POST -Uri $tag_url -Headers $loginheader -Body $tag_body -WebSession $client.sid | Out-Null
        # Write-Log ( 'Клиент ответил: ' + $req.StatusCode.ToString( ) + ' ' + $req.StatusDescription + $req.Content )
    }
}

function Add-Category ( $category, [switch]$silent, $mess_sender ) {
    if (!$silent) {
        Write-Log ( "Метим раздачу категорией '$category'" )
    }
    $add_url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.Port + '/api/v2/torrents/createCategory'
    $add_body = @{ category = $category; save_path = '' }
    Invoke-WebRequest -Method POST -Uri $add_url -Body $add_body -WebSession $client.sid | Out-Null
}

function Set-Category ( $client, $torrent, $category, [switch]$silent, $mess_sender ) {
    if (!$silent) {
        Write-Log ( "Метим раздачу $( $torrent.name ) категорией '$category'" )
    }
    $cat_url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.Port + '/api/v2/torrents/setCategory'
    $tag_body = @{ hashes = $torrent.hash; category = $category }
    try {
        Invoke-WebRequest -Method POST -Uri $cat_url -Body $tag_body -WebSession $client.sid | Out-Null
    }
    catch {
        Add-Category $category
        Invoke-WebRequest -Method POST -Uri $tag_url -Body $tag_body -WebSession $client.sid | Out-Null
    }
}

function Set-ForceStart ( $client, $torrent, $mess_sender ) {
    $set_url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.Port + '/api/v2/torrents/setForceStart'
    $set_body = @{ 
        hashes = $torrent.hash
        value  = $true
    }
    try {
        Invoke-WebRequest -Method POST -Uri $set_url -Headers $loginheader -Body $set_body -WebSession $client.sid | Out-Null
    }
    catch {
        Initialize-Client -client $client -force -mess_sender $mess_sender
        Invoke-WebRequest -Method POST -Uri $set_url -Headers $loginheader -Body $set_body -WebSession $client.sid | Out-Null
    }
}

function Remove-Comment ( $client, $torrent, $label, [switch]$silent ) {
    if (!$silent) {
        Write-Log ( 'Снимаем с раздачи метку ' + $label )
    }
    $tag_url = $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.Port + '/api/v2/torrents/removeTags'
    $tag_body = @{ hashes = $torrent.hash; tags = $label }
    try {
        Invoke-WebRequest -Method POST -Uri $tag_url -Headers $loginheader -Body $tag_body -WebSession $client.sid | Out-Null
    }
    catch {
        Initialize-Client -client $client -force -mess_sender $mess_sender
        Invoke-WebRequest -Method POST -Uri $tag_url -Headers $loginheader -Body $tag_body -WebSession $client.sid | Out-Null
    }
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
        default {
            switch ( $qty % 10 ) {
                { $PSItem -eq 1 } { if ( $spelling -eq 1 ) { return ( $entity -eq 'torrents' ? "$qty раздача" : "$qty день" ) } else { return ( $entity -eq 'torrents' ? "$qty раздачу" : "$qty день" ) } }
                { $PSItem -in ( 2..4 ) } { return ( $entity -eq 'torrents' ? "$qty раздачи" : "$qty дня" ) }
                default { return ( $entity -eq 'torrents' ? "$qty раздач" : "$qty дней" ) }
            }
        }
    }
}

function Get-APISeeding ( $sections, $seeding_days, $call_from ) {
    $seed_dates = @{}
    foreach ( $section in $sections ) {
        Write-Log "Запрашиваем историю сидирования по разделу $section"
        $url = "/krs/api/v1/keeper/$($settings.connection.user_id)/reports?only_subforums_marked_as_kept=true&last_seeded_limit_days=$seeding_days&last_update_limit_days=60&columns=last_seeded_time&subforum_id=$section"

        ( ( Get-RepHTTP -url $url -headers $headers -call_from $call_from ) | ConvertFrom-Json ).kept_releases | ForEach-Object {
            if ( $null -ne $_ ) { $seed_dates[$_[0]] = $_[1] }
        } 
    }
    return $seed_dates
}

function Get-RepSeeds( $topic_id, $call_from ) {
    Write-Log "Запрашиваем количество сидов по раздаче $topic_id"
    $url = "/krs/api/v1/releases/pvc?topic_ids=$topic_id&columns=seeders"
    return ( ( Get-RepHTTP -url $url -headers $headers -call_from $call_from ) | ConvertFrom-Json ).releases[0][1]
}

function Get-RepRegTime( $topic_id, $call_from ) {
    Write-Log "Запрашиваем дату добавления раздачи $topic_id"
    $url = "/krs/api/v1/releases/pvc?topic_ids=$topic_id&columns=reg_time"
    try {
        return ( ( Get-RepHTTP -url $url -headers $headers -call_from $call_from ) | ConvertFrom-Json ).releases[0][1]
    }
    catch {
        Write-Log 'Не получилось' -Red
        return $null
    }
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
    if ( $call_from -like '*Adder*' -and $no_telemetry -ne 'Y') {
        Send-Handshake -sections $sections -use_avg_seeds $use_avg_seeds
    }

    while ( $counter -lt 10 ) {
        try {
            foreach ( $section in $sections ) {
                $section_torrents = Get-RepSectionTorrents `
                    -section $section -ok_states $ok_states -call_from $call_from -avg_seeds:$avg_seeds.IsPresent -min_avg $min_avg -min_seeders $min_seeders -min_release_date $min_release_date -get_low $get_lows -get_mids $get_mids -get_highs $get_highs
                $section_torrents.keys | Where-Object { $null -eq $tracker_torrents[$_] } | ForEach-Object { $tracker_torrents[$_] = $section_torrents[$_] }
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

function GetRepSectionKeepers( $section, $excluded = @(), $call_from ) {
    Write-Log "Выгружаем отчёты по подразделу $section"
    $url = "/krs/api/v1/subforum/$section/reports?columns=status,keeping_priority"
    $content = ( Get-RepHTTP -url $url -headers $headers -call_from $call_from ) | ConvertFrom-Json
    if ( $null -eq $content ) { exit }
    if ( $excluded.count -gt 0 ) {
        $content = $content | Where-Object { $_.keeper_id -notin $excluded }
    }
    $content = $content | Select-Object kept_releases -ExpandProperty kept_releases
    # $content = $content | Select-Object kept_releases -ExpandProperty
    return $content
}

function GetRepKeptTorrents( $sections, $call_from, $max_keepers, $max_keepers_extra, $excluded = @() ) {
    $keepers = @{}
    foreach ( $section in $sections ) {
        $section_keepers = GetRepSectionKeepers -section $section -excluded $excluded
        $section_keepers | Where-Object { -bnot ( $_[1] -band 0b10 ) } | ForEach-Object {
            $id = $_[0].ToInt32($null)
            if ( !$keepers[$id] ) { $keepers[$id] = @{ cnt = 0; prio = $_[2] } }
            $keepers[$id].cnt++
        }
    }
    if ( $null -ne $max_keepers -or $null -ne $max_keepers_extra ) {
        $max_keepers_tmp = $null -ne $max_keepers -and $max_keepers -gt -1 ? $max_keepers : 999999
        $max_keepers_extra_tmp = $null -ne $max_keepers_extra  -and $max_keepers_extra -gt -1 ? $max_keepers_extra : 999999
        $kept_ids = $keepers.keys | Where-Object { ( $keepers[$_].cnt -gt $max_keepers_extra_tmp -and $keepers[$_].keeping_priority -eq 2 ) -or ( $keepers[$_].cnt -gt $max_keepers_tmp -and $keepers[$_].keeping_priority -ne 2 ) } 
    }
    else { $kept_ids = $keepers.keys }
    return $kept_ids
}

function Get-TopicKeepingStatus( $topic_id, $call_from ) {
    $url = "/krs/api/v1/releases/reports?topic_ids=$topic_id&columns=status"
    $content = ( Get-RepHTTP -url $url -call_from $call_from ) | ConvertFrom-Json
    $check = ( $content.result | ForEach-Object { $_[3] -band 0b10 } | Measure-Object -Minimum ).Minimum
    $result = $check -eq 0 -or $null -eq $check 
    return $result
}

function Get-RepSectionTorrents( $section, $ok_states, $call_from, [switch]$avg_seeds, $min_avg, $min_release_date, $min_seeders ) {
    $use_avg_seeds = ( $avg_seeds.IsPresent ? $true : ( $ini_data.sections.avg_seeders -eq '1' ) )
    $avg_days = $ini_data.sections.avg_seeders_period
    $subst = $( $use_avg_seeds -eq 'Y' ? ',average_seeds_sum,average_seeds_count' : '')
    $url = "/krs/api/v1/subforum/$section/pvc?columns=tor_status,reg_time,topic_poster,info_hash,tor_size_bytes,keeping_priority,seeder_last_seen,seeders,topic_title,keeper_seeders$subst"
    $content = ( Get-RepHTTP -url $url -call_from $call_from )
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
    Write-Log ( "По разделу $section получено: $( Get-Spell $($lines.count) )" ) # -skip_timestamp -nologfile
    # if ( !$lines.count ) {
    #     Write-Log 'Не получилось' -Red
    #     exit 
    # }
    return $lines
}

function Send-Handshake ( $sections, $use_avg_seeds ) {
    $body = [ordered]@{
        # 'subforum_id' = $section.ToInt64( $null )
        'subforum_id' = ( $sections | Join-String -Separator ', ' )
        'tool_name'   = 'Adder'
        'filters'     = [ordered]@{
            'max_keepers'       = $max_keepers ? $max_keepers : -1
            'max_seeders'       = $use_avg_seeds ? - 1 : $settings.adder.max_seeds
            'max_average_seeds' = $use_avg_seeds ? $settings.adder.max_seeds : - 1
            'min_days_old'      = $min_days
            # 'exact_keeper_id' = exact_keeper_id
            'exclude_low_prio'  = $get_lows -eq 'Y' ? $false : $true
            'exclude_mid_prio'  = $get_mids -eq 'Y' ? $false : $true
            'exclude_high_prio' = $get_highs -eq 'Y' ? $false : $true
            # 'exclude_self_kept' = exclude_self_kept
            'get_news'          = $settings.adder.get_news -ne 'N' ? $true : $false
            'get_updated'       = $get_updated -ne 'N' ? $true : $false
            'get_blacklist'     = $settings.adder.get_blacklist -eq 'Y' ? $true : $false
            'get_hidden'        = $settings.adder.get_hidden -eq 'Y' ? $true : $false
            'get_shown'         = $settings.adder.get_shown -ne 'N' ? $true : $false
            'report_changes'    = ( $settings.adder.update_stats -eq 'Y' -and $send_reports -eq 'Y' ) ? $true : $false
            'self_update'       = $settings.others.auto_update -eq 'Y' ? $true : $false
        }
    }
    Write-Log 'Отчитываемся в API по параметрам запроса'
    Write-Log "Отчитываемые разделы: $( $body.subforum_id )"
    $url = '/krs/api/v1/mark_subforum_fetch'
    $headers = @{}
    $headers.'Authorization' = 'Basic ' + [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes( $settings.connection.user_id + ':' + $settings.connection.api_key ))
    Send-HTTP -url "$( $settings.connection.report_ssl -eq 'Y' ? 'https://' : 'http://' )$($settings.connection.report_url)$url" -body ( $body | ConvertTo-Json -Compress ) `-headers $headers -call_from $call_from -use_proxy $settings.connection.proxy.use_for_rep
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
    $headers.'Authorization' = 'Basic ' + [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes( $settings.connection.user_id + ':' + $settings.connection.api_key ))
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
                            -UserAgent "PowerShell/$($PSVersionTable.PSVersion) -$call_from-on-$($PSVersionTable.Platform)" -OperationTimeoutSeconds 20 ).Content
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
            if ( $retry_cnt -lt 10 ) { Start-Sleep -Seconds 10; $retry_cnt++; Write-Log "Попытка номер $retry_cnt" }
            elseif ( $retry_cnt -ge 10 ) { break }
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

function Send-HTTP ( $url, $body, $headers, $call_from, [switch]$break ) {
    $retry_cnt = 1
    $retry_max = 1
    while ( $true ) {
        try {
            # if ( [bool]$ConnectDetails.ProxyURL -and $ConnectDetails.UseApiProxy -eq 1 ) {
            if ( $settings.connection.proxy.use_for_rep -eq 'Y' ) {
                if ( $settings.connection.proxy.credentials ) {
                    # Write-Log 'Указан прокси с аутентификацией'
                    $hs = ( Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Proxy $settings.connection.proxy.url -ProxyCredential $settings.connection.proxy.credentials -Body $body `
                            -UserAgent "PowerShell/$($PSVersionTable.PSVersion)-$call_from-on-$($PSVersionTable.Platform)" -ContentType 'application/json' -ConnectionTimeoutSeconds 30 )
                    Write-Log "API ответило $( $hs.StatusCode ) $( $hs.StatusDescription ) $( $hs.Content )"
                    return
                }
                else {
                    # Write-Log 'Указан прокси без аутентификации'
                    $hs = ( Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Proxy $settings.connection.proxy.url -Body $body `
                            -UserAgent "PowerShell/$($PSVersionTable.PSVersion)-$call_from-on-$($PSVersionTable.Platform)" -ContentType 'application/json' -ConnectionTimeoutSeconds 30 )
                    Write-Log "API ответило $( $hs.StatusCode ) $( $hs.StatusDescription ) $( $hs.Content )"
                    return
                }
            }
            else {
                # Write-Log 'Прокси не используем'
                $hs = ( Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -UserAgent "PowerShell/$($PSVersionTable.PSVersion)-$call_from-on-$($PSVersionTable.Platform)" -ContentType 'application/json' -ConnectionTimeoutSeconds 30 )
                Write-Log "API ответило $( $hs.StatusCode ) $( $hs.StatusDescription ) $( $hs.Content )"
                return
            }
        }
        catch {
            if ( $retry_cnt -ge $retry_max ) { return }
            Write-Log "Ошибка`n$($_.ToString())`n ждём 10 секунд" -Red
            Start-Sleep -Seconds 10; $retry_cnt++; Write-Log "Попытка номер $retry_cnt"
        }
    }
    if ( $break.IsPresent ) {
        Write-Log 'Не удалось отправить данные, выходим досрочно' -Red
        exit
    }
    Write-Log 'Функция отработала'
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

function  Set-SaveLocation ( $client, $torrent, $new_path, $verbose = $false, $mess_sender, $old_path ) {
    $error.Clear()
    $data = @{
        hashes   = $torrent.hash
        location = $new_path
    }
    try {
        if ( $verbose.IsPresent ) {
            Write-Log "Отправляем команду на перемещение торрента $($torrent.name ) из папки $old_path в папку $new_path"
        }
        Invoke-WebRequest -Uri ( $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.ip + ':' + $client.Port + '/api/v2/torrents/setLocation' ) -WebSession $client.sid -Body $data -Method POST | Out-Null
    }
    catch {
        if ( $null -ne $error[0].Exception.Message ) {
            # if ( $error[0].Exception.Message -match 'path') {
            Write-Log "Не удалось переместить торрент в $new_path. Ошибка $($error[0].ErrorDetails.Message), $($error[0].Exception.Message)" -Red
        }
        # else {
        #     $client.sid = $null
        #     $error.Clear()
        #     Initialize-Client -client $client -mess_sender $mess_sender -force -verbose
        #     Invoke-WebRequest -Uri ( $client.ip + ':' + $client.Port + '/api/v2/torrents/setLocation' ) -WebSession $client.sid -Body $data -Method POST | Out-Null
        #     if ( $nul -ne $error[0] ) {
        #     }
        # }
    }
}

function Get-ClientApiVersions ( $clients, $mess_sender ) {
    Write-Log 'Получаем версии API клиентов для правильной работы с ними'
    foreach ( $client_key in ( $clients.keys | Where-Object { $null -eq $clients[$_].api_verion } ) ) {
        $client = $clients[$client_key]
        Initialize-Client $client -mess_sender $mess_sender -verbos
        $client.api_version = [version]( Invoke-WebRequest -Uri ( $( $client.ssl -eq '0' ? 'http://' : 'https://' ) + $client.IP + ':' + $client.port + '/api/v2/app/webapiVersion' ) -WebSession $client.sid ).content
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

function Expand-TarGz( $url, $tmp_dir, $destination, $headers = $null ) {
    Write-Log "Качаем $url"
    # Invoke-WebRequest -Uri $url -Headers $headers -OutFile ( Join-Path $tmp_dir 'arch.tar' )
    $from = ( $url -like '*rep.rutracker.cc*' ? 'rep' : $url -like '*api.rutracker.cc*' ? 'api' : 'forum' ) 
    Get-File -uri $url -headers $headers -save_path ( Join-Path $tmp_dir 'arch.tar' ) -from $from
    New-Item -Path $destination -ErrorAction SilentlyContinue -ItemType Directory | Out-Null
    Remove-Item -Path ( Join-Path $destination '*.*')
    Write-Log 'Распаковываем tar'
    tar xf ( Join-Path $tmp_dir 'arch.tar' ) -C $destination
    Remove-Item -Path ( Join-Path $tmp_dir 'arch.tar' )
    Set-Location $destination
    Write-Log 'Распаковываем gz'
    Get-Item -Path '*.gz' | ForEach-Object { . 'C:\Program Files\7-Zip\7z.exe' x $_ | Out-Null }
    Remove-Item -Path '*.gz'
    Set-Location $PSScriptRoot
}
