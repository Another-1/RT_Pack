param ([switch]$verbose, $client_name, $path_from, $path_to, $category, $max_size, $max_1_size, $min_move_days, $id_subfolder, [switch]$reverse, [switch]$keep_empty_folders, $max_inactive_days, $min_inactive_days )

$window_title = 'Mover'
Write-Host "$([char]0x1B)]0;$window_title`a"

Write-Host 'Проверяем версию Powershell...'
If ( $PSVersionTable.PSVersion -lt [version]'7.1.0.0') {
    Write-Host 'У вас слишком древний Powershell, обновитесь с https://github.com/PowerShell/PowerShell#get-powershell ' -ForegroundColor Red
    Pause
    Exit
}

if ( Test-Path ( Join-Path $PSScriptRoot 'settings.json') ) {
    $debug = 1
    $settings = Get-Content -Path ( Join-Path $PSScriptRoot 'settings.json') | ConvertFrom-Json -AsHashtable
    $standalone = $true
}
else {
    try {
        . ( Join-Path $PSScriptRoot _settings.ps1 )
    }
    catch {
        Write-Host ( 'Не найден файл настроек ' + ( Join-Path $PSScriptRoot _settings.ps1 ) + ', видимо это первый запуск.' )
    }
    $settings = [ordered]@{}
    $settings.interface = @{}
    $settings.interface.use_timestamp = ( $use_timestamp -eq 'Y' ? 'Y' : 'N' )
    $standalone = $false
}

if ( $use_timestamp -eq 'Y' ) { $use_timestamp = 'N' }

Write-Host 'Подгружаем функции'
. ( Join-Path $PSScriptRoot _functions.ps1 )

if ( ( Test-Version '_functions.ps1' 'Mover' ) -eq $true ) {
    Write-Log 'Запускаем новую версию  _functions.ps1'
    . ( Join-Path $PSScriptRoot '_functions.ps1' )
}
Test-Version ( $PSCommandPath | Split-Path -Leaf ) 'Mover'

if ( -not ( [bool](Get-InstalledModule -Name PsIni -ErrorAction SilentlyContinue) ) ) {
    Write-Output 'Не установлен модуль PSIni для чтения настроек Web-TLO, ставим...'
    Install-Module -Name PsIni -Scope CurrentUser -Force
}

if ( !$settings.others ) { $settings.others = [ordered]@{} }
$settings.others.auto_update = Test-Setting 'auto_update' -required

$tlo_path = Test-Setting 'tlo_path' -required
### DEBUG ###
# $tlo_path = '\\192.168.0.29\Software\1'   # Путь к папке Web-TLO
### DEBUG ###
$ini_path = Join-Path $tlo_path 'data' 'config.ini'
$ini_data = Get-IniContent $ini_path

Get-Clients
# Get-ClientApiVersions $settings.clients
if ( $client_name ) {
    $client = $settings.clients[$client_name ]
    if ( !$client ) {
        Write-Log "Не найден клиент $client_name" -Red
        exit
    }
    $client_to = $client
}
else {
    Write-Log 'Выберите исходный клиент'
    $client = Select-Client
    Write-Log ( 'Выбран клиент ' + $client.Name )
    Write-Log "`nВыберите целевой клиент"
    $client_to = Select-Client
    Write-Log ( 'Выбран клиент ' + $client_to.Name )
    Set-ConnectDetails $settings
    Set-Proxy $settings
}
if ( !$path_from ) { $path_from = Select-Path 'from' }
if ( !$path_to ) { $path_to = Select-Path 'to' }
if ( $null -eq $category ) { $category = Get-String -prompt 'Укажите категорию (при необходимости)' }
if ( !$max_size ) {
    $max_size = ( Get-String -obligatory -prompt 'Максимальный суммарный объём всех раздач к перемещению, Гб (при необходимости, -1 = без ограничений)' ).ToInt16($null) * 1Gb 
}
else {
    $max_size = $max_size.ToInt16( $null ) * 1Gb
}
if ( !$max_1_size ) {
    $max_1_size = ( Get-String -obligatory -prompt 'Максимальный объём одной раздачи к перемещению, Гб (при необходимости, -1 = без ограничений)' ).ToInt16($null) * 1Gb
}
else {
    $max_1_size = $max_1_size.ToInt16( $null ) * 1Gb
}

if ( !$min_move_days ) {
    $min_move_days = ( Get-String -obligatory -prompt 'Минимальное количество дней с добавления (при необходимости, 0 = без ограничений)' ).ToInt16($null)
}
else { $min_move_days = $min_move_days.ToInt16($null) }

if ( !$id_subfolder ) { $id_subfolder = Test-Setting -setting id_subfolder -required -default 'N' -no_ini_write }

Write-Log "Указаны параметры:`nИсходный клиент: $($client.Name)`nЦелевой клиент: $($client_to.Name)`nИсходный кусок пути: $path_from`nЦелевой кусок пути: $path_to`nКатегория: $category`nСуммарный объём: $($max_size / 1Gb)`nОбъём раздачи: $($max_1_size / 1Gb)`nМинимальное количество дней: $min_move_days`nСоздавать подкаталоги: $id_subfolder"
Initialize-Client $client
if ( $client.sid ) {
    $i = 0
    $sum_size = 0
    if ( !$torrents_list ) {
        $torrents_list = Get-ClientTorrents -client $client -mess_sender 'Mover' -verbos -completed:$($move_incomplete -ne 'Y') | Where-Object { $_.save_path -like "*${path_from}*" }
        if ( $client_to -ne $client ) {
            Initialize-Client $client_to
            $already_list = Get-ClientTorrents -client $client_to -mess_sender 'Mover' -verbos 
            $torrents_list = @( $torrents_list | Where-Object { $_.hash -notin $already_list.hash } )
        }
        if ( $min_move_days -gt 0 ) {
            $max_add_date = ( Get-Date -UFormat %s ).ToInt32($null) - $min_move_days * 24 * 60 * 60
            $torrents_list = @( $torrents_list | Where-Object { $_.added_on -lt $max_add_date } )
        }

        if ( $max_inactive_days -and $max_inactive_days -gt 0 ) {
            $min_act_date = ( Get-Date -UFormat %s ).ToInt32($null) - $max_inactive_days * 24 * 60 * 60
            $torrents_list = @( $torrents_list | Where-Object { $_.last_activity -gt $min_act_date } )
        }

        if ( $min_inactive_days -and $min_inactive_days -gt 0 ) {
            $max_act_date = ( Get-Date -UFormat %s ).ToInt32($null) - $min_inactive_days * 24 * 60 * 60
            $torrents_list = @( $torrents_list | Where-Object { $_.last_activity -lt $max_act_date } )
        }
        # if ( $max_size -eq -1 * 1Gb ) {
        Write-Log 'Сортируем по полезности и подразделу'

        if ( $reverse.IsPresent ) {
            $torrents_list = @( $torrents_list | Sort-Object -Property category | Sort-Object { $_.uploaded / $_.size } -Stable )
        }
        else {
            $torrents_list = @( $torrents_list | Sort-Object -Property category | Sort-Object { $_.uploaded / $_.size } -Descending -Stable )
        }

        if ( $category -and $category -ne '' ) {
            $torrents_list = @( $torrents_list | Where-Object { $_.category -eq "${category}" } )
        }

        if ( $max_size -gt 0 ) {
            $torrents_list = @( $torrents_list | Where-Object { $_.size -le $max_size } )
        }

        if ( $max_1_size -gt 0 ) {
            $torrents_list = @( $torrents_list | Where-Object { $_.size -le $max_1_size } )
        }

        If ( $id_subfolder.ToUpper() -eq 'Y' ) {
            Write-Log 'Получаем ID раздач из комментариев. Это может быть небыстро.'
            Get-TopicIDs -client $client -torrent_list $torrents_list -verbos
        }
    }
    # Write-Log "Предстоит переместить $( Get-Spell -qty $torrents_list.Count -spelling 2 -entity 'torrents' )"
    foreach ( $torrent in $torrents_list ) {
        if ( -not $keep_empty_folders.IsPresent -and $prev_path -and ( Get-ChildItem -Path $torrent.save_path ).Count -eq 0 ) {
            Remove-Item -Path $prev_path -ErrorAction SilentlyContinue
        }

        $i++
        $new_path = $torrent.save_path.replace( $path_from, $path_to )
        if ( $id_subfolder -eq 'Y' -and $new_path -notlike "*$($torrent.topic_id)*" ) {
            $new_path = Join-Path $new_path $torrent.topic_id
        }
        if ( $new_path -ne $torrent.save_path -or $client -ne $client_to ) {
            $sum_size += $torrent.size
            if ( $max_size -gt 0 -and $sum_size -gt $max_size ) {
                $sum_size -= $torrent.size
                continue
            }
            $verbose = $true
            if ( $client -eq $client_to ) {
                # Write-Log 'Клиент один и тот же, просто даём ему команду переместить файл'
                Set-SaveLocation -client $client -torrent $torrent -new_path $new_path.replace( '\', '/' ) -verbose:$( $verbose.IsPresent ) -old_path $torrent.save_path -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')
                Write-Progress -Activity 'Moving' -Status $torrent.name -PercentComplete ( $i * 100 / $torrents_list.Count )
                $prev_path = $torrent.save_path
            }
            else {
                Remove-Variable prev_path -ErrorAction SilentlyContinue
                # if ( -not ( Test-ForumWorkingHours ) ) {
                #     Write-Log 'Подождём часик' -Red
                #     Start-Sleep -Seconds ( 3600 )
                # }
                if ( $pairs -and $pairs[$client_to.Name] ) {
                    Foreach ( $pair in $pairs[$client_to.Name].Keys ) {
                        $copy_dest = $path_to.replace( $pair, $pairs[$client_to.Name][$pair] )
                        if ( $copy_dest -and $copy_dest -ne $path_to ) {
                            Write-Log "Используется подмена шары $path_to -> $copy_dest"
                            break
                        }
                    }
                }
                else { $copy_dest = $path_to }
                Write-Log "Будем перемещать $($torrent.name) размером $( to_kmg $torrent.size 2 ) из $path_from в $path_to"
                if ( $path_from -ne $path_to -or $client.IP -ne $client_to.IP ) {
                    Copy-Item -Path $torrent.save_path -Destination ( ( Join-Path $copy_dest ( $torrent.save_path.replace( $path_from, '' ) ) ) ) -Recurse
                }
                # robocopy $torrent.save_path ( Join-Path $copy_dest ( $torrent.save_path.replace( $path_from, '' ) ) ) /MIR /nfl /ndl /eta /njh /njs
                $fake_torrents_list = @( @{ hash = $torrent.hash } )
                Get-TopicIDs -client $client -torrent_list $fake_torrents_list
                # $torrent_file = Get-ForumTorrentFile $fake_torrents_list[0].topic_id -save_path $PSScriptRoot
                Export-ClientTorrentFile -client $client -hash $torrent.hash -save_path ( Join-Path $PSScriptRoot "$( $fake_torrents_list[0].topic_id ).torrent" )
                $torrent_file = Get-Item ( Join-Path $PSScriptRoot "$($fake_torrents_list[0].topic_id).torrent" )
                $is_OK = Add-ClientTorrent -client $client_to -file $torrent_file -path $new_path -category $torrent.category -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') -addToTop:$( $add_to_top -eq 'Y' ) -Skip_checking
                if ( $is_ok ) {
                    Write-Log "$($torrent.name)   $( to_kmg $torrent.size 2 ) " -Green
                    if ( $path_from -ne $path_to -or $client.IP -ne $client_to.IP ) {
                        Remove-ClientTorrent -client $client -hash $torrent.hash -deleteFiles
                        if ( ( Get-ChildItem -Path $torrent.save_path ).Count -eq 0 ) {
                            Remove-Item -Path $torrent.save_path -ErrorAction SilentlyContinue
                        }
                    }
                    else {
                        Remove-ClientTorrent -client $client -hash $torrent.hash
                    }
                }
                else { Write-Log "$($torrent.name)   $( to_kmg $torrent.size 2 )" -Red }
            }
            Start-Sleep -Milliseconds 100
        }
        if ( -not $keep_empty_folders.IsPresent -and $prev_path -and ( Get-ChildItem -Path $torrent.save_path ).Count -eq 0 ) {
            Remove-Item -Path $prev_path -ErrorAction SilentlyContinue
        }
    }
    Write-Progress -Activity 'Moving' -Completed
    Write-Log "Отправлено в очередь перемещения $( to_kmg -bytes $sum_size -precision 2 )"
}
