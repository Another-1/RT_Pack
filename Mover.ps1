param ([switch]$verbose, $client_name, $path_from, $path_to, $category, $max_size, $max_1_size, $id_subfolder )

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

$tlo_path = Test-Setting 'tlo_path' -required
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
}
else {
    $client = Select-Client
}
Write-Log ( 'Выбран клиент ' + $client.Name )
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

if ( !$id_subfolder ) { $id_subfolder = Test-Setting -setting id_subfolder -required -default 'N' -no_ini_write }
Initialize-Client $client
if ( $client.sid ) {
    $i = 0
    $sum_size = 0
    $torrents_list = Get-ClientTorrents -client $client -mess_sender 'Mover' -verbose -completed | Where-Object { $_.save_path -like "*${path_from}*" } 
    # if ( $max_size -eq -1 * 1Gb ) {
    Write-Log 'Сортируем по полезности и подразделу'
    $torrents_list = $torrents_list | Sort-Object -Property category | Sort-Object { $_.uploaded / $_.size } -Descending -Stable

    if ( $category -and $category -ne '' ) {
        $torrents_list = $torrents_list | Where-Object { $_.category -eq "${category}" }
    }
    if ( $max_1_size -gt 0 ) {
        $max_1_bytes = $max_1_size * 1Gb
        $torrents_list = $torrents_list | Where-Object { $_.size -le $max_1_bytes }
    }

    If ( $id_subfolder -eq 'Y' ) {
        Write-Log 'Получаем ID раздач из комментариев. Это может быть небыстро.'
        Get-TopicIDs -client $client -torrent_list $torrents_list
    }
    foreach ( $torrent in $torrents_list) {
        $i++
        $new_path = $torrent.save_path.replace( $path_from, $path_to )
        if ( $id_subfolder -eq 'Y' -and $new_path -notlike "*$($torrent.topic_id)*" ) {
            $new_path = Join-Path $new_path $torrent.topic_id
        }
        if ( $new_path -ne $torrent.save_path ) {
            $sum_size += $torrent.size
            if ( $max_size -gt 0 -and $sum_size -gt $max_size ) {
                Write-Log 'Достигнут максимальный объём'
                break
            }
            Set-SaveLocation $client $torrent $new_path -verbose:$( $verbose -eq $true )
            Write-Progress -Activity 'Moving' -Status $torrent.name -PercentComplete ( $i * 100 / $torrents_list.Count )
            Start-Sleep -Milliseconds 100
        }
    }
    Write-Progress -Activity 'Moving' -Completed
}
