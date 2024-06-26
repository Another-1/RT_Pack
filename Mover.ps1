Write-Host 'Проверяем версию Powershell...'
If ( $PSVersionTable.PSVersion -lt [version]'7.1.0.0') {
    Write-Host 'У вас слишком древний Powershell, обновитесь с https://github.com/PowerShell/PowerShell#get-powershell ' -ForegroundColor Red
    Pause
    Exit
}
try {
    . ( Join-Path $PSScriptRoot _settings.ps1 )
}
catch { Write-Host ( 'Не найден файл настроек ' + ( Join-Path $PSScriptRoot _settings.ps1 ) + ', видимо это первый запуск.' ) }
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

$ini_path = Join-Path $tlo_path 'data' 'config.ini'
$ini_data = Get-IniContent $ini_path

$clients = Get-Clients
$client = Select-Client $clients
Write-Log ( 'Выбран клиент ' + $client.Name )
$path_from = Select-Path 'from'
$separator = Get-Separator
if ( $path_from -notmatch "\${separator}$") { $path_from = "$path_from$separator" }
$path_to = Select-Path 'to'
if ( $path_to -notmatch "\${separator}$") { $path_to = "$path_to$separator" }
$category = Get-String -prompt 'Укажите категорию (при необходимости)'
$max_size = ( Get-String -obligatory -prompt 'Максимальный объём к перемещению, Гб (при необходимости, -1 = без ограничений)' ).ToInt16($null) * 1073741824
Initialize-Client $client
if ( $client.sid ) {
    $i = 0
    $sum_size = 0
    $torrents_list = Get-ClientTorrents -client $client -mess_sender 'Mover' -verbose | Where-Object { $_.save_path -like "*${path_from}*" }
    Write-Log 'Сортируем по полезности и подразделу'
    $torrents_list = $torrents_list | Sort-Object -Property category | Sort-Object { $_.uploaded / $_.size } -Descending -Stable

    if ( $category -and $category -ne '' ) {
        $torrents_list = $torrents_list | Where-Object { $_.category -eq "${category}" }
    }
    foreach ( $torrent in $torrents_list) {
        $i++
        $new_path = $torrent.save_path.replace( $path_from, $path_to )
        if ( $new_path -ne $torrent.save_path ) {
            $sum_size += $torrent.size
            if ( $max_size -gt 0 -and $sum_size -gt $max_size ) {
                Write-Log 'Достигнут максимальный объём'
                break
            }
            Set-SaveLocation $client $torrent $new_path
            Write-Progress -Activity 'Moving' -Status $torrent.name -PercentComplete ( $i * 100 / $torrents_list.Count )
            Start-Sleep -Milliseconds 100
        }
    }
    Write-Progress -Activity 'Moving' -Completed
}
