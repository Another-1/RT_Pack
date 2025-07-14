$settings_file = Join-Path $PSScriptRoot 'settings.json'
if ( Test-Path $settings_file ) {
    # $debug = 1
    # Write-Output "Подгружаем настройки из $settings_file"
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

Test-ForumWorkingHours -verbose -break

if ( !$debug ) {
    Test-PSVersion
    Test-Module 'PsIni' 'для чтения настроек TLO'
    Write-Log 'Проверяем актуальность скриптов' 
    if ( ( Test-Version -name '_functions.ps1' -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '') ) -eq $true ) {
        Write-Log 'Запускаем новую версию _functions.ps1'
        . ( Join-Path $PSScriptRoot '_functions.ps1' )
    }
    Test-Version -name ( $PSCommandPath | Split-Path -Leaf ) -mess_sender ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')
}

if ( !$settings.interface ) { $settings.interface = [ordered]@{} }
if ( $standalone -eq $true ) { $settings.interface.use_timestamp = Test-Setting 'use_timestamp' -json_path 'interface' -required } else { $settings.interface.use_timestamp = Test-Setting 'use_timestamp' -required }
if ( $standalone -eq $false ) {
    $tlo_path = Test-Setting 'tlo_path' -required
    $ini_path = Join-Path $tlo_path 'data' 'config.ini'
    Write-Log 'Читаем настройки Web-TLO'
    $ini_data = Get-IniContent $ini_path
}
if ( !$settings.connection -and $standlone -ne $true ) {
    if ( !$settings.connection ) { $settings.connection = [ordered]@{} }
    Set-ConnectDetails $settings
    Set-Proxy( $settings )
}
if ( $ini_data ) { $section_numbers = $ini_data.sections.subsections.split( ',' ) } else { $section_numbers = $settings.sections.keys }
if ( $standalone -ne $true ) {
    Get-Clients
}

Write-Log 'Выберите исходный клиент'
$client = Select-Client
Initialize-Client $client
if ( !$torrents_list ) {
    $torrents_list = Get-ClientTorrents -client $client -mess_sender 'Mover' -verbos
}

if ( !$tracker_torrents ) {
    $tracker_torrents = Get-RepTorrents -sections $section_numbers $section_numbers -id $settings.connection.user_id -api_key $settings.connection.api_key `
        -call_from ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')
}
Write-Log 'Получаем названия всех подразделов'
$existing_sections = (( Get-ApiHTTP -url '/v1/static/cat_forum_tree' ) | ConvertFrom-Json -AsHashtable ).result.f
$i = 0
foreach ( $torrent in $torrents_list ) {
    $i++
    try {
        if ( $torrent.category -ne $existing_sections[$tracker_torrents[$torrent.hash].section] ) {
            Set-Category -client $client -torrent $torrent -category $existing_sections[$tracker_torrents[$torrent.hash].section] -call_from ( $PSCommandPath | Split-Path -Leaf ).replace('.ps1', '')
        }
    }
    catch { }
    Write-Progress -Activity scanning -Status $torrent.name -PercentComplete ( $i * 100 / $torrents_list.Count )
}
Write-Log 'Готово'
Write-Progress -Activity scanning -Completed
Remove-Variable -Name 'torrents_list'
