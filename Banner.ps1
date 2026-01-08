#Settings
$ipfilter_source = 'https://bot.keeps.cyou/static/ipfilter.dat'

# Code
Write-Output 'Подгружаем настройки'

$separator = $( $PSVersionTable.OS.ToLower().contains('windows') ? '\' : '/' )
. ( $PSScriptRoot + $separator + '_settings.ps1' )

$str = 'Подгружаем функции'
if ( $use_timestamp -ne 'Y' ) { Write-Host $str } else { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) }
. "$PSScriptRoot\_functions.ps1"

$ipfilter_path = Test-Setting 'ipfilter_path'

Write-Log 'Проверяем версии скриптов'
Test-Version ( '_functions.ps1' ) 'Banner'
Test-Version ( $PSCommandPath | Split-Path -Leaf ) 'Banner'

if ( -not ( [bool](Get-InstalledModule -Name PSIni -ErrorAction SilentlyContinue) ) ) {
    Write-Log 'Не установлен модуль PSIni для чтения настроек Web-TLO, ставим...'
    Install-Module -Name PSIni -Scope CurrentUser -Force
}

Write-Log 'Скачиваем файл'
$new_path = $ipfilter_path -replace '\..+?$', '.new'
try {
    Invoke-WebRequest -Uri $ipfilter_source -OutFile $new_path
    if ( -not ( Test-Path -Path $ipfilter_path ) -or ( Get-FileHash -Path $ipfilter_path ).Hash -ne ( Get-FileHash -Path $new_path).Hash ) {
        Write-Log 'Файл обновился, перечитываем'
        Write-Log 'Читаем настройки Web-TLO'
        $ini_path = $tlo_path + '\data\config.ini'
        $ini_data = Remove-Quotes( Import-Ini $ini_path )
        $clients = Get-Clients
        Move-Item -Path $new_path -Destination $ipfilter_path -Force
        foreach ( $client_key in $clients.Keys ) {
            Initialize-Client $clients[$client_key]
            Write-Log ( 'Обновляем фильтр в клиенте ' + $clients[$client_key].Name )
            Switch-Filtering -client $clients[$client_key] -enable $false -mess_sender 'Banner'
            Start-Sleep -Seconds 1
            Switch-Filtering $clients[$client_key] -enable $true -mess_sender 'Banner'
            Write-Log 'Готово'
        }
        if ( $tg_token -and $tg_token -ne '' ) {
            Send-TGMessage -message 'Обновился файл блокировок.' -token $tg_token $tg_chat 'Banner'
        }
    }
    else {
        Write-Output 'Файл не изменился'
        Remove-Item $new_path -Force
    }
}
catch { Write-Host 'Не удалось скачать файл' -ForegroundColor Red }
 