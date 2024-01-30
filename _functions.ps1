function Write-Log ( $str, $red = $false ) {
    if ( $use_timestamp -ne 'Y' ) {
        if ( $red ) { Write-Host $str -ForegroundColor Red }
        else { Write-Host $str }
    }
    else {
        if ( $red ) { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) -ForegroundColor Red }
        else { Write-Host ( ( Get-Date -Format 'dd-MM-yyyy HH:mm:ss' ) + ' ' + $str ) }
    }
}

function Test-PSVersion {
    Write-Output 'Проверяем версию Powershell...'
    if ( $PSVersionTable.PSVersion -lt [version]'7.1.0.0') {
        Write-Log 'У вас слишком древний Powershell, обновитесь с https://github.com/PowerShell/PowerShell#get-powershell ' $true
        Pause
        Exit
    }
    else {
        Write-Log 'Версия достаточно свежая, продолжаем'
    }
}

function Test-Version ( $name ) {
    try {
        $separator = Get-Separator
        $old_hash = ( Get-FileHash -Path ( $PSScriptRoot + $separator + $name ) ).Hash
        $new_file_path = ( $PSScriptRoot + $separator + $name.replace( '.ps1', '.new' ) )
        Invoke-WebRequest -Uri ( 'https://raw.githubusercontent.com/Another-1/RT_Pack/main/' + $name ) -OutFile $new_file_path | Out-Null
        if ( Test-Path $new_file_path ) {
            $new_hash = ( Get-FileHash -Path $new_file_path ).Hash
            if ( $old_hash -ne $new_hash ) {
                Write-Log "$name обновился! Рекомендуется скачать новую версию." $true
            }
        }
        Remove-Item $new_file_path
    }
    catch {}
}
