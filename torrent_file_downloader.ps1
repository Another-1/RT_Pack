param ( [string]$topicId )

Write-Output 'Подгружаем функции'
try { . ( Join-Path $PSScriptRoot '_functions.ps1' ); Write-Output 'Функции подгружены' } catch { Write-Host 'Не найден файл _functions.ps1' -ForegroundColor Red; exit 1 }

$settings_file = Join-Path $PSScriptRoot '_settings.ps1'
Write-Output "Подгружаем настройки из $settings_file"
try { . $settings_file; Write-Output 'Настройки подгружены' } catch { Write-Host 'Не найден файл настроек' -ForegroundColor Red; exit 1 }
$tlo_path = Test-Setting 'tlo_path' -required
$ini_path = Join-Path $tlo_path 'data' 'config.ini'
Test-Module 'PsIni' 'для чтения настроек TLO'
Write-Log 'Читаем настройки Web-TLO'
$ini_data = Get-IniContent $ini_path

Test-ForumWorkingHours -verbose

$settings = @{}
$settings.connection = @{}
Set-ConnectDetails $settings
Set-Proxy( $settings )

if ($topicId) {
    $torrentFilesReceived = 0
    $topicIds = $topicId.split(',')
    foreach ($id in $topicIds) {
        Write-Log "Получаем .torrent для раздачи $id..."
        $new_torrent_file = Get-ForumTorrentFile $id
        if (!$new_torrent_file) {
            Write-Log "Ошибка: не могу получить torrent-файл для раздачи $($id)!"
        }
        else {
            $minTorrentFileSizeBytes = 1000
            # Если размер .torrent-файла меньше определённого значения ($minTorrentFileSizeBytes), то это скорее всего сообщение об ошибке
            $fileSizeBytes = -1
            if (Test-Path -Path $new_torrent_file) {
                $fileInfo = Get-Item $new_torrent_file
                if ($fileInfo) { $fileSizeBytes = $fileInfo.Length; }
            }
            if ($fileSizeBytes -lt $minTorrentFileSizeBytes) {
                if ($fileSizeBytes -ge 0) {
                    $bakFname = "$new_torrent_file.bak"
                    Write-Log "Получен файл $new_torrent_file размером менее $minTorrentFileSizeBytes, переименовываем в $bakFname"
                    Rename-Item -Path $new_torrent_file -NewName $bakFname
                }
                else {
                    Write-Log "Ошибка: не могу прочитать файл $($new_torrent_file)!"
                }
            }
            else {
                Write-Log "Сохранено в $new_torrent_file ($fileSizeBytes)."
                $torrentFilesReceived++
            }
        }
    }
    Write-Log "Сохранено $torrentFilesReceived torrent-файлов."
    $exitCode = 1
    if ($torrentFilesReceived -ge 1) { $exitCode = 0 }
    # Если получен хотя бы один нормальный torrent-файл, выходим с кодом 0, иначе выходим с кодом 1
    exit $exitCode
}
else {
    Write-Log "`nНе указано ни одного ID раздачи" -Red
    Write-Log "`nПример правильного вызова:`ntorrent_file_downloader.ps1 103910,113457,117415`n"
}