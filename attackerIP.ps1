Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | 
ForEach-Object {
    $message = $_.Message
    if ($message -match "Source Network Address:\s+(\d{1,3}(?:\.\d{1,3}){3})") {
        $matches[1]
    }
} | Sort-Object | Get-Unique
