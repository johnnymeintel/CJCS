Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort # Gets listening TCP ports - baseline for detecting rogue services and backdoors
$procByPid = Get-CimInstance Win32_Process | Group-Object -Property ProcessId -AsHashTable -AsString # Creates process lookup table by PID for correlation analysis
Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object { # Maps listening ports to processes and executables - critical for malware detection and unauthorized service identification
    $p = $procByPid[[string]$_.OwningProcess]
    [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        PID = $_.OwningProcess
        ProcessName = $p.Name
        ExecutablePath = $p.ExecutablePath
    }
}