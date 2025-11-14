# Calculates the average CPU load over 60 seconds
$CPUAverage = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 60 |
    Select-Object -ExpandProperty CounterSamples |
    Measure-Object -Property CookedValue -Average).Average
[PSCustomObject]@{ Metric = "Average CPU % (60s)"; Value = [math]::Round($CPUAverage, 2) }

# Checks the memory used by the critical LSASS process (credential dumping indicator)
Get-Process lsass | Select-Object WS,PM,VM

# Calculates total system memory usage percentage
$OS = Get-CimInstance Win32_OperatingSystem
$MemUsed = [math]::Round((($OS.TotalVisibleMemorySize - $OS.FreePhysicalMemory) / $OS.TotalVisibleMemorySize) * 100, 2)
[PSCustomObject]@{ Metric = "Total Memory Utilization"; Value = "$MemUsed%" }