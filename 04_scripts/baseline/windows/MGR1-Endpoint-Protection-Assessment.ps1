Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,QuickScanAge,FullScanAge   # Windows Defender status and last-scan/signature recency
Get-WmiObject -Class AntiVirusProduct -Namespace "root\SecurityCenter2" | Select-Object displayName,productState   # enumerate registered AV products and reported product state via SecurityCenter2
