Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID,Description,InstalledOn | Select-Object -First 10   # list the 10 most recently installed Windows updates and hotfixes
Get-Service wuauserv | Select-Object Name,Status,StartType                                              # check if Windows Update (wuauserv) service is running and its startup type
