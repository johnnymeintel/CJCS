# Create .gitkeep in all empty subfolders of the current directory
$root = Get-Location
$folders = Get-ChildItem -Recurse -Directory

foreach ($folder in $folders) {
    # check if folder is empty (no files or subdirectories)
    $contents = Get-ChildItem -LiteralPath $folder.FullName -Force
    if ($contents.Count -eq 0) {
        $gitkeepPath = Join-Path $folder.FullName ".gitkeep"
        if (-not (Test-Path $gitkeepPath)) {
            New-Item -Path $gitkeepPath -ItemType File -Force | Out-Null
            Write-Host "Added .gitkeep -> $($folder.FullName)" -ForegroundColor Green
        }
    }
}

Write-Host "`nScan complete. .gitkeep files added to all empty directories under:" -ForegroundColor Cyan
Write-Host $root
