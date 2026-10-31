# General-user read-only CCD capture. No elevation or topology changes.
$ErrorActionPreference='Stop'
$Project=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Out=Join-Path $Project ('.local\evidence\display-paths-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $Out|Out-Null
$OldTemp=$env:TEMP;$OldTmp=$env:TMP
$Report=[ordered]@{schema=1;changes_performed=$false;gpu_workload=$false;ok=$false;error=$null;data=$null}
try{
    $env:TEMP=$Out;$env:TMP=$Out
    Add-Type -Path (Join-Path $PSScriptRoot 'ReadOnlyDisplayConfig.cs')
    $Report.data=[RtxReadOnlyDisplayConfig]::Capture();$Report.ok=$true
}catch{$Report.error=$_.Exception.Message}
finally{$env:TEMP=$OldTemp;$env:TMP=$OldTmp}
$Report|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $Out 'report.json') -Encoding UTF8
Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath,(Join-Path $PSScriptRoot 'ReadOnlyDisplayConfig.cs')|Select-Object Path,Hash|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Out 'source-hashes.json') -Encoding UTF8
Write-Output "CCD read-only result: $Out"
if(!$Report.ok){throw $Report.error}
Write-Output ('Active paths: '+$Report.data.Paths.Count)
