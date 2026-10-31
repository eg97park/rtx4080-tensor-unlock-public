# General-user read-only display diagnostics. Does not elevate or change settings.
[CmdletBinding()]
param([ValidateSet('unlocked-symptomatic','stock-recovery','cold-stock','unspecified')][string]$Label='unspecified')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Project=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Stamp=Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$Out=Join-Path $Project ('.local\evidence\display-health-'+$Stamp+'-'+$Label)
New-Item -ItemType Directory -Path $Out | Out-Null
$Report=[ordered]@{schema_version=1;label=$Label;utc=(Get-Date).ToUniversalTime().ToString('o');settings_changed=$false;gpu_workload=$false;queries=[ordered]@{}}
function Read-Query([string]$Name,[scriptblock]$Query) {
    try {$Report.queries[$Name]=@{ok=$true;data=@(& $Query)}}
    catch {$Report.queries[$Name]=@{ok=$false;error=$_.Exception.Message}}
}
Read-Query 'os' {Get-CimInstance Win32_OperatingSystem | Select-Object Version,LastBootUpTime,SystemDrive}
Read-Query 'current_partition' {Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) | Select-Object DiskNumber,PartitionNumber,DriveLetter,Guid,Size}
Read-Query 'video' {Get-CimInstance Win32_VideoController | Select-Object Name,PNPDeviceID,ConfigManagerErrorCode,DriverVersion,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate}
Read-Query 'monitors' {
    foreach($m in @(Get-PnpDevice -Class Monitor -PresentOnly)) {
        $parent=(Get-PnpDeviceProperty -InstanceId $m.InstanceId -KeyName 'DEVPKEY_Device_Parent').Data
        $p=Get-PnpDevice -InstanceId $parent
        [pscustomobject]@{name=$m.FriendlyName;id=$m.InstanceId;status=$m.Status;parent=$parent;parent_name=$p.FriendlyName;parent_class=$p.Class}
    }
}
$OldTemp=$env:TEMP; $OldTmp=$env:TMP
try {
    $env:TEMP=$Out; $env:TMP=$Out
    Read-Query 'gdi' {
        Add-Type -Path (Join-Path $PSScriptRoot 'ReadOnlyDisplay.cs')
        [RtxReadOnlyDisplay]::Enumerate()
    }
    Read-Query 'screens' {
        Add-Type -AssemblyName System.Windows.Forms
        [Windows.Forms.Screen]::AllScreens | ForEach-Object {
            [pscustomobject]@{name=$_.DeviceName;primary=$_.Primary;x=$_.Bounds.X;y=$_.Bounds.Y;width=$_.Bounds.Width;height=$_.Bounds.Height}
        }
    }
} finally {$env:TEMP=$OldTemp; $env:TMP=$OldTmp}
$Start=(Get-Date).AddMinutes(-30)
Read-Query 'system_graphics_events' {
    $events=@(Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$Start;Level=@(1,2,3)} -MaxEvents 500 -ErrorAction SilentlyContinue -ErrorVariable EventError)
    if($EventError -and @($EventError | Where-Object {$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'}).Count){throw $EventError[0]}
    $events | Where-Object {$_.ProviderName -match 'Display|nvlddmkm|igfx|igdkmd|Intel.*Graphics|Dxg|WHEA'} | Select-Object TimeCreated,ProviderName,Id,LevelDisplayName,Message
}
Read-Query 'application_graphics_events' {
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$Start;Id=@(1000,1001)} -MaxEvents 200 -ErrorAction SilentlyContinue -ErrorVariable EventError)
    if($EventError -and @($EventError | Where-Object {$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'}).Count){throw $EventError[0]}
    $events | Where-Object {$_.Message -match 'LiveKernelEvent|dwm\.exe|nvlddmkm|igdkmd|igfx'} | Select-Object TimeCreated,ProviderName,Id,Message
}
foreach($Log in @('Microsoft-Windows-Dwm-Core/Operational','Microsoft-Windows-DxgKrnl/Operational')) {
    Read-Query $Log {
        $Info=Get-WinEvent -ListLog $Log
        if(!$Info.IsEnabled){[pscustomobject]@{enabled=$false;note='Not enabled; no logging settings changed'};return}
        $events=@(Get-WinEvent -FilterHashtable @{LogName=$Log;StartTime=$Start} -MaxEvents 100 -ErrorAction SilentlyContinue -ErrorVariable EventError)
        if($EventError -and @($EventError | Where-Object {$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'}).Count){throw $EventError[0]}
        $events | Select-Object TimeCreated,ProviderName,Id,LevelDisplayName,Message
    }
}
$Report.event_window_start=$Start.ToUniversalTime().ToString('o')
$Report.queries_are_bounded=$true
$Report | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath (Join-Path $Out 'report.json') -Encoding UTF8
Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath,(Join-Path $PSScriptRoot 'ReadOnlyDisplay.cs') | Select-Object Path,Hash | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Out 'source-hashes.json') -Encoding UTF8
Write-Output ('Read-only display report: '+(Join-Path $Out 'report.json'))
foreach($Name in $Report.queries.Keys){Write-Output ($Name+': '+$Report.queries[$Name].ok)}
