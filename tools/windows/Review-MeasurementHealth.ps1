# Post-run metadata/event collection only. Never runs or retries a CUDA workload.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidatePattern('^[0-9]{8}-[0-9]{6}-[0-9]{3}-(stock|unlocked|restored)$')][string]$RunName)
$ErrorActionPreference='Stop'
$Project=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Directory=Join-Path $Project ('.local\measurements\'+$RunName)
$RunFile=Join-Path $Directory 'run.json'
$Run=Get-Content -LiteralPath $RunFile -Raw | ConvertFrom-Json
$Start=[DateTimeOffset]::Parse($Run.start_utc).LocalDateTime
$End=Get-Date
$Report=[ordered]@{schema_version=1;gpu_workload_started=$false;run_sha256=(Get-FileHash $RunFile -Algorithm SHA256).Hash.ToLower();
    event_start_utc=$Start.ToUniversalTime().ToString('o');event_end_utc=$End.ToUniversalTime().ToString('o');errors=@();healthy=$false}
. (Join-Path $PSScriptRoot 'Native-ReadOnly.ps1')
. (Join-Path $PSScriptRoot 'Measurement-Context.ps1')
$Report.context_verified=$null
try {
    if($Run.schema_version -eq 2){
        $Report.context=Get-MeasurementContext $Directory
        if(@($Run.context_checks).Count -ne (2+2*@($Run.cases).Count) -or
           $Run.context_checks[0].stage -ne 'baseline' -or $Run.context_checks[-1].stage -ne 'final'){
            throw 'Run context checkpoints are incomplete.'
        }
        foreach($Context in $Run.context_checks){Assert-MeasurementContextUnchanged $Run.context_checks[0] $Context}
        Assert-MeasurementContextUnchanged $Run.context_checks[0] $Report.context
        $Report.context_verified=$true
    }elseif($Run.schema_version -ne 1){throw 'Unknown measurement schema.'}
} catch {$Report.context_verified=$false;$Report.errors+=@($_.Exception.Message)}
try {
    $Report.display=@(Get-CimInstance Win32_VideoController | Select-Object Name,PNPDeviceID,ConfigManagerErrorCode)
    $Target=@($Report.display | Where-Object {$_.PNPDeviceID -like 'PCI\VEN_10DE&DEV_2704&SUBSYS_15007377*'})
    $Intel=@($Report.display | Where-Object {$_.PNPDeviceID -like 'PCI\VEN_8086*'})
    if($Target.Count -ne 1 -or $Target[0].ConfigManagerErrorCode -ne 0 -or !$Intel.Count -or
       @($Intel | Where-Object {$_.ConfigManagerErrorCode -ne 0}).Count){throw 'Display identity/health mismatch.'}
} catch {$Report.errors+=@($_.Exception.Message)}
try {
    $Smi=(Get-Command nvidia-smi.exe -ErrorAction Stop).Source
    $Report.control=Invoke-ReadOnlyNvidiaQuery $Smi 'pci.bus_id,pci.device_id,pci.sub_device_id,vbios_version,driver_version,power.limit,clocks.max.sm,clocks.max.memory'
    if($Report.control -ne $Run.control_after){throw 'Driver/power/clock limits differ from the completed measurement.'}
} catch {$Report.errors+=@($_.Exception.Message)}
try {
    $Events=@()
    try {
        $Events=@(Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$Start;EndTime=$End} -ErrorAction Stop |
            Where-Object {$_.ProviderName -in @('Display','nvlddmkm','Microsoft-Windows-WHEA-Logger')} |
            Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message)
    } catch {if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
    $Report.events=$Events
    if($Events.Count){throw 'Display/driver/WHEA event observed since this measurement began.'}
} catch {$Report.errors+=@($_.Exception.Message)}
$Report.healthy=$Run.complete -eq $true -and $Run.event_review_required -eq $false -and
    @($Run.failures).Count -eq 0 -and $Report.errors.Count -eq 0
$Output=Join-Path $Directory ('post-health-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff')+'.json')
$Report|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $Output -Encoding UTF8
if(!$Report.healthy){throw "Read-only post-run health needs review: $Output. No retry/reset/settings changes."}
Write-Output "Read-only post-run health passed: $Output. No CUDA workload started."
