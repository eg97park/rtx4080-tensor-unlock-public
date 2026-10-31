# Prepared for a separately approved native Windows workload. Never auto-runs.
[CmdletBinding()]
param([switch]$RunApproved, [ValidateSet('smoke','standard')][string]$Suite='smoke',
      [ValidateSet('stock','unlocked','restored')][string]$State='stock')
$ErrorActionPreference='Stop'
if(!$RunApproved){throw 'GPU workload requires explicit run approval. Review scope/stop conditions in docs/STATUS.md first.'}
. (Join-Path $PSScriptRoot 'Native-ReadOnly.ps1')
. (Join-Path $PSScriptRoot 'Measurement-Context.ps1')
$Project=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Build=Join-Path $Project 'build\windows'
$Manifest=Get-Content -LiteralPath (Join-Path $Build 'manifest.json') -Raw | ConvertFrom-Json
$Exe=Join-Path $Build 'windows_bench.exe'
$ExeHash=(Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLower()
if($ExeHash -ne $Manifest.artifacts.'windows_bench.exe'){throw 'Executable differs from reviewed build manifest.'}
$Cuda=$Manifest.cuda_root
$DllDirectory=$Manifest.cuda_dll_directory
foreach($Item in $Manifest.cublas_dlls.PSObject.Properties){
    if((Get-FileHash -LiteralPath (Join-Path $DllDirectory $Item.Name) -Algorithm SHA256).Hash.ToLower() -ne $Item.Value){throw 'cuBLAS DLL changed since build.'}
    if(Test-Path -LiteralPath (Join-Path $Build $Item.Name)){throw 'A local cuBLAS DLL would shadow the pinned toolkit DLL.'}
}
$Gpu=@(Get-CimInstance Win32_VideoController | Where-Object {$_.PNPDeviceID -like 'PCI\VEN_10DE&DEV_2704&SUBSYS_15007377*'})
if($Gpu.Count -ne 1 -or $Gpu[0].ConfigManagerErrorCode -ne 0){throw 'Target identity/driver health mismatch.'}
$Intel=@(Get-CimInstance Win32_VideoController | Where-Object {$_.PNPDeviceID -like 'PCI\VEN_8086*'})
if($Intel.Count -eq 0 -or @($Intel | Where-Object {$_.ConfigManagerErrorCode -ne 0}).Count){throw 'Intel display health check failed.'}
$Smi=(Get-Command nvidia-smi.exe -ErrorAction Stop).Source
function Read-Control {
    $Text=Invoke-ReadOnlyNvidiaQuery $Smi 'pci.bus_id,pci.device_id,pci.sub_device_id,vbios_version,driver_version,power.limit,clocks.max.sm,clocks.max.memory'
    return [string]$Text
}
$Control=Read-Control
$Dir=Join-Path $Project ('.local\measurements\'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff')+'-'+$State)
New-Item -ItemType Directory -Path $Dir | Out-Null
$Start=Get-Date
$Report=[ordered]@{schema_version=2;state=$State;suite=$Suite;start_utc=$Start.ToUniversalTime().ToString('o');
 exe_sha256=$ExeHash;cublas_dlls=$Manifest.cublas_dlls;control_before=$Control;complete=$false;
 max_temperature_c=83;case_timeout_seconds=60;suite_timeout_seconds=180;cases=@();event_review_required=$true;
 environment=@{};failures=@();launch_attempts=0;processes_started=0;context_checks=@()}
function Check-Context([string]$Stage) {
    $Context=Get-MeasurementContext $Dir
    $Context.stage=$Stage
    # Save the changed observation before rejecting it.
    $Report.context_checks+=@($Context)
    Assert-MeasurementContextUnchanged $Report.context_checks[0] $Context
}
function Check-Telemetry([int]$CaseIndex) {
    $Sample=Invoke-ReadOnlyNvidiaQuery $Smi 'timestamp,temperature.gpu,power.draw,clocks.sm,clocks.mem,utilization.gpu'
    "$CaseIndex,$Sample" | Add-Content -LiteralPath (Join-Path $Dir 'telemetry.csv') -Encoding UTF8
    $Fields=([string]$Sample).Split(',');[double]$Temperature=0
    if($Fields.Count -ne 6 -or ![double]::TryParse($Fields[1].Trim(),[Globalization.NumberStyles]::Float,[Globalization.CultureInfo]::InvariantCulture,[ref]$Temperature) -or
       [double]::IsNaN($Temperature) -or [double]::IsInfinity($Temperature) -or $Temperature -lt 0){throw 'Temperature unavailable.'}
    if($Temperature -ge 83){throw 'GPU temperature reached stop threshold (83 C).'}
}
function Recent-Events {
    try {
        return @(Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$Start} -ErrorAction Stop |
            Where-Object {$_.ProviderName -in @('Display','nvlddmkm','Microsoft-Windows-WHEA-Logger')} |
            Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message)
    } catch {
        if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){return @()}
        throw
    }
}
foreach($Name in @('NVIDIA_TF32_OVERRIDE','CUBLAS_WORKSPACE_CONFIG','CUBLAS_EMULATION_STRATEGY','CUDA_VISIBLE_DEVICES','CUDA_MODULE_LOADING','CUDA_LAUNCH_BLOCKING')){
    $Report.environment[$Name]=[Environment]::GetEnvironmentVariable($Name,'Process')
}
$Cases=if($Suite -eq 'smoke'){
    @(@('gemm','128','128','128','5','2704'),@('gemm','127','65','257','5','4080'),@('issue','5'))
}else{
    @(@('gemm','128','128','128','15','2704'),@('gemm','127','65','257','15','4080'),
      @('gemm','1024','1024','1024','15','2704'),@('gemm','4096','4096','4096','15','2704'),
      @('gemm','8192','8192','8192','15','2704'),@('gemm','4096','1024','2048','15','4080'),@('issue','15'))
}
$PreviousPath=$env:PATH
$SuiteTimer=[Diagnostics.Stopwatch]::StartNew()
try {
    Check-Context 'baseline'
    # Process-local DLL search path. Does not alter the user's PATH or toolkit.
    $env:PATH="$DllDirectory;$Cuda\bin;$env:PATH"
    for($Index=0;$Index -lt $Cases.Count;$Index++){
        if($SuiteTimer.Elapsed.TotalSeconds -gt 180){throw 'Suite exceeded 180-second bound.'}
        if((Read-Control) -ne $Control){throw 'Driver, power limit or clock limits changed; comparison invalid.'}
        Check-Telemetry $Index
        Check-Context "case-$Index-before"
        $Output=Join-Path $Dir ("case-$Index.json");$ErrorLog=Join-Path $Dir ("case-$Index.stderr.txt")
        $Report.launch_attempts++
        $Process=Start-Process -FilePath $Exe -ArgumentList (@('--run')+$Cases[$Index]) -WorkingDirectory $Build -PassThru -NoNewWindow -RedirectStandardOutput $Output -RedirectStandardError $ErrorLog
        $Report.processes_started++
        $null=$Process.Handle
        $Timer=[Diagnostics.Stopwatch]::StartNew()
        try {
            while(!$Process.WaitForExit(500)){
                Check-Telemetry $Index
                if($Timer.Elapsed.TotalSeconds -gt 60 -or $SuiteTimer.Elapsed.TotalSeconds -gt 180){throw 'Benchmark time bound exceeded (case 60 s / suite 180 s).'}
            }
            $Process.Refresh()
            if($Process.ExitCode -ne 0){throw "Benchmark case $Index failed ($($Process.ExitCode)); no retry."}
            Check-Context "case-$Index-after"
            $Data=Get-Content -LiteralPath $Output -Raw | ConvertFrom-Json
            $ExpectedModes=if($Cases[$Index][0] -eq 'issue'){@('f16_f32','bf16_f32','tf32')}else{@('f16_f32','bf16_f32','tf32','fp32_pedantic')}
            $ExpectedReps=[int]$Cases[$Index][$(if($Cases[$Index][0] -eq 'issue'){1}else{4})]
            if($Data.schema_version -ne 1 -or $Data.complete -ne $true -or $Data.reps -ne $ExpectedReps -or
               $Data.device -cne 'NVIDIA GeForce RTX 4080' -or @($Data.results).Count -ne $ExpectedModes.Count){throw 'Incomplete/failed benchmark result.'}
            foreach($Mode in $ExpectedModes){
                $Rows=@($Data.results | Where-Object {$_.mode -ceq $Mode})
                if($Rows.Count -ne 1 -or $Rows[0].accuracy_pass -ne $true){throw 'Missing/duplicate mode or failed accuracy.'}
                $Row=$Rows[0]
                if(@($Row.samples_ms).Count -ne $ExpectedReps){throw 'Missing timing repetitions.'}
                foreach($Timing in $Row.samples_ms){if(!($Timing -gt 0) -or [double]::IsInfinity([double]$Timing) -or [double]::IsNaN([double]$Timing)){throw 'Invalid timing sample.'}}
                if($Cases[$Index][0] -eq 'issue'){
                    if($Row.kind -cne 'mma_issue' -or $Row.all_sinks_checked_each_repeat -ne $true){throw 'Incomplete MMA sink check.'}
                }else{
                    if($Row.kind -cne 'gemm' -or $Row.all_outputs_finite -ne $true -or $Row.validation_runs -ne 2 -or $Row.checked_per_validation -lt 1){throw 'Incomplete GEMM validation.'}
                    $Limit=if($Mode -eq 'tf32'){0.002}else{0.00002}
                    foreach($Field in @('nrmse','initial_nrmse')){
                        $ErrorValue=$Row.$Field
                        if($null -eq $ErrorValue -or $ErrorValue -lt 0 -or $ErrorValue -gt $Limit -or [double]::IsNaN([double]$ErrorValue)){throw 'Accuracy threshold exceeded.'}
                    }
                }
            }
            foreach($Item in $Manifest.cublas_dlls.PSObject.Properties){
                $Loaded=$Data.dll_paths.($Item.Name)
                if(!$Loaded -or $Loaded -ne (Join-Path $DllDirectory $Item.Name)){throw 'Loaded cuBLAS location differs from pinned toolkit.'}
                if((Get-FileHash -LiteralPath $Loaded -Algorithm SHA256).Hash.ToLower() -ne $Item.Value){throw 'Loaded cuBLAS hash differs.'}
            }
            $Report.cases+=@{arguments=$Cases[$Index];file="case-$Index.json";sha256=(Get-FileHash $Output -Algorithm SHA256).Hash.ToLower()}
            Check-Telemetry $Index
            if(@(Recent-Events).Count){throw 'New display/driver/WHEA event; stop before the next case.'}
        } finally {
            try {
                if(!$Process.HasExited){
                    Stop-Process -Id $Process.Id -ErrorAction Stop
                    if(!$Process.WaitForExit(2000)){throw 'Benchmark process exit could not be confirmed; stop all further experiments.'}
                    $Report.stopped_case=$Index
                }
            } catch {
                $Report.process_stop_error=$_.Exception.Message
                throw
            } finally {$Process.Dispose()}
        }
    }
    $Report.control_after=Read-Control
    if($Report.control_after -ne $Control){throw 'Control snapshot changed after measurement.'}
    Check-Context 'final'
    $Report.complete=$true
} catch {
    $Report.failures+=@($_.Exception.Message)
} finally {
    $env:PATH=$PreviousPath
    try {
        $Events=@(Recent-Events)
        ConvertTo-Json -InputObject @($Events) -Depth 4 | Set-Content -LiteralPath (Join-Path $Dir 'events.json') -Encoding UTF8
        $Report.event_review_required=$Events.Count -gt 0
    } catch {
        if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){$Report.event_review_required=$false}
        else {$Report.event_query_error=$_.Exception.Message}
    }
    $Report.end_utc=(Get-Date).ToUniversalTime().ToString('o')
    $Report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $Dir 'run.json') -Encoding UTF8
}
if(!$Report.complete -or $Report.event_review_required){throw "Run needs review: $Dir. No retry/reset/reboot performed."}
Write-Output "Completed $Suite measurement: $Dir. Compare using tools/compare_bench.py."
