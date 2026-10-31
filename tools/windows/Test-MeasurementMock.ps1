# Run the exact orchestration script with CPU-only primitives in an isolated tree.
# The fake .exe/.dll files are text, never passed to Windows CreateProcess.
[CmdletBinding()]
param([string[]]$DisplayReplayFiles=@())
$ErrorActionPreference='Stop'
$Project=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$TestRoot=Join-Path $Project ('.local\evidence\measurement-mock-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory $TestRoot | Out-Null
$Scenarios=@('success','fractional_temperature','overheat','fractional_overheat','nan_temperature','infinite_temperature','unavailable_temperature','active_overheat','telemetry_timeout','accuracy','empty_results','process_error','event','dll_mismatch',
    'context_unavailable','duplicate_display','refresh_changed','boot_changed','volume_changed','timing_changed','mode_reindexed','invalid_refresh','missing_mode')
$Results=@()
foreach($ScenarioName in $Scenarios){
    $global:RtxMockScenario=$ScenarioName; $global:RtxMockLaunches=0; $global:RtxMockKills=0; $global:RtxMockTelemetryCount=0; $global:RtxMockStopped=$false
    $Root=Join-Path $TestRoot $ScenarioName
    $Scripts=Join-Path $Root 'tools\windows';$Build=Join-Path $Root 'build\windows';$Dlls=Join-Path $Root 'cuda\bin'
    foreach($Path in @($Scripts,$Build,$Dlls)){New-Item -ItemType Directory $Path -Force | Out-Null}
    foreach($Name in @('Measure-Benchmark.ps1','Review-MeasurementHealth.ps1','Measurement-Context.ps1')){
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $Name) -Destination $Scripts
    }
    $global:RtxMockDisplayFile=Join-Path $Project 'tests\fixtures\measurement-display.json'
    @'
function Get-MeasurementDisplaySnapshot([string]$ScratchDirectory) {
    if($global:RtxMockScenario -eq 'context_unavailable'){throw 'Synthetic display read failure.'}
    $Snapshot=Get-Content -LiteralPath $global:RtxMockDisplayFile -Raw|ConvertFrom-Json
    if($global:RtxMockScenario -eq 'duplicate_display'){$Snapshot.Paths+=@($Snapshot.Paths[0])}
    if($global:RtxMockScenario -eq 'invalid_refresh'){$Snapshot.Paths[0].Native.Target.Refresh.Denominator=0}
    if($global:RtxMockScenario -eq 'missing_mode'){$Snapshot.Modes[0].PSObject.Properties.Remove('Raw5')}
    if($global:RtxMockLaunches){
        if($global:RtxMockScenario -eq 'refresh_changed'){$Snapshot.Paths[0].Native.Target.Refresh.Numerator++}
        if($global:RtxMockScenario -eq 'timing_changed'){$Snapshot.Modes[0].Raw0++}
        if($global:RtxMockScenario -eq 'mode_reindexed'){
            $Snapshot.Modes=@($Snapshot.Modes[1],$Snapshot.Modes[0],$Snapshot.Modes[2])
            $Snapshot.Paths[0].SourceModeIndex=0;$Snapshot.Paths[0].TargetModeIndex=1
            $Snapshot.Paths[0].Native.Source.ModeIndex=65535;$Snapshot.Paths[0].Native.Target.ModeIndex=65538
        }
    }
    return $Snapshot
}
'@ | Set-Content -LiteralPath (Join-Path $Scripts 'Read-MeasurementDisplay.ps1') -Encoding ASCII
    @'
function Invoke-ReadOnlyNvidiaQuery([string]$Executable,[string]$Fields,[int]$TimeoutMs=4000) {
    if($Executable -ne 'HOST_MOCK_NO_EXECUTABLE'){throw 'Unexpected native command in mock.'}
    if($Fields -like 'timestamp,*'){
        $global:RtxMockTelemetryCount++
        if($global:RtxMockScenario -eq 'telemetry_timeout' -and $global:RtxMockLaunches){throw 'NVIDIA telemetry query timed out; no retry.'}
        if($global:RtxMockScenario -eq 'overheat'){return 'fixture, 83, 10, 1000, 1000, 0'}
        if($global:RtxMockScenario -eq 'fractional_temperature'){return 'fixture, 35.44, 10, 1000, 1000, 0'}
        if($global:RtxMockScenario -eq 'fractional_overheat'){return 'fixture, 83.01, 10, 1000, 1000, 0'}
        if($global:RtxMockScenario -eq 'nan_temperature'){return 'fixture, NaN, 10, 1000, 1000, 0'}
        if($global:RtxMockScenario -eq 'infinite_temperature'){return 'fixture, Infinity, 10, 1000, 1000, 0'}
        if($global:RtxMockScenario -eq 'unavailable_temperature'){return 'fixture, N/A, 10, 1000, 1000, 0'}
        if($global:RtxMockScenario -eq 'active_overheat' -and $global:RtxMockLaunches){return 'fixture, 83, 10, 1000, 1000, 0'}
        return 'fixture, 40, 10, 1000, 1000, 0'
    }
    return 'fixture-control'
}
'@ | Set-Content -LiteralPath (Join-Path $Scripts 'Native-ReadOnly.ps1') -Encoding ASCII
    $Exe=Join-Path $Build 'windows_bench.exe';'TEXT ONLY - MUST NOT EXECUTE'|Set-Content -LiteralPath $Exe
    $Pins=@{}
    foreach($Name in @('cublas64_13.dll','cublasLt64_13.dll')){
        'TEXT ONLY - MUST NOT LOAD'|Set-Content -LiteralPath (Join-Path $Dlls $Name)
        $Pins[$Name]=(Get-FileHash -LiteralPath (Join-Path $Dlls $Name) -Algorithm SHA256).Hash.ToLower()
    }
    @{artifacts=@{'windows_bench.exe'=(Get-FileHash $Exe -Algorithm SHA256).Hash.ToLower()};cuda_root=(Split-Path $Dlls);cuda_dll_directory=$Dlls;cublas_dlls=$Pins}|
        ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $Build 'manifest.json') -Encoding UTF8
    $global:RtxMockMockDlls=$Dlls
    function Get-CimInstance {param($ClassName,$Filter,$ErrorAction)
        switch($ClassName){
            'Win32_VideoController' {
                return @([pscustomobject]@{Name='fixture NVIDIA';PNPDeviceID='PCI\VEN_10DE&DEV_2704&SUBSYS_15007377';ConfigManagerErrorCode=0},
                    [pscustomobject]@{Name='fixture Intel';PNPDeviceID='PCI\VEN_8086&DEV_7D67';ConfigManagerErrorCode=0})
            }
            'Win32_OperatingSystem' {
                $Boot=[datetime]::Parse('2026-10-01T00:00:00Z').ToUniversalTime()
                if($global:RtxMockScenario -eq 'boot_changed' -and $global:RtxMockLaunches){$Boot=$Boot.AddSeconds(1)}
                return [pscustomobject]@{SystemDrive='C:';WindowsDirectory='C:\Windows';Version='10.0.fixture';BuildNumber='fixture';LastBootUpTime=$Boot}
            }
            'Win32_LogicalDisk' {
                if($Filter -cne "DeviceID='C:'"){throw 'Unexpected logical disk query.'}
                $Serial=if($global:RtxMockScenario -eq 'volume_changed' -and $global:RtxMockLaunches){'22222222'}else{'11111111'}
                return [pscustomobject]@{DriveType=3;VolumeSerialNumber=$Serial}
            }
            default {throw 'Unexpected CIM call in mock.'}
        }
    }
    function Get-Command {param($Name,$ErrorAction)
        if($Name -ne 'nvidia-smi.exe'){throw 'Unexpected command lookup.'}
        [pscustomobject]@{Source='HOST_MOCK_NO_EXECUTABLE'}
    }
    function Get-WinEvent {param($FilterHashtable,$ErrorAction)
        if($global:RtxMockScenario -eq 'event' -and $global:RtxMockLaunches){[pscustomobject]@{ProviderName='nvlddmkm';Id=999;Message='synthetic event'}}
    }
    function Start-Process {param($FilePath,$ArgumentList,$WorkingDirectory,[switch]$PassThru,[switch]$NoNewWindow,$RedirectStandardOutput,$RedirectStandardError)
        $global:RtxMockLaunches++
        if((Get-Content -LiteralPath $FilePath -Raw) -notlike 'TEXT ONLY*'){throw 'Mock refused a real executable.'}
        $Issue=$ArgumentList[1] -eq 'issue'; $Reps=[int]$ArgumentList[$(if($Issue){2}else{5})]
        $Modes=if($Issue){@('f16_f32','bf16_f32','tf32')}else{@('f16_f32','bf16_f32','tf32','fp32_pedantic')}
        $Rows=@($Modes | ForEach-Object {@{mode=$_;kind=$(if($Issue){'mma_issue'}else{'gemm'});accuracy_pass=($global:RtxMockScenario -ne 'accuracy');samples_ms=@(1)*$Reps;
            all_sinks_checked_each_repeat=$true;all_outputs_finite=$true;validation_runs=2;checked_per_validation=100;nrmse=0;initial_nrmse=0}})
        if($global:RtxMockScenario -eq 'empty_results'){$Rows=@()}
        $Loaded=@{};foreach($Name in @('cublas64_13.dll','cublasLt64_13.dll')){$Loaded[$Name]=Join-Path $global:RtxMockMockDlls $Name}
        if($global:RtxMockScenario -eq 'dll_mismatch'){$Loaded['cublas64_13.dll']='wrong.dll'}
        @{schema_version=1;device='NVIDIA GeForce RTX 4080';reps=$Reps;complete=$true;results=$Rows;dll_paths=$Loaded}|
            ConvertTo-Json -Depth 8|Set-Content -LiteralPath $RedirectStandardOutput -Encoding UTF8
        ''|Set-Content -LiteralPath $RedirectStandardError
        $P=[pscustomobject]@{HasExited=$false;ExitCode=$(if($global:RtxMockScenario -eq 'process_error'){1}else{0});Id=-2704;Handle=1;Polls=0}
        $P|Add-Member ScriptMethod WaitForExit {param($Ms) $this.Polls++;if($global:RtxMockScenario -in @('telemetry_timeout','active_overheat') -and !$global:RtxMockStopped){return $false};$this.HasExited=$true;return $true}
        $P|Add-Member ScriptMethod Refresh {}
        $P|Add-Member ScriptMethod Dispose {}
        return $P
    }
    function Stop-Process {param($Id,$ErrorAction) if($Id -ne -2704){throw 'Mock refused real process ID.'};$global:RtxMockKills++;$global:RtxMockStopped=$true}
    $Failed=$false
    try{& (Join-Path $Scripts 'Measure-Benchmark.ps1') -RunApproved -Suite smoke -State stock | Out-Null}catch{$Failed=$true}
    $Runs=@(Get-ChildItem -LiteralPath (Join-Path $Root '.local\measurements') -Filter run.json -Recurse)
    if($Runs.Count -ne 1){throw "Mock $ScenarioName did not preserve run.json"}
    $Run=Get-Content $Runs[0].FullName -Raw | ConvertFrom-Json
    $EventFile=Join-Path $Runs[0].DirectoryName 'events.json'
    if(!(Test-Path -LiteralPath $EventFile)){throw 'Event query result was not preserved, including the empty case.'}
    if($ScenarioName -in @('success','fractional_temperature','mode_reindexed')){
        if($Failed -or !$Run.complete -or $Run.cases.Count -ne 3 -or $global:RtxMockLaunches -ne 3){throw 'Successful synthetic measurement failed.'}
        if($Run.schema_version -ne 2 -or $Run.context_checks.Count -ne 8){throw 'Context checkpoints not preserved.'}
    }else{
        if(!$Failed -or $Run.complete -or !$Run.failures.Count){throw "Mock $ScenarioName was not stopped/logged."}
        if($global:RtxMockLaunches -gt 1){throw 'Failed case was retried or followed by another case.'}
        if($ScenarioName -in @('overheat','fractional_overheat','nan_temperature','infinite_temperature','unavailable_temperature','context_unavailable','duplicate_display','invalid_refresh','missing_mode') -and $global:RtxMockLaunches){throw 'Invalid/hot GPU or display condition did not stop before launch.'}
        if($ScenarioName -in @('refresh_changed','boot_changed','volume_changed','timing_changed') -and
           ($global:RtxMockLaunches -ne 1 -or $Run.context_checks[-1].stage -ne 'case-0-after')){throw 'Changed context was not preserved and stopped after the first case.'}
        if($ScenarioName -in @('telemetry_timeout','active_overheat') -and ($global:RtxMockKills -ne 1 -or $null -eq $Run.stopped_case)){throw 'Active benchmark stop was not confirmed.'}
    }
    $Results+=@{scenario=$ScenarioName;pass=$true;launches=$global:RtxMockLaunches;stops=$global:RtxMockKills}
    if($ScenarioName -eq 'success'){
        foreach($PostScenario in @('success','boot_changed','refresh_changed','volume_changed','context_unavailable')){
            $global:RtxMockScenario=$PostScenario;$PostFailed=$false
            try{& (Join-Path $Scripts 'Review-MeasurementHealth.ps1') -RunName $Runs[0].Directory.Name|Out-Null}catch{$PostFailed=$true}
            $HealthFile=Get-ChildItem -LiteralPath $Runs[0].DirectoryName -Filter 'post-health-*.json'|Sort-Object Name|Select-Object -Last 1
            $Health=Get-Content -LiteralPath $HealthFile.FullName -Raw|ConvertFrom-Json
            $Expected=$PostScenario -eq 'success'
            if($PostFailed -eq $Expected -or $Health.healthy -ne $Expected -or $Health.context_verified -ne $Expected -or
               $Health.gpu_workload_started -ne $false -or $global:RtxMockLaunches -ne 3){throw "Post-health context scenario failed: $PostScenario"}
            $Results+=@{scenario=('post-health-'+$PostScenario);pass=$true;launches_added=0}
        }
    }
}
# Saved-data replay only. The sourced boundary is still the mock, no Add-Type.
. (Join-Path $Scripts 'Measurement-Context.ps1')
$Replays=@()
foreach($Replay in $DisplayReplayFiles){
    $Display=ConvertTo-MeasurementDisplay ((Get-Content -LiteralPath $Replay -Raw|ConvertFrom-Json).data)
    $Replays+=@{file_sha256=(Get-FileHash -LiteralPath $Replay -Algorithm SHA256).Hash.ToLower();display=$Display}
}
$ParseErrors=$null;$Tokens=$null
[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Read-MeasurementDisplay.ps1'),[ref]$Tokens,[ref]$ParseErrors)|Out-Null
if($ParseErrors.Count){throw 'Read-only CCD boundary syntax failed.'}
@{schema_version=1;gpu_access=$false;synthetic_only=$true;cases=$Results;replays=$Replays}|ConvertTo-Json -Depth 12|
    Set-Content -LiteralPath (Join-Path $TestRoot 'summary.json') -Encoding UTF8
Write-Output "$($Results.Count) CPU-only measurement/health scenarios and $($Replays.Count) saved-data replays passed: $TestRoot"
