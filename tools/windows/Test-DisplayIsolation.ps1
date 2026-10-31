# Default: capture/plan/SDC_VALIDATE only. -Apply is a separately approved
# 60-second temporary Intel-only desktop trial, with original topology restored
# in finally. -KeepForSession additionally requires approval to retain the
# successful topology for this session; it does not save a display configuration.
# No persistent display settings, driver changes, GPU reset or reboot.
[CmdletBinding()]param([switch]$Apply,[switch]$KeepForSession)
$ErrorActionPreference='Stop'
if($KeepForSession -and !$Apply){throw '-KeepForSession requires -Apply and explicit approval for session retention.'}
$Project=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Out=Join-Path $Project ('.local\evidence\display-isolation-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $Out|Out-Null
$Report=[ordered]@{schema=1;apply_requested=[bool]$Apply;applied=$false;restore_attempted=$false;restore_result=$null;
    gpu_reset=$false;persistent_settings_requested=$false;validation_result=$null;restore_validation_result=$null;restore_verified=$false;
    keep_for_session_requested=[bool]$KeepForSession;kept_for_session=$false;no_change_needed=$false;
    intel_mode_preserved=$false;error=$null}
$OldTemp=$env:TEMP;$OldTmp=$env:TMP
$Plan=$null;$Attempted=$false;$KeepActive=$false
function SaveReport {$Report|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $Out 'report.json') -Encoding UTF8}
try {
    $env:TEMP=$Out;$env:TMP=$Out
    Add-Type -Path @((Join-Path $PSScriptRoot 'ReadOnlyDisplayConfig.cs'),(Join-Path $PSScriptRoot 'DisplayIsolation.cs'))
    $Before=[RtxReadOnlyDisplayConfig]::Capture()
    $Plan=[RtxDisplayIsolation]::Prepare($Before)
    $Before|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $Out 'before.json') -Encoding UTF8
    @{paths_base64=$Plan.OriginalPathsBase64;modes_base64=$Plan.OriginalModesBase64;path_count=$Plan.Original.Length;mode_count=$Plan.Modes.Length}|
        ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $Out 'original-native.json') -Encoding UTF8
    $Report.no_change_needed=$Plan.AlreadyIsolated
    if($Plan.AlreadyIsolated){
        Write-Output 'Intel is already the sole active display. No SetDisplayConfig call or mode change is needed.'
    }else{
        $Report.validation_result=[RtxDisplayIsolation]::Validate($Plan,$false)
        $Report.restore_validation_result=[RtxDisplayIsolation]::Validate($Plan,$true);SaveReport
        if($Report.validation_result -ne 0){throw ('Temporary topology validation failed: '+$Report.validation_result)}
        if($Report.restore_validation_result -ne 0){throw ('Original topology validation failed: '+$Report.restore_validation_result)}
    }
    if($Apply -and !$Plan.AlreadyIsolated){
        # Re-read after saving files/validation. Do not apply a stale topology.
        $Fresh=[RtxDisplayIsolation]::Prepare([RtxReadOnlyDisplayConfig]::Capture())
        if($Fresh.OriginalPathsBase64 -cne $Plan.OriginalPathsBase64 -or $Fresh.OriginalModesBase64 -cne $Plan.OriginalModesBase64){throw 'Topology changed before apply.'}
        $Attempted=$true
        $Result=[RtxDisplayIsolation]::Apply($Plan,$false)
        $Report.apply_result=$Result;$Report.applied=$Result -eq 0;SaveReport
        if($Result -ne 0){throw ('Temporary topology apply failed: '+$Result)}
        $During=[RtxReadOnlyDisplayConfig]::Capture()
        $During|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $Out 'during.json') -Encoding UTF8
        [RtxDisplayIsolation]::VerifyIntelRetained($Plan,$During)
        $Report.intel_mode_preserved=$true;SaveReport
        if($KeepForSession){
            # Retain only after successful apply/readback and durable evidence.
            # No SAVE_TO_DATABASE; no automatic restore timer in this mode.
            $Report.kept_for_session=$true;SaveReport
            $KeepActive=$true
            Write-Output 'Intel-only desktop retained for this session, without saving a persistent configuration. No automatic restore timer.'
        }else{
            Write-Output 'Temporary Intel-only desktop active. Observe ordinary window movement; original topology restores after 60 seconds. Keep this process open.'
            Start-Sleep -Seconds 60
        }
    }
}catch{$Report.error=$_.Exception.Message}
finally{
    if($Attempted -and !$KeepActive -and $null -ne $Plan){
        $Report.kept_for_session=$false
        # Restoration must run even if writing the evidence directory fails.
        $Report.restore_attempted=$true
        try{$Report.restore_result=[RtxDisplayIsolation]::Apply($Plan,$true)}catch{$Report.restore_error=$_.Exception.Message}
        try{
            $After=[RtxReadOnlyDisplayConfig]::Capture()
            $After|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $Out 'after.json') -Encoding UTF8
            $Restored=[RtxDisplayIsolation]::Prepare($After)
            $Report.restore_verified=$Report.restore_result -eq 0 -and $Restored.OriginalPathsBase64 -ceq $Plan.OriginalPathsBase64 -and $Restored.OriginalModesBase64 -ceq $Plan.OriginalModesBase64
        }catch{$Report.after_error=$_.Exception.Message}
    }
    $env:TEMP=$OldTemp;$env:TMP=$OldTmp;SaveReport
}
Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath,(Join-Path $PSScriptRoot 'ReadOnlyDisplayConfig.cs'),(Join-Path $PSScriptRoot 'DisplayIsolation.cs')|
    Select-Object Path,Hash|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Out 'source-hashes.json') -Encoding UTF8
Write-Output "Display isolation result: $Out"
if($Report.error){throw $Report.error}
if($Attempted -and !$KeepActive -and !$Report.restore_verified){throw 'Original topology restore was not confirmed; stop, preserve report and do not repeat.'}
