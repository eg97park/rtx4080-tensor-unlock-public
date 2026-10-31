# CPU-only: every user32 import in the compiled test copy is a throwing stub.
# No device queries, display mutation, CUDA, administrator token or GPU access.
[CmdletBinding()]param([string]$ReplayDirectory,[string]$HighRefreshFile)
$ErrorActionPreference='Stop'
$Project=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Out=Join-Path $Project ('.local\evidence\display-isolation-host-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $Out|Out-Null
$OldTemp=$env:TEMP;$OldTmp=$env:TMP
$Report=[ordered]@{schema=1;gpu_access=$false;native_api_imports=0;native_api_stubs=0;cases=@();replays=@();ok=$false;error=$null}
try{
    $env:TEMP=$Out;$env:TMP=$Out
    $Paths=@()
    $Pattern='(?m)^\s*\[DllImport\("user32.dll"\)\] private static extern int ([^\r\n;]+);'
    foreach($Name in @('ReadOnlyDisplayConfig.cs','DisplayIsolation.cs')){
        $Source=Get-Content -LiteralPath (Join-Path $PSScriptRoot $Name) -Raw
        $Count=[regex]::Matches($Source,$Pattern).Count
        if($Count -ne $(if($Name -eq 'ReadOnlyDisplayConfig.cs'){3}else{1})){throw 'Unexpected native boundary; no compilation allowed.'}
        $Report.native_api_stubs+=$Count
        $Source=[regex]::Replace($Source,$Pattern,'    private static int $1 { throw new InvalidOperationException("Native display API forbidden in host test"); }')
        if($Source -match 'DllImport|extern '){throw 'Native import remains; no compilation allowed.'}
        $Path=Join-Path $Out $Name;$Source|Set-Content -LiteralPath $Path -Encoding ASCII;$Paths+=$Path
    }
    $TestFile=Join-Path $Project 'tests\test_display_isolation.cs'
    Add-Type -Path @($Paths+$TestFile)
    $Report.cases=@([DisplayIsolationHostTests]::Run())
    if($ReplayDirectory -or $HighRefreshFile){
        Add-Type -AssemblyName System.Web.Extensions
        $Serializer=New-Object Web.Script.Serialization.JavaScriptSerializer
        if($ReplayDirectory){
            $Before=$Serializer.Deserialize((Get-Content -LiteralPath (Join-Path $ReplayDirectory 'before.json') -Raw),[RtxReadOnlyDisplayConfig+Snapshot])
            $During=$Serializer.Deserialize((Get-Content -LiteralPath (Join-Path $ReplayDirectory 'during.json') -Raw),[RtxReadOnlyDisplayConfig+Snapshot])
            [RtxDisplayIsolation]::VerifyIntelRetained([RtxDisplayIsolation]::Prepare($Before),$During)
            $Report.replays+=@{case='preserved 60Hz before/during capture';pass=$true}
        }
        if($HighRefreshFile){
            $Data=(Get-Content -LiteralPath $HighRefreshFile -Raw|ConvertFrom-Json).data|ConvertTo-Json -Depth 15
            $Snapshot=$Serializer.Deserialize($Data,[RtxReadOnlyDisplayConfig+Snapshot])
            $Plan=[RtxDisplayIsolation]::Prepare($Snapshot)
            if(!$Plan.AlreadyIsolated -or [RtxDisplayIsolation]::Apply($Plan,$false) -ne 0){throw 'Recorded Intel-only topology was not a no-op.'}
            [RtxDisplayIsolation]::VerifyIntelRetained($Plan,$Snapshot)
            $Report.replays+=@{case='preserved 144Hz single-display capture';pass=$true}
        }
    }
    $ParseErrors=$null;$Tokens=$null
    [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-DisplayIsolation.ps1'),[ref]$Tokens,[ref]$ParseErrors)|Out-Null
    if($ParseErrors.Count){throw 'Display script syntax failed.'}
    $Report.source_sha256=@(Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PSScriptRoot 'ReadOnlyDisplayConfig.cs'),(Join-Path $PSScriptRoot 'DisplayIsolation.cs'),(Join-Path $PSScriptRoot 'Test-DisplayIsolation.ps1'),$TestFile,$PSCommandPath|Select-Object Path,Hash)
    $Report.ok=$true
}catch{$Report.error=$_.Exception.Message}
finally{
    $env:TEMP=$OldTemp;$env:TMP=$OldTmp
    $Report|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $Out 'report.json') -Encoding UTF8
}
Write-Output "CPU-only display tests: $Out"
if(!$Report.ok){throw $Report.error}
Write-Output ($Report.cases.Count.ToString()+' synthetic checks and '+$Report.replays.Count+' saved-data replays passed; native APIs blocked.')
