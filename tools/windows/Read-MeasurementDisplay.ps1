# Read-only boundary, kept separate so Host tests can replace it completely.
function Get-MeasurementDisplaySnapshot([string]$ScratchDirectory) {
    if(!('RtxReadOnlyDisplayConfig' -as [type])){
        $PreviousTemp=$env:TEMP;$PreviousTmp=$env:TMP
        try {
            $env:TEMP=$ScratchDirectory;$env:TMP=$ScratchDirectory
            Add-Type -Path (Join-Path $PSScriptRoot 'ReadOnlyDisplayConfig.cs')
        } finally {$env:TEMP=$PreviousTemp;$env:TMP=$PreviousTmp}
    }
    return [RtxReadOnlyDisplayConfig]::Capture()
}
