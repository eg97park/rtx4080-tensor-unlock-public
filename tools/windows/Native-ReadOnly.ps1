# Bounded NVIDIA metadata queries. Arguments cannot select reset/set operations.
function Invoke-ReadOnlyNvidiaQuery([string]$Executable,[string]$Fields,[int]$TimeoutMs=4000) {
    if($Fields -notmatch '^[a-z0-9_.]+(,[a-z0-9_.]+)*$'){throw 'Invalid read-only NVIDIA query fields.'}
    $Info=New-Object Diagnostics.ProcessStartInfo
    $Info.FileName=$Executable
    $Info.Arguments='--query-gpu='+$Fields+' --format=csv,noheader,nounits'
    $Info.UseShellExecute=$false; $Info.CreateNoWindow=$true
    $Info.RedirectStandardOutput=$true; $Info.RedirectStandardError=$true
    $Process=New-Object Diagnostics.Process
    $Process.StartInfo=$Info
    try {
        if(!$Process.Start()){throw 'NVIDIA query did not start.'}
        $Output=$Process.StandardOutput.ReadToEndAsync(); $Errors=$Process.StandardError.ReadToEndAsync()
        if(!$Process.WaitForExit($TimeoutMs)){
            $Process.Kill(); [void]$Process.WaitForExit(2000)
            throw 'NVIDIA telemetry query timed out; no retry.'
        }
        $Text=$Output.GetAwaiter().GetResult(); $ErrorText=$Errors.GetAwaiter().GetResult()
        if($Process.ExitCode -ne 0){throw ('NVIDIA read-only query failed: '+$ErrorText)}
        $Lines=@($Text.Trim() -split '\r?\n')
        if($Lines.Count -ne 1 -or !$Lines[0]){throw 'Expected exactly one NVIDIA device record.'}
        return $Lines[0]
    } finally {$Process.Dispose()}
}
