# Read-only context for future, separately approved measurements. No auto-run.
. (Join-Path $PSScriptRoot 'Read-MeasurementDisplay.ps1')

function ConvertTo-MeasurementDisplay($Snapshot) {
    # Local strict mode prevents missing properties from silently becoming zero.
    Set-StrictMode -Version Latest
    if($Snapshot.QueryFlags -ne 82 -or @($Snapshot.Paths).Count -ne 1 -or
       @($Snapshot.Modes).Count -lt 3 -or @($Snapshot.Modes).Count -gt 256){
        throw 'Measurement requires one active Intel display; duplicate/unknown topology.'
    }
    $Path=$Snapshot.Paths[0];$Native=$Path.Native
    $AdapterPrefix='\\?\PCI#VEN_8086&DEV_7D67&'
    foreach($Name in @($Path.SourceAdapterName,$Path.TargetAdapterName)){
        if($Name.Status -ne 0 -or !$Name.Name.StartsWith($AdapterPrefix,[StringComparison]::OrdinalIgnoreCase)){
            throw 'Measurement display is not the expected Intel adapter.'
        }
    }
    $Luid=$Native.Source.Adapter
    if($Path.SourceAdapterName.Name -ine $Path.TargetAdapterName.Name -or
       $Luid.Low -ne $Native.Target.Adapter.Low -or $Luid.High -ne $Native.Target.Adapter.High -or
       $Native.Flags -ne 9 -or $Native.Target.Technology -ne 5 -or $Native.Target.Available -ne 1 -or
       $Native.Target.Refresh.Numerator -le 0 -or $Native.Target.Refresh.Denominator -le 0 -or
       $Path.TargetName.Status -ne 0 -or $Path.TargetName.Name -cne 'Odyssey G70D' -or
       !$Path.TargetName.MonitorPath.StartsWith('\\?\DISPLAY#SAME069#',[StringComparison]::OrdinalIgnoreCase)){
        throw 'Measurement Intel HDMI/monitor identity or refresh is invalid.'
    }
    $Indices=@(([uint32]$Native.Source.ModeIndex -shr 16),([uint32]$Native.Target.ModeIndex -shr 16),
               ([uint32]$Native.Target.ModeIndex -band 65535))
    if($Path.SourceModeIndex -ne $Indices[0] -or $Path.TargetModeIndex -ne $Indices[1]){throw 'CCD mode indices disagree.'}
    $ModeWords=@()
    for($Index=0;$Index -lt 3;$Index++){
        if($Indices[$Index] -ge $Snapshot.Modes.Count){throw 'CCD mode index out of bounds.'}
        $Mode=$Snapshot.Modes[$Indices[$Index]]
        $Id=if($Index -eq 0){$Native.Source.Id}else{$Native.Target.Id}
        if($Mode.Type -ne ($Index+1) -or $Mode.Id -ne $Id -or
           $Mode.Adapter.Low -ne $Luid.Low -or $Mode.Adapter.High -ne $Luid.High){throw 'CCD mode association mismatch.'}
        $Words=@(0..5|ForEach-Object {([uint64]$Mode.('Raw'+$_)).ToString('x16')})
        $ModeWords+=,@($Words)
    }
    $Source=$Snapshot.Modes[$Indices[0]]
    if($Source.SourceWidth -ne 3840 -or $Source.SourceHeight -ne 2160 -or
       $Source.SourceX -ne 0 -or $Source.SourceY -ne 0){throw 'Expected the primary Intel 4K display.'}
    # Resolve array references to their contents: a harmless index renumbering
    # is allowed; altered target timings/desktop image/format are not.
    return [ordered]@{
        adapter_path=$Path.SourceAdapterName.Name;monitor_path=$Path.TargetName.MonitorPath;
        adapter_luid=@($Luid.Low,$Luid.High);source_id=$Native.Source.Id;target_id=$Native.Target.Id;
        path_flags=$Native.Flags;technology=$Native.Target.Technology;rotation=$Native.Target.Rotation;
        scaling=$Native.Target.Scaling;scanline=$Native.Target.Scanline;
        clone_group=([uint32]$Native.Source.ModeIndex -band 65535);
        width=$Source.SourceWidth;height=$Source.SourceHeight;
        refresh_numerator=$Native.Target.Refresh.Numerator;refresh_denominator=$Native.Target.Refresh.Denominator;
        mode_words=$ModeWords
    }
}

function Get-MeasurementContext([string]$ScratchDirectory) {
    Set-StrictMode -Version Latest
    $Os=@(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop)
    if($Os.Count -ne 1){throw 'Expected one current Windows installation.'}
    $Os=$Os[0]
    if($Os.SystemDrive -notmatch '^[A-Za-z]:$' -or !$Os.WindowsDirectory -or !$Os.Version -or
       !$Os.BuildNumber -or $Os.LastBootUpTime -isnot [datetime]){throw 'Incomplete Windows boot context.'}
    $Volume=@(Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='"+$Os.SystemDrive+"'") -ErrorAction Stop)
    if($Volume.Count -ne 1 -or $Volume[0].DriveType -ne 3 -or
       $Volume[0].VolumeSerialNumber -notmatch '^[0-9A-Fa-f]{8}$'){throw 'System volume identity unavailable.'}
    $Display=ConvertTo-MeasurementDisplay (Get-MeasurementDisplaySnapshot $ScratchDirectory)
    $Captured=(Get-Date).ToUniversalTime()
    if($Os.LastBootUpTime.ToUniversalTime() -gt $Captured){throw 'Boot time is in the future.'}
    return [ordered]@{schema_version=1;captured_utc=$Captured.ToString('o');
        session=[ordered]@{boot_utc=$Os.LastBootUpTime.ToUniversalTime().ToString('o');
            windows_directory=$Os.WindowsDirectory;system_drive=$Os.SystemDrive;
            volume_serial=$Volume[0].VolumeSerialNumber;os_version=$Os.Version;os_build=$Os.BuildNumber};display=$Display}
}

function Assert-MeasurementContextUnchanged($Before,$After) {
    foreach($Section in @('session','display')){
        if($null -eq $Before.$Section -or $null -eq $After.$Section -or
           (ConvertTo-Json -InputObject $Before.$Section -Depth 8 -Compress) -cne
           (ConvertTo-Json -InputObject $After.$Section -Depth 8 -Compress)){
            throw "Measurement $Section changed; no retry or settings changes."
        }
    }
}
