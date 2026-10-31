[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$Project=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Out=Join-Path $Project 'build\windows'
New-Item -ItemType Directory -Path $Out -Force | Out-Null
$TempDir=Join-Path $Out 'temp'
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
$Vs=& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if($LASTEXITCODE -ne 0 -or !$Vs){throw 'Existing VS C++ tools not found; no installer is run.'}
$Cuda=$env:CUDA_PATH
if(!(Test-Path -LiteralPath "$Cuda\bin\nvcc.exe")){throw 'Windows CUDA Toolkit not found.'}
# All environment changes are confined to this child command process.
$Batch=@"
@echo off
set "TEMP=$TempDir"
set "TMP=$TempDir"
call "$Vs\VC\Auxiliary\Build\vcvars64.bat" > "$Out\compiler-environment.txt" 2>&1
if errorlevel 1 exit /b 1
"$Cuda\bin\nvcc.exe" -O3 -std=c++17 -arch=sm_89 --cudart static -Xcompiler /W4 -Xcompiler /utf-8 -Xcompiler /EHsc -o "$Out\windows_bench.exe" "$Project\src\bench\windows_bench.cu" -lcublas > "$Out\compile.log" 2>&1
if errorlevel 1 exit /b 1
cl.exe /nologo /O2 /std:c++17 /EHsc /W4 /WX /utf-8 /Fe:"$Out\reference_test.exe" /Fo:"$Out\reference_test.obj" "$Project\tests\test_reference.cpp" > "$Out\reference-compile.log" 2>&1
if errorlevel 1 exit /b 1
"$Cuda\bin\nvcc.exe" --version > "$Out\nvcc-version.txt"
cl.exe > "$Out\cl-version.txt" 2>&1
exit /b 0
"@
$Batch | Set-Content -LiteralPath (Join-Path $Out 'compile.cmd') -Encoding ASCII
& $env:ComSpec /d /c (Join-Path $Out 'compile.cmd')
if($LASTEXITCODE -ne 0){throw "Compile failed; see $Out\compile.log"}
# cuobjdump's nvdisasm child mishandles escaped UNC temporary filenames.
# Relative temporary paths under the project avoid a drive mapping or C: staging.
$PreviousTemp=$env:TEMP; $PreviousTmp=$env:TMP; $PreviousDirectory=[Environment]::CurrentDirectory
Push-Location $Out
try {
    [Environment]::CurrentDirectory=$Out; $env:TEMP='.'; $env:TMP='.'
    & "$Cuda\bin\cuobjdump.exe" --dump-sass 'windows_bench.exe' 2>&1 |
        Set-Content -LiteralPath (Join-Path $Out 'sass.txt') -Encoding ASCII
    if($LASTEXITCODE -ne 0){throw 'cuobjdump failed'}
} finally {
    $env:TEMP=$PreviousTemp; $env:TMP=$PreviousTmp; [Environment]::CurrentDirectory=$PreviousDirectory; Pop-Location
}
$Sass=Get-Content -LiteralPath (Join-Path $Out 'sass.txt') -Raw
if($Sass -notmatch 'HMMA.16816.F32' -or $Sass -notmatch 'BF16' -or $Sass -notmatch 'TF32') {throw 'Expected sm_89 MMA instructions not found in disassembly.'}
$Hashes=[ordered]@{}
foreach($Name in @('windows_bench.exe','reference_test.exe','sass.txt','nvcc-version.txt','cl-version.txt')) {
    $Hashes[$Name]=(Get-FileHash -LiteralPath (Join-Path $Out $Name) -Algorithm SHA256).Hash.ToLower()
}
$Dlls=@{}
$DllDirectory=if(Test-Path -LiteralPath "$Cuda\bin\x64\cublas64_13.dll"){"$Cuda\bin\x64"}else{"$Cuda\bin"}
Get-ChildItem -LiteralPath $DllDirectory -Filter 'cublas*64_*.dll' | ForEach-Object { $Dlls[$_.Name]=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() }
if($Dlls.Count -lt 2){throw 'Expected cuBLAS and cuBLASLt DLLs not found.'}
@{schema_version=1;gpu_executed=$false;artifacts=$Hashes;cuda_root=$Cuda;cuda_dll_directory=$DllDirectory;cublas_dlls=$Dlls;
 source_sha256=(Get-FileHash (Join-Path $Project 'src\bench\windows_bench.cu') -Algorithm SHA256).Hash.ToLower();
 reference_sha256=(Get-FileHash (Join-Path $Project 'src\bench\reference.h') -Algorithm SHA256).Hash.ToLower()} |
 ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Out 'manifest.json') -Encoding UTF8
Write-Output "Built and disassembled $Out\windows_bench.exe; GPU workload was not run."
