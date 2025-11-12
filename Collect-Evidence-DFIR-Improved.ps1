<#
  Collect-Evidence-DFIR-Improved.ps1  (v1.3.5)

  Cambios vs 1.3.4:
    - esentutl -1032 tratado como NOTE si luego VSS copia OK (no cuenta como error).
    - Copy-FileWithFallback decide el nivel de severidad; solo WARN al fallar VSS.
    - Limpieza y trazas menores.

  Requisitos: Ejecutar como Administrador.

  Uso rápido:
    - Ayuda:  powershell -ExecutionPolicy Bypass -File .\Collect-Evidence-DFIR-Improved.ps1 -Help
    - Básico: powershell -ExecutionPolicy Bypass -File .\Collect-Evidence-DFIR-Improved.ps1 -BasePath E:\evidence -Operator SOC
    - RAM:    powershell -ExecutionPolicy Bypass -File .\Collect-Evidence-DFIR-Improved.ps1 -BasePath E:\evidence -DumpMemory -WinpmemPath E:\tools\winpmem_mini_x64.exe
    - SACL:   powershell -ExecutionPolicy Bypass -File .\Collect-Evidence-DFIR-Improved.ps1 -BasePath \\srv\dfir -PreserveSecurity
    - ACL fin (opcional): -FinalizeACL
#>

[CmdletBinding(DefaultParameterSetName='Run')]
param(
  # --- Set: Run ---
  [Parameter(ParameterSetName='Run', Mandatory=$true)]
  [ValidateNotNullOrEmpty()][string]$BasePath,
  [Parameter(ParameterSetName='Run')] [string]$Operator = "",
  [Parameter(ParameterSetName='Run')] [switch]$DumpMemory,
  [Parameter(ParameterSetName='Run')] [string]$WinpmemPath = "",
  [Parameter(ParameterSetName='Run')] [string[]]$HashExclude = @(),
  [Parameter(ParameterSetName='Run')] [switch]$PreserveSecurity,
  [Parameter(ParameterSetName='Run')] [switch]$FinalizeACL,

  # --- Set: Help ---
  [Parameter(ParameterSetName='Help', Mandatory=$true)]
  [Alias('?')][switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference     = "Continue"
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$ScriptVersion = "1.3.5"

function Show-Help {
@"
Collect-Evidence-DFIR-Improved.ps1 (v$ScriptVersion)

Descripción:
  Recolecta evidencia DFIR: eventos .evtx, artefactos comunes, hives de registro (HKLM y usuario),
  suscripciones WMI, hashing y ZIP. RAM opcional con WinPMEM. Soporta VSS para copiar archivos bloqueados.

Parámetros (Run):
  -BasePath <ruta>           Obligatorio. Carpeta raíz de salida (D:\evidence o \\srv\share).
  -Operator <texto>          Operador/analista (metadatos).
  -DumpMemory                Volcado de RAM con WinPMEM.
  -WinpmemPath <ruta>        Ruta de winpmem (requerido si usa -DumpMemory).
  -PreserveSecurity          Copia con /COPY:DATSOU (incluye SACL/OWNER). Por defecto /COPY:DAT.
  -HashExclude <patrones[]>  Rutas relativas a excluir del hashing.
  -FinalizeACL               Endurece permisos finales (solo lectura para Administradores).

Parámetros (Help):
  -Help | -?                 Muestra esta ayuda y termina.

Ejemplos:
  powershell -File .\Collect-Evidence-DFIR-Improved.ps1 -BasePath E:\evidence -Operator "SOC"
  powershell -File .\Collect-Evidence-DFIR-Improved.ps1 -BasePath \\srv\dfir -DumpMemory -WinpmemPath "E:\tools\winpmem_mini_x64.exe"
  powershell -File .\Collect-Evidence-DFIR-Improved.ps1 -BasePath D:\evidence -PreserveSecurity -FinalizeACL
"@ | Out-Host
}
if ($PSCmdlet.ParameterSetName -eq 'Help') { Show-Help; exit 0 }

# --- Carpetas y logging ---
$hostn = $env:COMPUTERNAME
$ts    = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$root  = Join-Path $BasePath "$hostn-$ts"
$null  = New-Item -ItemType Directory -Path $root -Force
"logs","volatile","registry","artifacts" | ForEach-Object { New-Item -ItemType Directory -Path (Join-Path $root $_) -Force | Out-Null }
$LogPath    = Join-Path $root "collection.log"
$ErrorsPath = Join-Path $root "errors.log"
$global:ErrorList = [System.Collections.ArrayList]::new()

function Log  { param([string]$msg) $t=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); "[$t] $msg" | Tee-Object -FilePath $LogPath -Append | Out-Host }
function Warn { param([string]$msg) $t=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); $l="[$t] WARNING: $msg"; $l|Tee-Object -FilePath $LogPath -Append|Out-Host; [void]$global:ErrorList.Add($msg) }
function Note { param([string]$msg) $t=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); "[$t] NOTE: $msg" | Tee-Object -FilePath $LogPath -Append | Out-Host }
function StepProgress { param([int]$step,[int]$total,[string]$status="") $pct = if ($total -gt 0){[int](($step/$total)*100)}else{0}; Write-Progress -Id 1 -Activity "Recolección de evidencia" -Status $status -PercentComplete $pct }
function Quote-Arg { param([string]$Arg) if ($Arg -match '[\s"]') { '"{0}"' -f ($Arg -replace '"','\"') } else { $Arg } }

# Ejecuta externo y devuelve resultado (sin registrar WARN automáticamente)
function Invoke-ExternalRaw {
  param([string]$FilePath,[string[]]$ArgumentList=@())
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName  = $FilePath
  $psi.Arguments = ($ArgumentList|ForEach-Object{Quote-Arg $_}) -join ' '
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  return @{ ExitCode=$p.ExitCode; StdOut=$out; StdErr=$err }
}

# Robocopy con /COPY seleccionable
function Invoke-Robocopy {
  param([string]$Source,[string]$Dest,[string]$Files="*",[switch]$PreserveSecurity)
  if (-not (Test-Path -LiteralPath $Source)) { Warn "Robocopy: origen no existe: $Source"; return $false }
  New-Item -ItemType Directory -Path $Dest -Force | Out-Null
  $copyMode = if ($PreserveSecurity) { "/COPY:DATSOU" } else { "/COPY:DAT" }
  $opts = "/E $copyMode /DCOPY:T /R:0 /W:0 /XJ /ZB /NFL /NDL /NP /MT:16"
  $cmd = "robocopy `"$Source`" `"$Dest`" $Files $opts"
  Log "Robocopy: $cmd"
  cmd /c $cmd | Out-Null
  $code = $LASTEXITCODE; $global:LASTEXITCODE = 0
  if ($code -ge 8) { Warn "Robocopy error. Code=$code. $Source -> $Dest"; return $false } else { Log "Robocopy OK. Code=$code"; return $true }
}

# Guardado de hives HKLM
function Save-RegistryHive {
  param([Parameter(Mandatory=$true)][string]$Hive, [Parameter(Mandatory=$true)][string]$OutPath)
  try {
    $dir = Split-Path -Parent $OutPath
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    cmd /c "reg save $Hive `"$OutPath`" /y" | Out-Null
    $code = $LASTEXITCODE; $global:LASTEXITCODE=0
    if ($code -ne 0 -or -not (Test-Path -LiteralPath $OutPath)) { Warn "reg save $Hive falló. Code=$code"; return $false }
    Log "reg save $Hive OK"; return $true
  } catch { Warn "reg save $Hive excepción: $($_.Exception.Message)"; return $false }
}

# VSS helpers
$script:ShadowCache = @{}
$script:ShadowIds   = @()
function New-ShadowRoot {
  param([Parameter(Mandatory=$true)][string]$DriveLetter) # "C:"
  if ($script:ShadowCache.ContainsKey($DriveLetter)) { return $script:ShadowCache[$DriveLetter] }
  try {
    $res = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{ Volume = "$DriveLetter\"; Context = "ClientAccessible" } -ErrorAction Stop
    if ($res.ReturnValue -ne 0) { Note "VSS: Create devolvió $($res.ReturnValue) para $DriveLetter"; return $null }
    $id  = $res.ShadowID
    $obj = Get-CimInstance -ClassName Win32_ShadowCopy -Filter "ID='$id'"
    $dev = $obj.DeviceObject
    if (-not $dev) { Note "VSS: No se resolvió DeviceObject para $DriveLetter"; return $null }
    $script:ShadowCache[$DriveLetter] = $dev
    $script:ShadowIds += $id
    Log "VSS: snapshot creado para $DriveLetter ($dev)"
    return $dev
  } catch { Note "VSS: $($_.Exception.Message)"; return $null }
}
function Remove-ShadowCopies { foreach ($id in $script:ShadowIds) { try { Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Delete -Arguments @{ ID = $id } | Out-Null } catch {} } }

# Copia robusta: Copy-Item -> esentutl -> VSS
function Copy-FileWithFallback {
  param([string]$Source,[string]$Dest)
  # intento directo
  try { Copy-Item -LiteralPath $Source -Destination $Dest -Force -ErrorAction Stop; Log "Copiado: $Source"; return $true }
  catch { $msgDirect = $_.Exception.Message }

  # intento esentutl (no cuenta como error si falla; se usará VSS)
  $esent = "$env:SystemRoot\System32\esentutl.exe"
  if (Test-Path -LiteralPath $esent) {
    Log "Intentando copia con esentutl de: $Source"
    $res = Invoke-ExternalRaw -FilePath $esent -ArgumentList @("/y",$Source,"/d",$Dest,"/o")
    if ($res.ExitCode -eq 0 -and (Test-Path -LiteralPath $Dest)) { Log "esentutl OK: $Source"; return $true }
    else { Note "esentutl copy falló. ExitCode=$($res.ExitCode)." }
  }

  # intento VSS
  $drive = (Split-Path -Qualifier $Source).TrimEnd('\')
  $shadowRoot = New-ShadowRoot -DriveLetter $drive
  if ($shadowRoot) {
    $rel = $Source.Substring($drive.Length).TrimStart('\')
    $shadowSrc = Join-Path $shadowRoot $rel
    try { Copy-Item -LiteralPath $shadowSrc -Destination $Dest -Force -ErrorAction Stop; Log "Copiado desde VSS: $Source"; return $true }
    catch { $msgVss = $_.Exception.Message }
  }

  # todo falló → verdadero error
  $allMsg = if ($msgVss) { "$msgVss" } else { "$msgDirect" }
  Warn "Copia con fallback falló: $Source -> $allMsg"; return $false
}

# ZIP robusto (reflexión → Compress-Archive → tar.exe)
function New-Zip {
  param([Parameter(Mandatory=$true)][string]$SourceRoot,[Parameter(Mandatory=$true)][string]$ZipPath)
  Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
  $haveDotNetZip = $false
  try {
    $null = [Type]::GetType('System.IO.Compression.ZipArchiveMode, System.IO.Compression', $false)
    if (-not $?) { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop }
    $zipModeType   = [Type]::GetType('System.IO.Compression.ZipArchiveMode, System.IO.Compression', $false)
    $levelType     = [Type]::GetType('System.IO.Compression.CompressionLevel, System.IO.Compression', $false)
    if ($zipModeType -and $levelType) { $haveDotNetZip = $true }
  } catch { $haveDotNetZip = $false }

  if ($haveDotNetZip) {
    $fs=$null;$zip=$null
    try {
      $files = Get-ChildItem -LiteralPath $SourceRoot -Recurse -File -Force -ErrorAction SilentlyContinue
      $cnt=[math]::Max(1,$files.Count); $j=0
      $fs=[System.IO.File]::Open($ZipPath,[System.IO.FileMode]::Create,[System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::None)
      $zip=New-Object System.IO.Compression.ZipArchive($fs,([System.IO.Compression.ZipArchiveMode]::Create),$false)
      foreach($f in $files){
        $j++; Write-Progress -Id 5 -ParentId 1 -Activity "Compresión ZIP" -Status $f.FullName -PercentComplete ([int](($j/$cnt)*100))
        $rel=$f.FullName.Substring($SourceRoot.Length).TrimStart('\','/')
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$f.FullName,$rel,[System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
      }
      return
    } finally { if ($zip){$zip.Dispose()}; if($fs){$fs.Dispose()} }
  }

  try { Compress-Archive -Path (Join-Path $SourceRoot '*') -DestinationPath $ZipPath -Force -ErrorAction Stop; return }
  catch { Warn "Compress-Archive falló: $($_.Exception.Message)" }

  try { & tar.exe -a -c -f $ZipPath -C $SourceRoot .; if ($LASTEXITCODE -eq 0) { Log "tar.exe ZIP OK"; return } else { Warn "tar.exe ZIP code=$LASTEXITCODE" } }
  catch { Warn "tar.exe ZIP: $($_.Exception.Message)" }

  throw "No se pudo crear el ZIP por ningún método"
}

# --- Prechequeo ---
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $IsAdmin) { Write-Error "Ejecuta como Administrador"; exit 1 }
try { Start-Transcript -Path (Join-Path $root "transcript.log") -IncludeInvocationHeader | Out-Null } catch { Warn "No se pudo iniciar Transcript: $($_.Exception.Message)" }

# --- Plan de pasos ---
$TotalSteps = 11 + [int]$DumpMemory.IsPresent + [int]$FinalizeACL.IsPresent
$Step = 0

# 1) Contexto
$Step++; StepProgress $Step $TotalSteps "Contexto"
try {
  Log "Contexto del sistema"
  (Get-Date).ToUniversalTime().ToString("o") | Out-File (Join-Path $root "volatile/timestamp_utc.txt")
  Get-CimInstance Win32_OperatingSystem | Select-Object * | Out-String -Width 4096 | Out-File (Join-Path $root "volatile/os.txt")
  Get-CimInstance Win32_ComputerSystem  | Select-Object * | Out-String -Width 4096 | Out-File (Join-Path $root "volatile/system.txt")
  Get-HotFix | Out-String -Width 4096 | Out-File (Join-Path $root "volatile/hotfix.txt")
} catch { Warn "Contexto: $($_.Exception.Message)" }

# 2) Volátil
$Step++; StepProgress $Step $TotalSteps "Volátil"
try {
  Log "Volátil: procesos/red/tareas/drivers"
  cmd /c "tasklist /v"      | Out-File (Join-Path $root "volatile/tasklist.txt")
  cmd /c "whoami /all"      | Out-File (Join-Path $root "volatile/whoami_all.txt")
  cmd /c "netstat -ano"     | Out-File (Join-Path $root "volatile/netstat.txt")
  cmd /c "arp -a"           | Out-File (Join-Path $root "volatile/arp.txt")
  cmd /c "ipconfig /all"    | Out-File (Join-Path $root "volatile/ipconfig.txt")
  cmd /c "route print"      | Out-File (Join-Path $root "volatile/route.txt")
  Get-Process | Select-Object * | Out-String -Width 4096 | Out-File (Join-Path $root "volatile/processes.txt")
  Get-Service | Select-Object * | Out-String -Width 4096 | Out-File (Join-Path $root "volatile/services.txt")
  cmd /c "schtasks /query /fo LIST /v" | Out-File (Join-Path $root "volatile/schtasks.txt")
  cmd /c "driverquery /v"              | Out-File (Join-Path $root "volatile/drivers.txt")
} catch { Warn "Volátil: $($_.Exception.Message)" }

# 3) Exportación .evtx
$Step++; StepProgress $Step $TotalSteps ".evtx"
$elog = Join-Path $root "logs"
$requested = @(
  "Security","System","Application",
  "Microsoft-Windows-Sysmon/Operational",
  "Microsoft-Windows-PowerShell/Operational",
  "Microsoft-Windows-TaskScheduler/Operational",
  "Microsoft-Windows-Windows Defender/Operational",
  "Microsoft-Windows-WMI-Activity/Operational",
  "Microsoft-Windows-Bits-Client/Operational",
  "Microsoft-Windows-AppLocker/EXE and DLL"
)
try {
  try { $available = (Get-WinEvent -ListLog * -ErrorAction Stop).LogName } catch { $available = & wevtutil el 2>$null }
  $channels = @(); foreach ($c in $requested) { if ($available -contains $c) { $channels += $c } else { Note "Canal inexistente o deshabilitado: $c" } }
  for ($i=0; $i -lt $channels.Count; $i++) {
    $ch = $channels[$i]; $safe = ($ch -replace '[\\/]', '_')
    $pct = [int](((($i+1)) / [math]::Max(1,$channels.Count))*100)
    Write-Progress -Id 2 -ParentId 1 -Activity "Exportando eventos" -Status $ch -PercentComplete $pct
    try {
      $outFile = Join-Path $elog "$safe.evtx"
      $res = Invoke-ExternalRaw -FilePath "wevtutil.exe" -ArgumentList @("epl",$ch,$outFile)
      if ($res.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $outFile)) { Warn "Export $ch salida no generada. ExitCode=$($res.ExitCode)" } else { Log "wevtutil $ch OK. ExitCode=0" }
    } catch { Warn "Export $ch excepción: $($_.Exception.Message)" }
  }
  Write-Progress -Id 2 -ParentId 1 -Activity "Exportando eventos" -Completed
} catch { Warn ".evtx: $($_.Exception.Message)" }

# 4) Artefactos
$Step++; StepProgress $Step $TotalSteps "Artefactos"
try {
  Log "Copiando winevt";  Invoke-Robocopy -Source "$env:SystemRoot\System32\winevt\Logs" -Dest (Join-Path $elog "winevt") -Files "*.evtx" -PreserveSecurity:$PreserveSecurity | Out-Null
  if (Test-Path -LiteralPath "$env:SystemRoot\Prefetch") { Log "Copiando Prefetch"; Invoke-Robocopy -Source "$env:SystemRoot\Prefetch" -Dest (Join-Path $root "artifacts/Prefetch") -Files "*" -PreserveSecurity:$PreserveSecurity | Out-Null } else { Note "Prefetch no encontrado. Puede estar deshabilitado." }
  if (Test-Path -LiteralPath "$env:SystemRoot\System32\LogFiles\Firewall") { Log "Copiando Firewall"; Invoke-Robocopy -Source "$env:SystemRoot\System32\LogFiles\Firewall" -Dest (Join-Path $elog "Firewall") -Files "*" -PreserveSecurity:$PreserveSecurity | Out-Null } else { Note "Ruta de Firewall no encontrada." }
  if (Test-Path -LiteralPath "C:\inetpub\logs\LogFiles") { Log "Copiando IIS"; Invoke-Robocopy -Source "C:\inetpub\logs\LogFiles" -Dest (Join-Path $elog "IIS") -Files "*" -PreserveSecurity:$PreserveSecurity | Out-Null } else { Log "IIS no presente. Omitido." }
  Log "Copiando Tasks"; Invoke-Robocopy -Source "$env:SystemRoot\System32\Tasks" -Dest (Join-Path $root "artifacts/Tasks") -Files "*" -PreserveSecurity:$PreserveSecurity | Out-Null
  Log "Copiando StartUp global"; $globalStartup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
  if (Test-Path -LiteralPath $globalStartup) { Invoke-Robocopy -Source $globalStartup -Dest (Join-Path $root "artifacts/Startup_Global") -Files "*" -PreserveSecurity:$PreserveSecurity | Out-Null }
} catch { Warn "Artefactos: $($_.Exception.Message)" }

# 5) Hives HKLM
$Step++; StepProgress $Step $TotalSteps "Hives HKLM"
try {
  [void](Save-RegistryHive -Hive "HKLM\SAM"      -OutPath (Join-Path $root "registry/SAM.hiv"))
  [void](Save-RegistryHive -Hive "HKLM\SYSTEM"   -OutPath (Join-Path $root "registry/SYSTEM.hiv"))
  [void](Save-RegistryHive -Hive "HKLM\SECURITY" -OutPath (Join-Path $root "registry/SECURITY.hiv"))
  [void](Save-RegistryHive -Hive "HKLM\SOFTWARE" -OutPath (Join-Path $root "registry/SOFTWARE.hiv"))
  [void](Save-RegistryHive -Hive "HKU\.DEFAULT"  -OutPath (Join-Path $root "registry/DEFAULT.hiv"))
  $amc = "$env:WINDIR\AppCompat\Programs\Amcache.hve"
  if (Test-Path -LiteralPath $amc) { [void](Copy-FileWithFallback -Source $amc -Dest (Join-Path $root "registry/Amcache.hve")) } else { Log "Amcache no presente. Omitido." }
} catch { Warn "Hives HKLM: $($_.Exception.Message)" }

# 6) Hives usuario
$Step++; StepProgress $Step $TotalSteps "Hives usuario"
try {
  $profiles = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Default','Default User','Public','All Users') }
  $pl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Select-Object PSChildName,ProfileImagePath
  foreach ($p in $profiles) {
    try {
      $dst = Join-Path $root ("registry/Users/" + $p.Name); New-Item -ItemType Directory -Path $dst -Force | Out-Null
      $sid = ($pl | Where-Object { $_.ProfileImagePath -eq $p.FullName } | Select-Object -First 1).PSChildName
      $didNt=$false; $didCls=$false
      if ($sid -and (Test-Path "HKU:\$sid")) {
        $didNt  = Save-RegistryHive -Hive "HKU\$sid" -OutPath (Join-Path $dst 'NTUSER.DAT')
        if (Test-Path "HKU:\${sid}_Classes") { $didCls = Save-RegistryHive -Hive "HKU\${sid}_Classes" -OutPath (Join-Path $dst 'UsrClass.dat') }
      }
      if (-not $didNt)  { $ntuser = Join-Path $p.FullName 'NTUSER.DAT'; if (Test-Path -LiteralPath $ntuser)  { [void](Copy-FileWithFallback -Source $ntuser -Dest (Join-Path $dst 'NTUSER.DAT')) } }
      if (-not $didCls) { $usrcls = Join-Path $p.FullName 'AppData\Local\Microsoft\Windows\UsrClass.dat'; if (Test-Path -LiteralPath $usrcls) { [void](Copy-FileWithFallback -Source $usrcls -Dest (Join-Path $dst 'UsrClass.dat')) } }

      $userStartup = Join-Path $p.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
      if (Test-Path -LiteralPath $userStartup) { Invoke-Robocopy -Source $userStartup -Dest (Join-Path $root ("artifacts/Startup_"+$p.Name)) -Files "*" -PreserveSecurity:$PreserveSecurity | Out-Null }
    } catch { Warn "Hives/Startup usuario $($p.Name): $($_.Exception.Message)" }
  }
} catch { Warn "Hives usuario: $($_.Exception.Message)" }

# 7) WMI
$Step++; StepProgress $Step $TotalSteps "WMI"
try {
  $wmip = Join-Path $root 'artifacts/WMI'; New-Item -ItemType Directory -Path $wmip -Force | Out-Null
  Get-CimInstance -Namespace root\subscription -ClassName __EventFilter             -ErrorAction SilentlyContinue | Out-String -Width 4096 | Out-File (Join-Path $wmip 'EventFilter.txt')
  Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer           -ErrorAction SilentlyContinue | Out-String -Width 4096 | Out-File (Join-Path $wmip 'EventConsumer.txt')
  Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Out-String -Width 4096 | Out-File (Join-Path $wmip 'FilterToConsumerBinding.txt')
} catch { Warn "WMI: $($_.Exception.Message)" }

# 8) Memoria (opcional)
$memPath = ""
if ($DumpMemory) {
  $Step++; StepProgress $Step $TotalSteps "Memoria"
  Log "Volcado de RAM con WinPMEM"
  if (-not (Test-Path -LiteralPath $WinpmemPath)) { Warn "WinPMEM no encontrado en $WinpmemPath. RAM omitida." }
  else {
    try {
      $totalRam = [double]((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory)
      if ($BasePath -match '^[A-Za-z]:') { $drive = New-Object System.IO.DriveInfo ($BasePath.Substring(0,1)+':'); if ([double]$drive.AvailableFreeSpace -lt ($totalRam*1.1)) { Note "Espacio justo para RAM (~$([math]::Round($totalRam/1GB,2)) GB)." } }
      $memPath = Join-Path $root "$($hostn)-$ts.raw"
      $proc = Start-Process -FilePath $WinpmemPath -ArgumentList @("--output",$memPath,"--format","raw") -NoNewWindow -PassThru
      while (-not $proc.HasExited) {
        $size = if (Test-Path -LiteralPath $memPath) { (Get-Item -LiteralPath $memPath).Length } else { 0 }
        $pct  = if ($totalRam -gt 0) { [int]([math]::Min(99, ($size/$totalRam)*100)) } else { 0 }
        Write-Progress -Id 3 -ParentId 1 -Activity "WinPMEM" -Status ("{0:N2} MB escritos" -f ($size/1MB)) -PercentComplete $pct
        Start-Sleep -Seconds 2
      }
      Write-Progress -Id 3 -ParentId 1 -Activity "WinPMEM" -Completed
      if ($proc.ExitCode -ne 0) { Warn "WinPMEM ExitCode=$($proc.ExitCode)" }
      if (Test-Path -LiteralPath $memPath) {
        try { Get-FileHash -LiteralPath $memPath -Algorithm SHA256 | Format-List * | Out-File (Join-Path $root "memory_SHA256.txt") }
        catch { Warn "Hash memoria: $($_.Exception.Message)" }
      } else { Warn "Archivo de memoria no generado." }
    } catch { Warn "WinPMEM: $($_.Exception.Message)" }
  }
}

# 9) Manifiesto
$Step++; StepProgress $Step $TotalSteps "Manifiesto"
try {
  Log "Creando manifest.json"
  $os = Get-CimInstance Win32_OperatingSystem; $sys = Get-CimInstance Win32_ComputerSystem
  $memGB = [math]::Round(($sys.TotalPhysicalMemory/1GB),2)
  $freeGB = $null; if ($BasePath -match '^[A-Za-z]:') { $drv = New-Object System.IO.DriveInfo ($BasePath.Substring(0,1)+':'); $freeGB = [math]::Round(($drv.AvailableFreeSpace/1GB),2) }
  $toolMemLeaf = if ($WinpmemPath) { Split-Path -Leaf $WinpmemPath } else { "" }
  $toolMemHash = $null; if ($WinpmemPath -and (Test-Path -LiteralPath $WinpmemPath)) { $toolMemHash = (Get-FileHash -LiteralPath $WinpmemPath -Algorithm SHA256).Hash }
  $memDumpLeaf = if ($memPath) { Split-Path -Leaf $memPath } else { "" }
  $manifest = [ordered]@{
    Host=$hostn; TimeUTC=$ts; Operator=$Operator; Base=$root; MemoryDump=$memDumpLeaf;
    System=@{ OSVersion=$os.Version; Build=$os.BuildNumber; Caption=$os.Caption; TotalRAMGB=$memGB; FreeSpaceGB=$freeGB };
    Tooling=@{ MemoryPath=$toolMemLeaf; MemorySHA256=$toolMemHash; Script="Collect-Evidence-DFIR-Improved.ps1"; ScriptVersion=$ScriptVersion };
    Notes="Subir a repositorio WORM. Mantener cadena de custodia."
  }
  $manifest | ConvertTo-Json -Depth 6 | Out-File (Join-Path $root "manifest.json") -Encoding utf8
} catch { Warn "Manifest: $($_.Exception.Message)" }

# 10) Cerrar transcript
try { Stop-Transcript | Out-Null } catch { Warn "Stop-Transcript: $($_.Exception.Message)" }

# 11) Preparar ACL para hashing
$Step++; StepProgress $Step $TotalSteps "ACL para hashing"
try {
  $adminSid  = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
  $adminAcct = $adminSid.Translate([System.Security.Principal.NTAccount]).Value
  cmd /c "icacls `"$root`" /grant:r `"$adminAcct`":(R) /T" 1>nul 2>nul
} catch { Note "Preparación ACL hashing: $($_.Exception.Message)" }

# 12) Hashing
$Step++; StepProgress $Step $TotalSteps "Hashing"
function Should-SkipHash([string]$path) { foreach ($ex in $HashExclude) { if ($path -like (Join-Path $root $ex)) { return $true } } return $false }
try {
  Log "Hashing SHA256 recursivo"
  $csv = Join-Path $root "hashes_sha256.csv"; "Path,SHA256" | Out-File $csv -Encoding utf8
  $files = Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'transcript.log' }
  $cnt=[math]::Max(1,$files.Count); $i=0
  foreach($f in $files){
    if (Should-SkipHash $f.FullName) { continue }
    $i++; Write-Progress -Id 4 -ParentId 1 -Activity "Hashing" -Status $f.FullName -PercentComplete ([int](($i/$cnt)*100))
    try { $h=Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop; '"{0}",{1}' -f $f.FullName,$h.Hash | Out-File $csv -Append -Encoding utf8 }
    catch { Warn "Hash falló: $($f.FullName) -> $($_.Exception.Message)" }
  }
  Write-Progress -Id 4 -ParentId 1 -Activity "Hashing" -Completed
} catch { Warn "Hashing general: $($_.Exception.Message)" }

# 13) ZIP
$Step++; StepProgress $Step $TotalSteps "ZIP"
$zipPath = Join-Path $BasePath "$($hostn)-$ts.zip"
try {
  Log "Comprimiendo a ZIP: $zipPath"
  try { New-Zip -SourceRoot $root -ZipPath $zipPath }
  catch { Warn "ZIP general: $($_.Exception.Message)" }
  Write-Progress -Id 5 -ParentId 1 -Activity "Compresión ZIP" -Completed
  try { Get-FileHash -LiteralPath $zipPath -Algorithm SHA256 | Format-List * | Out-File ($zipPath + ".sha256.txt") } catch { Warn "Hash ZIP: $($_.Exception.Message)" }
} catch { Warn "ZIP general: $($_.Exception.Message)" }

# 14) ACL final (opcional)
if ($FinalizeACL) {
  $Step++; StepProgress $Step $TotalSteps "ACL final (opcional)"
  try {
    Log "Aplicando ACL de solo lectura (opcional)"
    $adminSid  = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    $adminAcct = $adminSid.Translate([System.Security.Principal.NTAccount]).Value
    cmd /c "icacls `"$root`"   /inheritance:r"                1>nul 2>nul
    cmd /c "icacls `"$root`"   /grant:r `"$adminAcct`":(R) /T" 1>nul 2>nul
    cmd /c "icacls `"$zipPath`" /inheritance:r"               1>nul 2>nul
    cmd /c "icacls `"$zipPath`" /grant:r `"$adminAcct`":(R)"  1>nul 2>nul
    try { attrib +R $zipPath } catch { Warn "attrib ZIP: $($_.Exception.Message)" }
  } catch { Warn "ACL final: $($_.Exception.Message)" }
}

# --- Limpieza VSS y salida ---
Remove-ShadowCopies | Out-Null
Write-Progress -Id 1 -Activity "Recolección de evidencia" -Completed

if ($global:ErrorList.Count -gt 0) {
  "Errores detectados:" | Out-File $ErrorsPath -Encoding utf8
  $global:ErrorList | Out-File $ErrorsPath -Append -Encoding utf8
  Warn "Finalizado con errores. Ver $ErrorsPath"
  Log  "Carpeta: $root"; Log  "ZIP: $zipPath"; exit 2
} else {
  Log "Finalizado sin errores."; Log "Carpeta: $root"; Log "ZIP: $zipPath"; exit 0
}
