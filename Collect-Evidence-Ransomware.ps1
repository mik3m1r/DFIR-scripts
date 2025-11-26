<#
  Collect-Evidence-Ransomware.ps1  (v2.0.4)

  Cambios vs 2.0.3:
    - Mejora en gestión de WinPMEM (mensajes más claros y validaciones adicionales).
    - Mejora en compresión ZIP (uso de .NET ZipFile/CreateFromDirectory con soporte ZIP64
      y fallbacks; el fallo de creación de ZIP ya no se considera error crítico).

  Cambios vs 2.0.2:
    - Ajuste de la invocación a WinPMEM para la versión winpmem_mini_x64_rc2.exe
      (sintaxis: winpmem.exe [opciones] <output_path>, sin --output/--format).

  Propósito:
    Script de triage para incidentes de ransomware en Windows.
    Recolecta artefactos forenses habituales (contexto, evidencia volátil,
    logs de eventos, registro, WMI, tareas programadas, RAM opcional).
    No realiza hashing ni pretende cubrir una cadena de custodia formal.

  Requisitos:
    - Ejecutar como Administrador.
    - PowerShell 4.0 o superior.
    - Windows Server 2012 / Windows 8 o superior.

  Uso rápido:
    - Ayuda:
        powershell -ExecutionPolicy Bypass -File .\Collect-Evidence-Ransomware.ps1 -Help
    - Recolección básica:
        powershell -ExecutionPolicy Bypass -File .\Collect-Evidence-Ransomware.ps1 -BasePath E:\evidence -Operator SOC
    - Con volcado de RAM (ej. winpmem_mini_x64_rc2.exe):
        powershell -ExecutionPolicy Bypass -File .\Collect-Evidence-Ransomware.ps1 -BasePath E:\evidence -Operator SOC -DumpMemory -WinpmemPath "E:\tools\winpmem_mini_x64_rc2.exe"
    - Preservando SACL/OWNER y endureciendo ACL final:
        powershell -ExecutionPolicy Bypass -File .\Collect-Evidence-Ransomware.ps1 -BasePath \\srv\dfir -PreserveSecurity -FinalizeACL
#>

[CmdletBinding(DefaultParameterSetName='Run')]
param(
  # --- Set: Run ---
  [Parameter(ParameterSetName='Run', Mandatory=$true)]
  [ValidateNotNullOrEmpty()][string]$BasePath,

  [Parameter(ParameterSetName='Run')]
  [string]$Operator = "",

  [Parameter(ParameterSetName='Run')]
  [switch]$DumpMemory,

  [Parameter(ParameterSetName='Run')]
  [string]$WinpmemPath = "",

  [Parameter(ParameterSetName='Run')]
  [switch]$PreserveSecurity,

  [Parameter(ParameterSetName='Run')]
  [switch]$FinalizeACL,

  # --- Set: Help ---
  [Parameter(ParameterSetName='Help', Mandatory=$true)]
  [Alias('?')]
  [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'Continue'
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$ScriptVersion = '2.0.4'

function Show-Help {
@"
Collect-Evidence-Ransomware.ps1 (v$ScriptVersion)

Descripción:
  Recolecta evidencia típica en un incidente de ransomware:
    - Contexto del sistema.
    - Información volátil (procesos, red, sesiones, tareas, drivers).
    - Logs de eventos críticos para ransomware.
    - Artefactos comunes: winevt, Prefetch, Firewall/IIS, Tasks, Startup.
    - Hives de registro (HKLM y usuarios) y suscripciones WMI.
    - Volcado de memoria RAM (opcional, con WinPMEM).
    - Compresión final a ZIP (si es posible).

  No realiza hashing ni implementa cadena de custodia formal.

Parámetros (Run):
  -BasePath <ruta>     Obligatorio. Carpeta raíz de salida (D:\evidence o \\srv\share).
  -Operator <texto>    Operador/analista (metadatos).
  -DumpMemory          Volcado de RAM con WinPMEM.
  -WinpmemPath <ruta>  Ruta de winpmem (requerido si usa -DumpMemory).
                       Para winpmem_mini_x64_rc2.exe la sintaxis es:
                       winpmem_mini_x64_rc2.exe <ruta_salida.raw>
  -PreserveSecurity    Copia con /COPY:DATSOU (incluye SACL/OWNER). Por defecto /COPY:DAT.
  -FinalizeACL         Endurece permisos finales (solo lectura para Administradores).

Parámetros (Help):
  -Help | -?           Muestra esta ayuda y termina.

Ejemplos:
  powershell -File .\Collect-Evidence-Ransomware.ps1 -BasePath E:\evidence -Operator "SOC"
  powershell -File .\Collect-Evidence-Ransomware.ps1 -BasePath \\srv\dfir -DumpMemory -WinpmemPath "E:\tools\winpmem_mini_x64_rc2.exe"
  powershell -File .\Collect-Evidence-Ransomware.ps1 -BasePath D:\evidence -PreserveSecurity -FinalizeACL
"@ | Out-Host
}

if ($PSCmdlet.ParameterSetName -eq 'Help') {
    Show-Help
    exit 0
}

# --- Carpetas y logging ---
$hostn = $env:COMPUTERNAME
$ts    = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$root  = Join-Path $BasePath "$hostn-$ts"

$null = New-Item -ItemType Directory -Path $root -Force
'logs','volatile','registry','artifacts' | ForEach-Object {
    New-Item -ItemType Directory -Path (Join-Path $root $_) -Force | Out-Null
}

$LogPath    = Join-Path $root 'collection.log'
$ErrorsPath = Join-Path $root 'errors.log'
$global:ErrorList = @()   # Corregido: usar array en lugar de ArrayList

function Log {
    param([string]$msg)
    $t = (Get-Date).ToUniversalTime().ToString('o')
    "[{0}] {1}" -f $t, $msg | Tee-Object -FilePath $LogPath -Append | Out-Host
}

function Warn {
    param([string]$msg)
    $t = (Get-Date).ToUniversalTime().ToString('o')
    "[{0}] [WARN] {1}" -f $t, $msg | Tee-Object -FilePath $LogPath -Append | Out-Host
    # Corregido: agregar al array en lugar de usar .Add() sobre ArrayList
    $global:ErrorList += $msg
}

function Note {
    param([string]$msg)
    $t = (Get-Date).ToUniversalTime().ToString('o')
    "[{0}] [NOTE] {1}" -f $t, $msg | Tee-Object -FilePath $LogPath -Append | Out-Host
}

function StepProgress {
    param(
        [int]$step,
        [int]$total,
        [string]$status
    )
    if ($total -le 0) { return }
    $pct = [int](($step / [double]$total) * 100)
    Write-Progress -Id 1 -Activity 'Recolección de evidencia (ransomware)' -Status $status -PercentComplete $pct
}

function Quote-Arg {
    param([string]$Arg)
    if ($Arg -match '[\s"]') {
        '"{0}"' -f ($Arg -replace '"','\"')
    } else {
        $Arg
    }
}

function Invoke-ExternalRaw {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList = @()
    )

    # Implementación simple usando &, capturando salida combinada
    $out = & $FilePath @ArgumentList 2>&1
    $code = $LASTEXITCODE
    $global:LASTEXITCODE = 0

    return @{
        ExitCode = $code
        StdOut   = ($out | Out-String)
        StdErr   = ''
    }
}

function Invoke-Robocopy {
    param(
        [string]$Source,
        [string]$Dest,
        [string]$Files = '*',
        [switch]$PreserveSecurity
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        Warn "Robocopy: origen no existe: $Source"
        return $false
    }

    New-Item -ItemType Directory -Path $Dest -Force | Out-Null

    $copyMode = if ($PreserveSecurity) { '/COPY:DATSOU' } else { '/COPY:DAT' }
    $opts     = "/E $copyMode /DCOPY:T /R:0 /W:0 /XJ /ZB /NFL /NDL /NP /MT:16"
    $cmd      = "robocopy `"$Source`" `"$Dest`" $Files $opts"

    Log "Robocopy: $cmd"
    cmd /c $cmd | Out-Null
    $code = $LASTEXITCODE
    $global:LASTEXITCODE = 0

    if ($code -ge 8) {
        Warn "Robocopy error. Code=$code. $Source -> $Dest"
        return $false
    } else {
        Log "Robocopy OK. Code=$code"
        return $true
    }
}

function Save-RegistryHive {
    param(
        [Parameter(Mandatory=$true)][string]$Hive,
        [Parameter(Mandatory=$true)][string]$OutPath
    )

    try {
        $dir = Split-Path -Parent $OutPath
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        cmd /c "reg save $Hive `"$OutPath`" /y" | Out-Null
        $code = $LASTEXITCODE
        $global:LASTEXITCODE = 0

        if ($code -ne 0 -or -not (Test-Path -LiteralPath $OutPath)) {
            Warn "reg save $Hive falló. Code=$code"
            return $false
        }

        Log "reg save $Hive OK"
        return $true
    } catch {
        Warn "reg save $Hive excepción: $($_.Exception.Message)"
        return $false
    }
}

# VSS helpers
$script:ShadowCache = @{}
$script:ShadowIds   = @()

function New-ShadowRoot {
    param(
        [Parameter(Mandatory=$true)][string]$DriveLetter  # "C:"
    )

    if ($script:ShadowCache.ContainsKey($DriveLetter)) {
        return $script:ShadowCache[$DriveLetter]
    }

    try {
        $res = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{
            Volume  = "$DriveLetter\"
            Context = 'ClientAccessible'
        } -ErrorAction Stop

        if ($res.ReturnValue -ne 0) {
            Note "VSS: Create devolvió $($res.ReturnValue) para $DriveLetter"
            return $null
        }

        $id  = $res.ShadowID
        $obj = Get-CimInstance -ClassName Win32_ShadowCopy -Filter "ID='$id'"
        $dev = $obj.DeviceObject

        if (-not $dev) {
            Note "VSS: No se resolvió DeviceObject para $DriveLetter"
            return $null
        }

        $script:ShadowCache[$DriveLetter] = $dev
        $script:ShadowIds += $id
        Log "VSS: snapshot creado para $DriveLetter ($dev)"
        return $dev
    } catch {
        Note "VSS: $($_.Exception.Message)"
        return $null
    }
}

function Remove-ShadowCopies {
    foreach ($id in $script:ShadowIds) {
        try {
            Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Delete -Arguments @{ ID = $id } -ErrorAction SilentlyContinue | Out-Null
        } catch {
            # Ignorar errores de limpieza
        }
    }
}

function Copy-FileWithFallback {
    param(
        [string]$Source,
        [string]$Dest
    )

    try {
        Copy-Item -LiteralPath $Source -Destination $Dest -Force -ErrorAction Stop
        Log "Copiado: $Source"
        return $true
    } catch {
        $msgDirect = $_.Exception.Message
    }

    $esent = "$env:SystemRoot\System32\esentutl.exe"
    if (Test-Path -LiteralPath $esent) {
        Log "Intentando copia con esentutl de: $Source"
        $res = Invoke-ExternalRaw -FilePath $esent -ArgumentList @('/y',$Source,'/d',$Dest,'/o')
        if ($res.ExitCode -eq 0 -and (Test-Path -LiteralPath $Dest)) {
            Log "esentutl OK: $Source"
            return $true
        } else {
            if ($res.ExitCode -eq -1032) {
                Note "esentutl no pudo copiar el archivo porque está en uso o bloqueado (ExitCode=-1032, JET_errFileAccessDenied). Se intentará copia usando VSS."
            } else {
                Note "esentutl no pudo copiar el archivo. ExitCode=$($res.ExitCode). Se intentará copia usando VSS si es posible."
            }
        }
    }

    $drive = [System.IO.Path]::GetPathRoot($Source)
    if ($drive -and $drive.Length -ge 2) {
        $driveLetter = $drive.Substring(0,2)   # "C:"
        $shadowRoot  = New-ShadowRoot -DriveLetter $driveLetter

        if ($shadowRoot) {
            $rel        = $Source.Substring($driveLetter.Length).TrimStart('\')
            $shadowPath = Join-Path $shadowRoot $rel

            try {
                Copy-Item -LiteralPath $shadowPath -Destination $Dest -Force -ErrorAction Stop
                Log "Copiado vía VSS: $Source"
                return $true
            } catch {
                $msgVss = $_.Exception.Message
                Warn "Copy-FileWithFallback falló. Directo='$msgDirect'; VSS='$msgVss'"
                return $false
            }
        }
    }

    Warn "Copy-FileWithFallback falló. Directo='$msgDirect'. No se pudo usar VSS."
    return $false
}

function New-Zip {
    param(
        [Parameter(Mandatory=$true)][string]$SourceRoot,
        [Parameter(Mandatory=$true)][string]$ZipPath
    )

    Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue

    # 1) Intento principal: .NET ZipFile.CreateFromDirectory (ZIP64)
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop

        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            $SourceRoot,
            $ZipPath,
            [System.IO.Compression.CompressionLevel]::Optimal,
            $false
        )

        Log "ZIP (.NET CreateFromDirectory) OK: $ZipPath"
        return
    } catch {
        Note "ZIP (.NET CreateFromDirectory) falló: $($_.Exception.Message). Se intentan otros métodos."
    }

    # 2) Fallback: Compress-Archive, solo si existe el cmdlet
    if (Get-Command -Name Compress-Archive -ErrorAction SilentlyContinue) {
        try {
            Compress-Archive -Path (Join-Path $SourceRoot '*') `
                             -DestinationPath $ZipPath `
                             -Force -ErrorAction Stop
            Log "ZIP (Compress-Archive) OK: $ZipPath"
            return
        } catch {
            Note "Compress-Archive falló (no crítico): $($_.Exception.Message)"
        }
    } else {
        Note "Compress-Archive no está disponible en esta versión de PowerShell."
    }

    # 3) Fallback adicional: tar.exe, solo si está disponible
    $tarCmd = Get-Command -Name tar.exe -ErrorAction SilentlyContinue
    if ($tarCmd) {
        try {
            & $tarCmd.Source -a -c -f $ZipPath -C $SourceRoot .
            if ($LASTEXITCODE -eq 0) {
                Log "ZIP (tar.exe) OK: $ZipPath"
                return
            } else {
                Note "tar.exe ZIP falló (no crítico). Code=$LASTEXITCODE"
            }
        } catch {
            Note "tar.exe ZIP excepción (no crítico): $($_.Exception.Message)"
        }
    } else {
        Note "tar.exe no está disponible en este sistema, se omite fallback."
    }

    # 4) Si llega aquí, no se pudo crear ZIP automáticamente
    Note "No se pudo crear ZIP automáticamente. La carpeta $SourceRoot contiene toda la evidencia; comprímela manualmente si es necesario."
}

# --- Prechequeo ---
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] 'Administrator'
)
if (-not $IsAdmin) {
    Write-Error 'Ejecuta este script en una PowerShell elevada (Run as administrator).'
    exit 1
}

try {
    Start-Transcript -Path (Join-Path $root 'transcript.log') -Force | Out-Null
} catch {
    Note "No se pudo iniciar Transcript: $($_.Exception.Message)"
}

# --- Plan de pasos ---
$TotalSteps = 9 + [int]$DumpMemory.IsPresent + [int]$FinalizeACL.IsPresent
$Step       = 0

# 1) Contexto
$Step++; StepProgress $Step $TotalSteps 'Contexto'
try {
    Log 'Contexto del sistema'
    (Get-Date).ToUniversalTime().ToString('o') | Out-File (Join-Path $root 'volatile\timestamp_utc.txt')
    Get-CimInstance Win32_OperatingSystem | Select-Object * | Out-String -Width 4096 | Out-File (Join-Path $root 'volatile\os.txt')
    Get-CimInstance Win32_ComputerSystem  | Select-Object * | Out-String -Width 4096 | Out-File (Join-Path $root 'volatile\system.txt')
    Get-HotFix | Out-String -Width 4096 | Out-File (Join-Path $root 'volatile\hotfix.txt')
    Get-WmiObject Win32_TimeZone | Out-String -Width 4096 | Out-File (Join-Path $root 'volatile\timezone.txt')
} catch {
    Warn "Contexto: $($_.Exception.Message)"
}

# 2) Volátil
$Step++; StepProgress $Step $TotalSteps 'Volátil'
try {
    Log 'Volátil: procesos/red/tareas/drivers'
    cmd /c 'tasklist /v'                           | Out-File (Join-Path $root 'volatile\tasklist.txt')
    cmd /c 'whoami /all'                           | Out-File (Join-Path $root 'volatile\whoami_all.txt')
    cmd /c 'query user'                            | Out-File (Join-Path $root 'volatile\query_user.txt') 2>$null
    cmd /c 'qwinsta'                               | Out-File (Join-Path $root 'volatile\qwinsta.txt') 2>$null
    cmd /c 'netstat -ano'                          | Out-File (Join-Path $root 'volatile\netstat.txt')
    cmd /c 'arp -a'                                | Out-File (Join-Path $root 'volatile\arp.txt')
    cmd /c 'ipconfig /all'                         | Out-File (Join-Path $root 'volatile\ipconfig.txt')
    cmd /c 'route print'                           | Out-File (Join-Path $root 'volatile\route.txt')
    Get-Process | Select-Object * | Out-String -Width 4096  | Out-File (Join-Path $root 'volatile\processes.txt')
    Get-Service | Select-Object * | Out-String -Width 4096  | Out-File (Join-Path $root 'volatile\services.txt')
    cmd /c 'schtasks /query /fo LIST /v'           | Out-File (Join-Path $root 'volatile\schtasks.txt')
    cmd /c 'driverquery /v'                        | Out-File (Join-Path $root 'volatile\drivers.txt')
} catch {
    Warn "Volátil: $($_.Exception.Message)"
}

# 3) Exportación .evtx
$Step++; StepProgress $Step $TotalSteps '.evtx'
$elog = Join-Path $root 'logs'
$requested = @(
    'Security',
    'System',
    'Application',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-WMI-Activity/Operational',
    'Microsoft-Windows-Bits-Client/Operational',
    'Microsoft-Windows-AppLocker/EXE and DLL',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
    'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'
)

try {
    try {
        $available = (Get-WinEvent -ListLog * -ErrorAction Stop).LogName
    } catch {
        $available = & wevtutil el 2>$null
    }

    $channels = @()
    foreach ($c in $requested) {
        if ($available -contains $c) {
            $channels += $c
        } else {
            Note "Canal inexistente o deshabilitado: $c"
        }
    }

    for ($i = 0; $i -lt $channels.Count; $i++) {
        $ch   = $channels[$i]
        $safe = ($ch -replace '[\\/]', '_')
        $pct  = [int]((($i + 1) / [math]::Max(1,$channels.Count)) * 100)

        Write-Progress -Id 2 -ParentId 1 -Activity 'Exportando eventos' -Status $ch -PercentComplete $pct

        try {
            $outFile = Join-Path $elog "$safe.evtx"
            $res = Invoke-ExternalRaw -FilePath 'wevtutil.exe' -ArgumentList @('epl', $ch, $outFile)
            if ($res.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $outFile)) {
                Warn "wevtutil epl $ch falló. ExitCode=$($res.ExitCode). StdErr=$($res.StdErr)"
            } else {
                Log "wevtutil $ch OK. ExitCode=0"
            }
        } catch {
            Warn "Export $ch excepción: $($_.Exception.Message)"
        }
    }

    Write-Progress -Id 2 -ParentId 1 -Activity 'Exportando eventos' -Completed
} catch {
    Warn ".evtx: $($_.Exception.Message)"
}

# 4) Artefactos
$Step++; StepProgress $Step $TotalSteps 'Artefactos'
try {
    Log 'Copiando winevt completo'
    Invoke-Robocopy -Source "$env:SystemRoot\System32\winevt\Logs" -Dest (Join-Path $elog 'winevt') -Files '*.evtx' -PreserveSecurity:$PreserveSecurity | Out-Null

    if (Test-Path -LiteralPath "$env:SystemRoot\Prefetch") {
        Log 'Copiando Prefetch'
        Invoke-Robocopy -Source "$env:SystemRoot\Prefetch" -Dest (Join-Path $root 'artifacts\Prefetch') -Files '*' -PreserveSecurity:$PreserveSecurity | Out-Null
    } else {
        Note 'Prefetch no encontrado. Puede estar deshabilitado.'
    }

    if (Test-Path -LiteralPath "$env:SystemRoot\System32\LogFiles\Firewall") {
        Log 'Copiando logs de Firewall'
        Invoke-Robocopy -Source "$env:SystemRoot\System32\LogFiles\Firewall" -Dest (Join-Path $elog 'Firewall') -Files '*' -PreserveSecurity:$PreserveSecurity | Out-Null
    } else {
        Note 'Ruta de Firewall no encontrada.'
    }

    if (Test-Path -LiteralPath 'C:\inetpub\logs\LogFiles') {
        Log 'Copiando logs de IIS'
        Invoke-Robocopy -Source 'C:\inetpub\logs\LogFiles' -Dest (Join-Path $elog 'IIS') -Files '*' -PreserveSecurity:$PreserveSecurity | Out-Null
    } else {
        Note 'IIS no presente o sin ruta de logs por defecto.'
    }

    Log 'Copiando Tasks'
    Invoke-Robocopy -Source "$env:SystemRoot\System32\Tasks" -Dest (Join-Path $root 'artifacts\Tasks') -Files '*' -PreserveSecurity:$PreserveSecurity | Out-Null

    Log 'Copiando Startup global'
    $globalStartup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    if (Test-Path -LiteralPath $globalStartup) {
        Invoke-Robocopy -Source $globalStartup -Dest (Join-Path $root 'artifacts\Startup_Global') -Files '*' -PreserveSecurity:$PreserveSecurity | Out-Null
    } else {
        Note 'Startup global no encontrada.'
    }
} catch {
    Warn "Artefactos: $($_.Exception.Message)"
}

# 5) Hives HKLM
$Step++; StepProgress $Step $TotalSteps 'Hives HKLM'
try {
    [void](Save-RegistryHive -Hive 'HKLM\SAM'      -OutPath (Join-Path $root 'registry\SAM.hiv'))
    [void](Save-RegistryHive -Hive 'HKLM\SYSTEM'   -OutPath (Join-Path $root 'registry\SYSTEM.hiv'))
    [void](Save-RegistryHive -Hive 'HKLM\SECURITY' -OutPath (Join-Path $root 'registry\SECURITY.hiv'))
    [void](Save-RegistryHive -Hive 'HKLM\SOFTWARE' -OutPath (Join-Path $root 'registry\SOFTWARE.hiv'))
    [void](Save-RegistryHive -Hive 'HKU\.DEFAULT'  -OutPath (Join-Path $root 'registry\DEFAULT.hiv'))

    $amc = "$env:WINDIR\AppCompat\Programs\Amcache.hve"
    if (Test-Path -LiteralPath $amc) {
        [void](Copy-FileWithFallback -Source $amc -Dest (Join-Path $root 'registry\Amcache.hve'))
    } else {
        Log 'Amcache no presente. Omitido.'
    }
} catch {
    Warn "Hives HKLM: $($_.Exception.Message)"
}

# 6) Hives usuario
$Step++; StepProgress $Step $TotalSteps 'Hives usuario'
try {
    $profiles = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notin @('Default','Default User','Public','All Users') }

    $pl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' |
          Select-Object PSChildName,ProfileImagePath

    foreach ($p in $profiles) {
        try {
            $dst = Join-Path $root ("registry\Users\" + $p.Name)
            New-Item -ItemType Directory -Path $dst -Force | Out-Null

            $sid = ($pl | Where-Object { $_.ProfileImagePath -eq $p.FullName } | Select-Object -First 1).PSChildName
            $didNt  = $false
            $didCls = $false

            if ($sid -and (Test-Path "HKU:\$sid")) {
                $didNt  = Save-RegistryHive -Hive "HKU\$sid" -OutPath (Join-Path $dst 'NTUSER.DAT')
                if (Test-Path "HKU:\${sid}_Classes") {
                    $didCls = Save-RegistryHive -Hive "HKU\${sid}_Classes" -OutPath (Join-Path $dst 'UsrClass.dat')
                }
            }

            if (-not $didNt) {
                $ntuser = Join-Path $p.FullName 'NTUSER.DAT'
                if (Test-Path -LiteralPath $ntuser) {
                    [void](Copy-FileWithFallback -Source $ntuser -Dest (Join-Path $dst 'NTUSER.DAT'))
                }
            }

            if (-not $didCls) {
                $usrcls = Join-Path $p.FullName 'AppData\Local\Microsoft\Windows\UsrClass.dat'
                if (Test-Path -LiteralPath $usrcls) {
                    [void](Copy-FileWithFallback -Source $usrcls -Dest (Join-Path $dst 'UsrClass.dat'))
                }
            }

            $userStartup = Join-Path $p.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
            if (Test-Path -LiteralPath $userStartup) {
                Invoke-Robocopy -Source $userStartup -Dest (Join-Path $root ("artifacts\Startup_" + $p.Name)) -Files '*' -PreserveSecurity:$PreserveSecurity | Out-Null
            }
        } catch {
            Warn "Hives/Startup usuario $($p.Name): $($_.Exception.Message)"
        }
    }
} catch {
    Warn "Hives usuario: $($_.Exception.Message)"
}

# 7) WMI
$Step++; StepProgress $Step $TotalSteps 'WMI'
try {
    $wmip = Join-Path $root 'artifacts\WMI'
    New-Item -ItemType Directory -Path $wmip -Force | Out-Null

    Get-CimInstance -Namespace root\subscription -ClassName __EventFilter             | Out-String -Width 4096 | Out-File (Join-Path $wmip 'EventFilter.txt')
    Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer           | Out-String -Width 4096 | Out-File (Join-Path $wmip 'EventConsumer.txt')
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Out-String -Width 4096 | Out-File (Join-Path $wmip 'FilterToConsumerBinding.txt')
} catch {
    Warn "WMI: $($_.Exception.Message)"
}

# 8) Memoria (opcional)
$memPath = ''
if ($DumpMemory) {
    $Step++; StepProgress $Step $TotalSteps 'Memoria'
    Log 'Volcado de RAM con WinPMEM'

    if (-not $WinpmemPath -or $WinpmemPath.Trim().Length -eq 0) {
        Warn "Se especificó -DumpMemory pero -WinpmemPath está vacío. RAM omitida."
    } elseif (-not (Test-Path -LiteralPath $WinpmemPath)) {
        Warn "WinPMEM no encontrado en $WinpmemPath. RAM omitida."
    } else {
        try {
            $totalRam = [double]((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory)

            if ($BasePath -match '^[A-Za-z]:') {
                $driveLetter = $BasePath.Substring(0,2)
                $drv = Get-PSDrive -Name ($driveLetter.TrimEnd('\').TrimEnd(':')) -ErrorAction SilentlyContinue
                if ($drv -and $drv.Free -lt $totalRam * 1.2) {
                    Warn ("Espacio libre insuficiente en {0} para volcado de memoria. " +
                          "Se requiere al menos ~120% de la RAM (~{1} GB)." -f $driveLetter,
                          [math]::Round($totalRam/1GB,2))
                }
            }

            $memPath   = Join-Path $root "$hostn-$ts.raw"
            $arguments = @($memPath)

            $proc = Start-Process -FilePath $WinpmemPath `
                                  -ArgumentList $arguments `
                                  -NoNewWindow -PassThru

            while ($proc -and -not $proc.HasExited) {
                $size = if (Test-Path -LiteralPath $memPath) {
                    (Get-Item -LiteralPath $memPath).Length
                } else { 0 }
                $pct  = if ($totalRam -gt 0) {
                    [int]([math]::Min(99, ($size / $totalRam) * 100))
                } else { 0 }
                Write-Progress -Id 3 -ParentId 1 -Activity 'WinPMEM' `
                    -Status ("{0:N2} MB escritos" -f ($size/1MB)) `
                    -PercentComplete $pct
                Start-Sleep -Seconds 2
            }

            Write-Progress -Id 3 -ParentId 1 -Activity 'WinPMEM' -Completed

            if (-not $proc) {
                Warn ("WinPMEM no se inició correctamente. No hay objeto de proceso disponible. " +
                      "Verifica la ruta y prueba a ejecutar la herramienta manualmente.")
            } elseif ($proc.ExitCode -ne 0) {
                Warn ("WinPMEM terminó con error. ExitCode={0}. " +
                      "Ejecuta WinPMEM manualmente para ver el mensaje detallado en consola." -f $proc.ExitCode)
            } elseif (-not (Test-Path -LiteralPath $memPath)) {
                Warn "WinPMEM terminó con ExitCode=0 pero no se encontró el archivo de volcado en $memPath."
            } else {
                Log "WinPMEM OK. Dump en: $memPath"
            }
        } catch {
            Warn "WinPMEM: $($_.Exception.Message)"
        }
    }
}

# 9) Manifiesto
$Step++; StepProgress $Step $TotalSteps 'Manifiesto'
try {
    Log 'Creando manifest.json'

    $os  = Get-CimInstance Win32_OperatingSystem
    $sys = Get-CimInstance Win32_ComputerSystem

    $memGB  = [math]::Round(($sys.TotalPhysicalMemory / 1GB),2)
    $freeGB = $null

    if ($BasePath -match '^[A-Za-z]:') {
        $driveName = $BasePath.Substring(0,2).TrimEnd('\').TrimEnd(':')
        $drv    = Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue
        if ($drv) {
            $freeGB = [math]::Round(($drv.Free / 1GB),2)
        }
    }

    $toolMemLeaf = if ($WinpmemPath) { Split-Path -Leaf $WinpmemPath } else { '' }
    $memDumpLeaf = if ($memPath)     { Split-Path -Leaf $memPath }     else { '' }

    # Evitar Test-Path con cadena vacía
    $winpmemPresent = $false
    if ($WinpmemPath -and $WinpmemPath.Trim().Length -gt 0) {
        try {
            $winpmemPresent = Test-Path -LiteralPath $WinpmemPath
        } catch {
            $winpmemPresent = $false
            Note "Manifest: Test-Path WinpmemPath falló: $($_.Exception.Message)"
        }
    }

    $manifest = [ordered]@{
        Host       = $hostn
        TimeUTC    = $ts
        Operator   = $Operator
        Base       = $root
        MemoryDump = $memDumpLeaf
        System     = @{
            OSVersion    = $os.Version
            Build        = $os.BuildNumber
            Caption      = $os.Caption
            TotalRAMGB   = $memGB
            FreeSpaceGB  = $freeGB
        }
        Tooling    = @{
            MemoryPath     = $toolMemLeaf
            Script         = 'Collect-Evidence-Ransomware.ps1'
            ScriptVersion  = $ScriptVersion
            WinpmemPresent = $winpmemPresent
        }
        Notes      = 'Script de triage para incidente de ransomware. No realiza hashing ni asegura cadena de custodia formal.'
    }

    $manifest | ConvertTo-Json -Depth 6 | Out-File (Join-Path $root 'manifest.json') -Encoding utf8
} catch {
    Warn "Manifest: $($_.Exception.Message)"
}

# Cerrar transcript (sin aumentar pasos)
try {
    Stop-Transcript | Out-Null
} catch {
    Note "Stop-Transcript: $($_.Exception.Message)"
}

# 10) ZIP
$Step++; StepProgress $Step $TotalSteps 'ZIP'
$zipPath = Join-Path $BasePath "$hostn-$ts.zip"
try {
    Log "Comprimiendo a ZIP: $zipPath"
    try {
        New-Zip -SourceRoot $root -ZipPath $zipPath
    } catch {
        Warn "ZIP general: $($_.Exception.Message)"
    }
    Write-Progress -Id 5 -ParentId 1 -Activity 'Compresión ZIP' -Completed
} catch {
    Warn "ZIP general: $($_.Exception.Message)"
}

# 11) ACL final (opcional)
if ($FinalizeACL) {
    $Step++; StepProgress $Step $TotalSteps 'ACL final (opcional)'
    try {
        Log 'Aplicando ACL de solo lectura (opcional)'

        # En entornos con ConstrainedLanguage puede fallar la creación de objetos .NET.
        # Si falla, simplemente se omite el endurecimiento de ACL.
        $adminAcct = $null
        try {
            $adminSid  = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
            $adminAcct = $adminSid.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            Note "No se pudo resolver SID de Administradores, se omite endurecimiento ACL: $($_.Exception.Message)"
        }

        if ($adminAcct) {
            cmd /c "icacls `"$root`"   /inheritance:r"                  1>nul 2>nul
            cmd /c "icacls `"$root`"   /grant:r `"$adminAcct`":(R) /T"  1>nul 2>nul
            cmd /c "icacls `"$zipPath`" /inheritance:r"                 1>nul 2>nul
            cmd /c "icacls `"$zipPath`" /grant:r `"$adminAcct`":(R)"    1>nul 2>nul

            try {
                attrib +R $zipPath
            } catch {
                Warn "attrib ZIP: $($_.Exception.Message)"
            }
        }
    } catch {
        Warn "ACL final: $($_.Exception.Message)"
    }
}

# --- Limpieza VSS y salida ---
Remove-ShadowCopies | Out-Null
Write-Progress -Id 1 -Activity 'Recolección de evidencia (ransomware)' -Completed

if ($global:ErrorList.Count -gt 0) {
    'Errores detectados:' | Out-File $ErrorsPath -Encoding utf8
    $global:ErrorList     | Out-File $ErrorsPath -Append -Encoding utf8
    Warn "Finalizado con errores. Ver $ErrorsPath"
    Log  "Carpeta: $root"
    Log  "ZIP: $zipPath"
    exit 2
} else {
    Log 'Finalizado sin errores.'
    Log "Carpeta: $root"
    Log "ZIP: $zipPath"
    exit 0
}
