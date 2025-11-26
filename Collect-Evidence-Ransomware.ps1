<#
  Collect-Evidence-Ransomware-Lite.ps1 (v1.0.0)

  Versión reducida para entornos con PowerShell en ConstrainedLanguage.

  Características:
    - Recolecta:
        * Contexto del sistema.
        * Información volátil (procesos, red, sesiones, tareas, drivers).
        * Logs de eventos .evtx seleccionados.
        * Artefactos básicos: winevt, Prefetch, Firewall, IIS, Tasks, Startup.
        * Hives de registro HKLM y de usuarios (si es posible).
        * Suscripciones WMI básicas.
        * Volcado de RAM opcional mediante WinPMEM (ejecutado como proceso externo).
    - Opcionalmente intenta comprimir todo a ZIP con Compress-Archive.
    - No usa VSS, ni Add-Type, ni objetos .NET avanzados.

  Requisitos:
    - Ejecutar idealmente como Administrador.
    - PowerShell 4.0 o superior.
    - Windows Server 2012 / Windows 8 o superior.

  Ejemplos:
    powershell -ExecutionPolicy Bypass -File .\Collect-Evidence-Ransomware-Lite.ps1 -BasePath E:\evidence -Operator "SOC"
    powershell -ExecutionPolicy Bypass -File .\Collect-Evidence-Ransomware-Lite.ps1 -BasePath E:\evidence -Operator "SOC" -DumpMemory -WinpmemPath "E:\tools\winpmem_mini_x64_rc2.exe"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BasePath,

    [string]$Operator = "",

    [switch]$DumpMemory,

    [string]$WinpmemPath = "",

    [switch]$PreserveSecurity,

    [switch]$Help
)

if ($Help) {
@"
Collect-Evidence-Ransomware-Lite.ps1 (v1.0.0)

Parámetros:
  -BasePath <ruta>     Obligatorio. Carpeta raíz de salida (D:\evidence o \\srv\share).
  -Operator <texto>    Nombre del operador/analista (metadato).
  -DumpMemory          Intenta volcar RAM usando WinPMEM (ruta obligatoria).
  -WinpmemPath <ruta>  Ruta completa al ejecutable de WinPMEM.
  -PreserveSecurity    Usa robocopy con /COPY:DATSOU para intentar preservar SACL/OWNER.
  -Help                Muestra esta ayuda.

Ejemplos:
  powershell -File .\Collect-Evidence-Ransomware-Lite.ps1 -BasePath E:\evidence -Operator "SOC"
  powershell -File .\Collect-Evidence-Ransomware-Lite.ps1 -BasePath E:\evidence -DumpMemory -WinpmemPath "E:\tools\winpmem_mini_x64_rc2.exe"
"@ | Out-Host
    return
}

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'Continue'
$ScriptVersion         = '1.0.0'

# --- Carpetas base ---
$hostn = $env:COMPUTERNAME
$ts    = Get-Date -Format 'yyyyMMddTHHmmss'
$root  = Join-Path $BasePath "$hostn-$ts"

New-Item -ItemType Directory -Path $root -Force | Out-Null
'logs','volatile','registry','artifacts' | ForEach-Object {
    New-Item -ItemType Directory -Path (Join-Path $root $_) -Force | Out-Null
}

$LogPath    = Join-Path $root 'collection.log'
$ErrorsPath = Join-Path $root 'errors.log'
$global:ErrorList = @()

function Log {
    param([string]$Message)
    $t = Get-Date -Format 'o'
    "[{0}] {1}" -f $t, $Message | Tee-Object -FilePath $LogPath -Append | Out-Host
}

function Warn {
    param([string]$Message)
    $t = Get-Date -Format 'o'
    "[{0}] [WARN] {1}" -f $t, $Message | Tee-Object -FilePath $LogPath -Append | Out-Host
    $global:ErrorList += $Message
}

function Note {
    param([string]$Message)
    $t = Get-Date -Format 'o'
    "[{0}] [NOTE] {1}" -f $t, $Message | Tee-Object -FilePath $LogPath -Append | Out-Host
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
        return
    }

    New-Item -ItemType Directory -Path $Dest -Force | Out-Null

    $copyMode = if ($PreserveSecurity) { '/COPY:DATSOU' } else { '/COPY:DAT' }
    $opts     = "/E $copyMode /DCOPY:T /R:0 /W:0 /XJ /ZB /NFL /NDL /NP"

    Log "Robocopy: $Source -> $Dest ($Files)"
    cmd /c "robocopy `"$Source`" `"$Dest`" $Files $opts" | Out-Null
    $code = $LASTEXITCODE

    if ($code -ge 8) {
        Warn "Robocopy error. Code=$code. $Source -> $Dest"
    } else {
        Log "Robocopy OK. Code=$code"
    }
}

function Save-RegistryHive {
    param(
        [Parameter(Mandatory = $true)][string]$Hive,
        [Parameter(Mandatory = $true)][string]$OutPath
    )

    try {
        $dir = Split-Path -Parent $OutPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        cmd /c "reg save $Hive `"$OutPath`" /y" | Out-Null
        $code = $LASTEXITCODE

        if ($code -ne 0 -or -not (Test-Path -LiteralPath $OutPath)) {
            Warn "reg save $Hive falló. Code=$code"
        } else {
            Log "reg save $Hive OK"
        }
    } catch {
        Warn "reg save $Hive excepción: $($_.Exception.Message)"
    }
}

function Try-Copy {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Dest
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        Warn "No se encontró $Source"
        return
    }

    $dir = Split-Path -Parent $Dest
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    try {
        Copy-Item -LiteralPath $Source -Destination $Dest -Force -ErrorAction Stop
        Log "Copiado: $Source"
    } catch {
        Warn "No se pudo copiar $Source $($_.Exception.Message)"
    }
}

# --- Comprobación básica de admin (no crítica) ---
try {
    $groups = whoami /groups 2>$null
    if ($groups -notmatch 'S-1-5-32-544') {
        Warn "La sesión podría no ser de Administrador (whoami /groups no muestra el grupo Administradores)."
    } else {
        Note "Sesión parece tener privilegios de Administrador."
    }
} catch {
    Note "No se pudo comprobar si la sesión es de administrador: $($_.Exception.Message)"
}

# --- Transcript ---
try {
    Start-Transcript -Path (Join-Path $root 'transcript.log') -Force | Out-Null
} catch {
    Note "No se pudo iniciar Transcript: $($_.Exception.Message)"
}

# 1) Contexto del sistema
try {
    Log 'Contexto del sistema'
    Get-Date -Format 'o' | Out-File (Join-Path $root 'volatile\timestamp_local.txt')
    Get-CimInstance Win32_OperatingSystem | Select-Object * | Out-String -Width 4096 | Out-File (Join-Path $root 'volatile\os.txt')
    Get-CimInstance Win32_ComputerSystem  | Select-Object * | Out-String -Width 4096 | Out-File (Join-Path $root 'volatile\system.txt')
    Get-HotFix | Out-String -Width 4096 | Out-File (Join-Path $root 'volatile\hotfix.txt')
    Get-WmiObject Win32_TimeZone | Out-String -Width 4096 | Out-File (Join-Path $root 'volatile\timezone.txt')
} catch {
    Warn "Contexto: $($_.Exception.Message)"
}

# 2) Información volátil
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
    Get-Process | Select-Object * | Out-String -Width 4096 | Out-File (Join-Path $root 'volatile\processes.txt')
    Get-Service | Select-Object * | Out-String -Width 4096 | Out-File (Join-Path $root 'volatile\services.txt')
    cmd /c 'schtasks /query /fo LIST /v'           | Out-File (Join-Path $root 'volatile\schtasks.txt')
    cmd /c 'driverquery /v'                        | Out-File (Join-Path $root 'volatile\drivers.txt')
} catch {
    Warn "Volátil: $($_.Exception.Message)"
}

# 3) Exportación de eventos .evtx
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
    $availableLogs = @()

    try {
        $availableLogs = (Get-WinEvent -ListLog * -ErrorAction Stop).LogName
    } catch {
        # Fallback: wevtutil el
        $availableLogs = & wevtutil el 2>$null
    }

    foreach ($c in $requested) {
        if ($availableLogs -contains $c) {
            $safe = ($c -replace '[\\/]', '_')
            $outFile = Join-Path $elog "$safe.evtx"

            try {
                Log "Exportando canal: $c"
                wevtutil epl "$c" "$outFile" 2>&1 | Out-Null
                if (-not (Test-Path -LiteralPath $outFile)) {
                    Warn "wevtutil epl $c parece haber fallado (no se generó el archivo)."
                } else {
                    Log "wevtutil $c OK."
                }
            } catch {
                Warn "Export $c excepción: $($_.Exception.Message)"
            }
        } else {
            Note "Canal inexistente o deshabilitado: $c"
        }
    }
} catch {
    Warn ".evtx: $($_.Exception.Message)"
}

# 4) Artefactos de disco
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
try {
    Save-RegistryHive -Hive 'HKLM\SAM'      -OutPath (Join-Path $root 'registry\SAM.hiv')
    Save-RegistryHive -Hive 'HKLM\SYSTEM'   -OutPath (Join-Path $root 'registry\SYSTEM.hiv')
    Save-RegistryHive -Hive 'HKLM\SECURITY' -OutPath (Join-Path $root 'registry\SECURITY.hiv')
    Save-RegistryHive -Hive 'HKLM\SOFTWARE' -OutPath (Join-Path $root 'registry\SOFTWARE.hiv')
    Save-RegistryHive -Hive 'HKU\.DEFAULT'  -OutPath (Join-Path $root 'registry\DEFAULT.hiv')

    $amc = "$env:WINDIR\AppCompat\Programs\Amcache.hve"
    if (Test-Path -LiteralPath $amc) {
        Try-Copy -Source $amc -Dest (Join-Path $root 'registry\Amcache.hve')
    } else {
        Log 'Amcache no presente. Omitido.'
    }
} catch {
    Warn "Hives HKLM: $($_.Exception.Message)"
}

# 6) Hives de usuario y Startup usuario
try {
    $profiles = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notin @('Default','Default User','Public','All Users') }

    $pl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' |
          Select-Object PSChildName,ProfileImagePath

    foreach ($p in $profiles) {
        try {
            $dst = Join-Path $root ("registry\Users\" + $p.Name)
            New-Item -ItemType Directory -Path $dst -Force | Out-Null

            $sidEntry = $pl | Where-Object { $_.ProfileImagePath -eq $p.FullName } | Select-Object -First 1
            $sid      = $null
            if ($sidEntry) { $sid = $sidEntry.PSChildName }

            if ($sid -and (Test-Path "HKU:\$sid")) {
                Save-RegistryHive -Hive "HKU\$sid" -OutPath (Join-Path $dst 'NTUSER.DAT')
                if (Test-Path "HKU:\${sid}_Classes") {
                    Save-RegistryHive -Hive "HKU\${sid}_Classes" -OutPath (Join-Path $dst 'UsrClass.dat')
                }
            } else {
                # Fallback: copiar archivos del perfil
                $ntuser = Join-Path $p.FullName 'NTUSER.DAT'
                if (Test-Path -LiteralPath $ntuser) {
                    Try-Copy -Source $ntuser -Dest (Join-Path $dst 'NTUSER.DAT')
                }

                $usrcls = Join-Path $p.FullName 'AppData\Local\Microsoft\Windows\UsrClass.dat'
                if (Test-Path -LiteralPath $usrcls) {
                    Try-Copy -Source $usrcls -Dest (Join-Path $dst 'UsrClass.dat')
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

# 7) Suscripciones WMI
try {
    $wmip = Join-Path $root 'artifacts\WMI'
    New-Item -ItemType Directory -Path $wmip -Force | Out-Null

    Get-CimInstance -Namespace root\subscription -ClassName __EventFilter             | Out-String -Width 4096 | Out-File (Join-Path $wmip 'EventFilter.txt')
    Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer           | Out-String -Width 4096 | Out-File (Join-Path $wmip 'EventConsumer.txt')
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Out-String -Width 4096 | Out-File (Join-Path $wmip 'FilterToConsumerBinding.txt')
} catch {
    Warn "WMI: $($_.Exception.Message)"
}

# 8) Volcado de memoria (opcional)
$memPath = ''
if ($DumpMemory) {
    Log 'Volcado de RAM con WinPMEM (lite)'

    if (-not $WinpmemPath -or $WinpmemPath.Trim().Length -eq 0) {
        Warn "Se especificó -DumpMemory pero -WinpmemPath está vacío. RAM omitida."
    } elseif (-not (Test-Path -LiteralPath $WinpmemPath)) {
        Warn "WinPMEM no encontrado en $WinpmemPath. RAM omitida."
    } else {
        try {
            $memPath = Join-Path $root "$hostn-$ts.raw"
            $arguments = @($memPath)

            Log "Ejecutando WinPMEM: `"$WinpmemPath`" $memPath"
            Start-Process -FilePath $WinpmemPath -ArgumentList $arguments -NoNewWindow -Wait

            if (Test-Path -LiteralPath $memPath) {
                Log "WinPMEM completado. Dump en: $memPath"
            } else {
                Warn "WinPMEM terminó pero no se encontró el archivo de volcado en $memPath."
            }
        } catch {
            Warn "WinPMEM: $($_.Exception.Message)"
        }
    }
}

# 9) Manifesto simple
try {
    Log 'Creando manifest.json (lite)'

    $os  = Get-CimInstance Win32_OperatingSystem
    $sys = Get-CimInstance Win32_ComputerSystem

    $memDumpLeaf = if ($memPath) { Split-Path -Leaf $memPath } else { '' }

    $manifest = @{
        Host       = $hostn
        TimeLocal  = Get-Date -Format 'o'
        Operator   = $Operator
        Base       = $root
        MemoryDump = $memDumpLeaf
        System     = @{
            OSVersion          = $os.Version
            Build              = $os.BuildNumber
            Caption            = $os.Caption
            TotalPhysicalBytes = $sys.TotalPhysicalMemory
        }
        Tooling    = @{
            Script        = 'Collect-Evidence-Ransomware-Lite.ps1'
            ScriptVersion = $ScriptVersion
            WinpmemPath   = $WinpmemPath
        }
        Notes      = 'Versión lite pensada para entornos con PowerShell en ConstrainedLanguage. No usa VSS ni Add-Type.'
    }

    $manifest | ConvertTo-Json -Depth 5 | Out-File (Join-Path $root 'manifest.json') -Encoding utf8
} catch {
    Warn "Manifest: $($_.Exception.Message)"
}

# Cerrar transcript
try {
    Stop-Transcript | Out-Null
} catch {
    Note "Stop-Transcript: $($_.Exception.Message)"
}

# 10) Compresión ZIP (solo Compress-Archive)
$zipPath = Join-Path $BasePath "$hostn-$ts.zip"
try {
    if (Get-Command -Name Compress-Archive -ErrorAction SilentlyContinue) {
        Log "Comprimiendo a ZIP (Compress-Archive): $zipPath"
        try {
            Compress-Archive -Path $root -DestinationPath $zipPath -Force -ErrorAction Stop
            Log "ZIP (Compress-Archive) OK: $zipPath"
        } catch {
            Warn "Compress-Archive falló (no crítico): $($_.Exception.Message)"
        }
    } else {
        Note "Compress-Archive no está disponible. No se creará ZIP automático."
    }
} catch {
    Warn "ZIP general: $($_.Exception.Message)"
}

# --- Salida final ---
if ($global:ErrorList.Count -gt 0) {
    'Errores detectados:' | Out-File $ErrorsPath -Encoding utf8
    $global:ErrorList     | Out-File $ErrorsPath -Append -Encoding utf8
    Warn "Finalizado con advertencias/errores. Ver $ErrorsPath"
    Log  "Carpeta: $root"
    Log  "ZIP: $zipPath"
    exit 2
} else {
    Log 'Finalizado sin errores registrados (lite).'
    Log "Carpeta: $root"
    Log "ZIP: $zipPath"
    exit 0
}
