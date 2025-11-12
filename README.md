# DFIR-scripts
# Collect-Evidence-DFIR-Improved — README

> Versión del script: **v1.3.5**
> Recolector de evidencia para Windows con buenas prácticas DFIR: exporta eventos, artefactos de persistencia, hives de registro (HKLM/usuario), WMI, hashes, manifiesto y ZIP final; volcado de RAM opcional con WinPMEM; coping robusto (VSS) y trazabilidad.

---

## TL;DR (uso rápido)

```powershell
# Mostrar ayuda
powershell -ExecutionPolicy Bypass -File .\Collect-Evidence-DFIR-Improved.ps1 -Help

# Recolección básica
powershell -EP Bypass -File .\Collect-Evidence-DFIR-Improved.ps1 -BasePath E:\evidence -Operator "SOC"

# Con volcado de memoria (WinPMEM)
powershell -EP Bypass -File .\Collect-Evidence-DFIR-Improved.ps1 -BasePath E:\evidence -DumpMemory -WinpmemPath E:\tools\winpmem_mini_x64.exe

# Copia preservando SACL/OWNER (cadena de custodia)
powershell -EP Bypass -File .\Collect-Evidence-DFIR-Improved.ps1 -BasePath \\srv\dfir -PreserveSecurity

# Endurecer permisos al final (solo lectura para Administradores)
powershell -EP Bypass -File .\Collect-Evidence-DFIR-Improved.ps1 -BasePath D:\evidence -FinalizeACL

# Excluir rutas del hashing (comodines relativos al caso)
powershell -EP Bypass -File .\Collect-Evidence-DFIR-Improved.ps1 -BasePath E:\evidence -HashExclude 'artifacts\Tasks\Microsoft\Windows\UNP\*'
```

> **Requisitos**: ejecutar como **Administrador**. Salidas y artefactos se escriben bajo `-BasePath`.

---

## Parámetros

| Parámetro           | Tipo     | Obligatorio | Descripción                                                                                  |
| ------------------- | -------- | ----------- | -------------------------------------------------------------------------------------------- |
| `-BasePath`         | string   | Sí          | Carpeta raíz de salida (p. ej. `D:\evidence` o `\\servidor\share`).                          |
| `-Operator`         | string   | No          | Nombre del operador (metadato en `manifest.json`).                                           |
| `-DumpMemory`       | switch   | No          | Habilita volcado de RAM con WinPMEM. Requiere `-WinpmemPath`.                                |
| `-WinpmemPath`      | string   | No          | Ruta al ejecutable de WinPMEM.                                                               |
| `-PreserveSecurity` | switch   | No          | Robocopy con `/COPY:DATSOU` y `/DCOPY:T` (incluye DACL/SACL/Owner). Por defecto `/COPY:DAT`. |
| `-HashExclude`      | string[] | No          | Patrones de rutas a **excluir** del hashing (relativos a la carpeta del caso).               |
| `-FinalizeACL`      | switch   | No          | ACL final opcional: solo lectura para grupo Administradores (independiente de idioma).       |
| `-Help` / `-?`      | switch   | —           | Muestra ayuda integrada y termina.                                                           |

**Códigos de salida**: `0` sin errores; `2` con errores resumidos en `errors.log`; `1` si no se ejecutó como Admin.

---

## Estructura de salida

```
<BasePath>\<HOST>-<UTC>\
├─ collection.log            # Bitácora de alto nivel
├─ errors.log                # Resumen de errores reales (si los hay)
├─ transcript.log            # Transcripción PowerShell (cerrada antes del hashing)
├─ manifest.json             # Metadatos del caso (host, OS, RAM, free space, hashes de herramientas)
├─ hashes_sha256.csv         # Hash de cada archivo recolectado
├─ volatile\                 # Estado volátil del sistema
│  ├─ tasklist.txt           # tasklist /v
│  ├─ processes.txt          # Get-Process completo
│  ├─ whoami_all.txt         # whoami /all
│  ├─ netstat.txt, arp.txt, ipconfig.txt, route.txt
│  ├─ schtasks.txt, drivers.txt
│  └─ hotfix.txt, os.txt, system.txt, timestamp_utc.txt
├─ logs\
│  ├─ Security.evtx, System.evtx, Application.evtx, ...
│  ├─ Microsoft-Windows-*.evtx
│  └─ winevt\*.evtx          # Copia íntegra de \Windows\System32\winevt\Logs
├─ logs\Firewall\*           # Si existe
├─ logs\IIS\W3SVC*\*.log     # Si existe
├─ artifacts\
│  ├─ Prefetch\*             # Prefetch (si habilitado)
│  ├─ Tasks\...               # Copia de \Windows\System32\Tasks (XML)
│  ├─ Startup_Global\*       # Inicio global
│  ├─ Startup_<user>\*       # Inicio por usuario
│  └─ WMI\EventFilter.txt, EventConsumer.txt, FilterToConsumerBinding.txt
└─ registry\
   ├─ SAM.hiv, SYSTEM.hiv, SECURITY.hiv, SOFTWARE.hiv, DEFAULT.hiv
   ├─ Amcache.hve            # Copiado con VSS si estaba en uso
   └─ Users\<user>\NTUSER.DAT, UsrClass.dat

# ZIP final
<BasePath>\<HOST>-<UTC>.zip          # ZIP del caso
<BasePath>\<HOST>-<UTC>.zip.sha256.txt
```

---

## ¿Qué se recolecta y por qué?

### 1) Registro de ejecución y metadatos

* **`collection.log`**: línea de tiempo de la recolección (útil para cadena de custodia y explicación de omisiones).
* **`errors.log`**: solo errores **reales** que requieren atención.
* **`transcript.log`**: comandos PowerShell (se cierra antes del hashing para no bloquear el archivo).
* **`manifest.json`**: contexto del host (OS/Build, RAM, espacio libre), operador, ruta y hashes de herramientas.
* **`hashes_sha256.csv`** y **`<ZIP>.sha256.txt`**: integridad de evidencias y del contenedor final.

### 2) Volátil (estado actual)

* **Procesos** (`processes.txt` y `tasklist.txt`), **Red** (`netstat/arp/ipconfig/route`), **Servicios**, **Tareas (vista)**, **Drivers** y **Token actual** (`whoami_all`).
* **Uso**: detectar ejecuciones inusuales, conexiones salientes, puertos a la escucha, drivers no firmados, tareas anómalas.

### 3) Registros de eventos (.evtx)

* Exportados selectivamente y copia íntegra de `winevt`. Canales clave:

  * `Security`, `System`, `Application`
  * `Microsoft-Windows-PowerShell/Operational` (4103/4104)
  * `Microsoft-Windows-TaskScheduler/Operational`
  * `Microsoft-Windows-Windows Defender/Operational`
  * `Microsoft-Windows-WMI-Activity/Operational`
  * `Microsoft-Windows-Bits-Client/Operational`
  * `Microsoft-Windows-AppLocker/EXE and DLL` (si está habilitado)
  * `Microsoft-Windows-Sysmon/Operational` (si el host lo tiene)

### 4) Artefactos de ejecución/persistencia

* **Prefetch** (`artifacts\Prefetch\`) → evidencia de ejecución.
* **Tareas programadas** (`artifacts\Tasks\...`) → persistencia y orquestación.
* **StartUp** global/usuario (`artifacts\Startup_*`) → persistencia al logon.
* **WMI** (`artifacts\WMI\*.txt`) → suscripciones de persistencia (Filter/Consumer/Binding).

### 5) Registro (hives)

* **HKLM** (`SYSTEM/SECURITY/SAM/SOFTWARE/DEFAULT`) con `reg save`.
* **Usuario** (`NTUSER.DAT` y `UsrClass.dat`), con `reg save`, `esentutl` o **VSS** si estaban en uso.
* **Amcache.hve** (instalación/ejecuciones) con **VSS** si estaba bloqueado.

### 6) Memoria (opcional)

* **`<HOST>-<UTC>.raw`** (WinPMEM) + `memory_SHA256.txt`.
* Análisis con **Volatility 3** (procesos, inyección, red, strings, Yara, servicios, drivers).

---

## ¿Cómo analizarlo luego?

### Eventos (.evtx)

Herramientas recomendadas:

* **Hayabusa**: detecciones rápidas Sigma.
* **Chainsaw**: hunting con reglas Sigma y mapping de campos.
* **Eric Zimmerman EvtxECmd**: parseo por canal/plantillas.

Ejemplos:

```powershell
# Hayabusa (CSV)
hayabusa.exe -e .\logs -o .\out\hayabusa_report.csv

# Chainsaw (detecciones)
chainsaw hunt .\logs --rules .\sigma\ --mapping .\mappings\windows-event-logs.yml -o .\out\

# EvtxECmd (PowerShell Operational)
EvtxECmd.exe -f .\logs\Microsoft-Windows-PowerShell_Operational.evtx --csv .\out\
```

Pistas comunes:

* **Security**: 4624/4625 (logons), 4672 (privilegios), 4697 (servicio), 4720 (usuario).
* **PowerShell Operational**: 4104 (scriptblock), 4103 (módulos). Buscar `FromBase64String`, `-enc`, `-nop`.
* **WMI-Activity**: 5857–5861 (Filter/Consumer/Binding).
* **TaskScheduler Operational**: 106/140 (creación/ejecución).
* **BITS**: 59/63 (descargas).
* **Defender**: 1116 (detecciones).

### Prefetch / Amcache

```powershell
# Prefetch\ nPECmd.exe -d .\artifacts\Prefetch -o .\out\prefetch.csv

# Amcache
AmcacheParser.exe -f .\registry\Amcache.hve --csv .\out\amcache.csv
```

Cruzar ejecutables/timestamps con **Security 4688** o **Sysmon 1** (si existe), y con `artifacts\Tasks`.

### Tareas / Startup / WMI

* Abrir XMLs en `artifacts\Tasks` y revisar `Actions/Exec/Command` y `WorkingDirectory`.
* Buscar en Startup ejecutables o accesos directos no esperados.
* En WMI, revisar:

  * `__EventFilter` → `Query` (triggers sospechosos)
  * `__EventConsumer` → `CommandLineTemplate`/`ScriptText`
  * `__FilterToConsumerBinding` → uniones entre ambos

### Registro (hives)

Herramientas: **Registry Explorer / RECmd**, **ShellBagsExplorer**, parsers específicos.

Claves útiles:

* `HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run(Once)`
* `HKLM\SYSTEM\CurrentControlSet\Services\*` (persistencia por servicio)
* `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
* `HKCU\Software\Classes\CLSID\{...}\InprocServer32` (COM hijacking)
* **ShellBags** en `UsrClass.dat` (carpetas visitadas)

### Memoria (si se volcó)

```powershell
# Ejemplos Volatility 3
vol.py -f <dump.raw> windows.pslist
vol.py -f <dump.raw> windows.netstat
vol.py -f <dump.raw> windows.malfind --dump
vol.py -f <dump.raw> windows.cmdline
vol.py -f <dump.raw> windows.services
vol.py -f <dump.raw> windows.vadyarascan --yara-rules rules.yar
```

### Integridad

* Recalcular `Get-FileHash -Algorithm SHA256` sobre archivos críticos y comparar con `hashes_sha256.csv`.
* Validar `<HOST>-<UTC>.zip.sha256.txt` tras transferencias.

---

## Notas y solución de problemas

* **Canal ausente (p. ej., Sysmon)** → aparece como `NOTE`, la ejecución continúa.
* **`esentutl` ExitCode `-1032` (archivo en uso)** → el script intenta **VSS** y registra `Copiado desde VSS:`; solo será **ERROR** si también VSS falla.
* **ZIP** → usa .NET `ZipArchive` si está disponible; si no, `Compress-Archive` y, como último recurso, `tar.exe -a`.
* **Locks durante hashing** → el script hace `Stop-Transcript` antes de hashear para evitar bloqueos de `transcript.log`.
* **ACL final** → solo si se pasa `-FinalizeACL`. Sin este parámetro, no se modifican las ACL del caso/ZIP.

---

## Buenas prácticas DFIR

* Ejecutar desde medio **limpio** y guardar en destino **WORM**/solo lectura.
* Registrar **quién/cuándo/dónde** (usando `-Operator` y conservando `collection.log`).
* No montar evidencias en sistemas no controlados; verificar integridad con hashes.
* Documentar cualquier excepción en `errors.log`.

---

## Licencia / Créditos

Michal Emir Reynosa

---
