# Collect-Evidence-Ransomware.ps1

Script de **triage forense** orientado a incidentes de **ransomware** en sistemas Windows.

Recolecta los artefactos mínimos pero relevantes para análisis post-incidente (procesos, red, eventos, registro, WMI, tareas programadas, etc.) y opcionalmente un **volcado de memoria RAM**.

> Nota: el script **no realiza hashing** ni pretende cumplir con una cadena de custodia estricta. Está pensado para respuesta rápida y análisis interno.

---

## 1. Alcance y limitaciones

### Qué hace

* Recolecta:

  * Contexto del sistema.
  * Evidencia volátil (procesos, red, sesiones, tareas, drivers).
  * Logs de eventos críticos para ransomware.
  * Artefactos comunes (Prefetch, logs Firewall/IIS, Tasks, Startup).
  * Hives de registro de sistema y usuarios + WMI.
  * Volcado de memoria RAM (opcional, con WinPMEM).
* Empaqueta todo en un **ZIP** y genera un `manifest.json` con metadatos.

### Qué no hace

* No genera hashes (ni de ficheros ni del ZIP).
* No implementa cadena de custodia formal (sellado criptográfico, firmas, etc.).
* No elimina ni modifica artefactos del sistema (salvo la creación de snapshots VSS temporales).

Úsalo como herramienta de recolección rápida cuando necesitas material para investigación, revisión interna o entrenamiento.

---

## 2. Requisitos

* **Windows**:

  * Windows Server 2012 o superior / Windows 8 o superior.
* **PowerShell**:

  * PowerShell **4.0 o superior**.
* **Permisos**:

  * Debe ejecutarse en una consola **elevada** (Run as administrator).
* **Espacio en disco**:

  * Suficiente espacio en `BasePath` para:

    * Logs y artefactos.
    * Volcado de RAM (si se usa `-DumpMemory`, el tamaño ≈ RAM física).
* **WinPMEM (solo si usas `-DumpMemory`)**:

  * Binario de WinPMEM (por ejemplo, `winpmem_mini_x64.exe`).

---

## 3. Uso rápido

### Mostrar ayuda

```powershell
powershell -ExecutionPolicy Bypass -File .\Collect-Evidence-Ransomware.ps1 -Help
```

### Ejecución básica

```powershell
powershell -ExecutionPolicy Bypass `
  -File .\Collect-Evidence-Ransomware.ps1 `
  -BasePath E:\evidence `
  -Operator "SOC"
```

### Con volcado de memoria

```powershell
powershell -ExecutionPolicy Bypass `
  -File .\Collect-Evidence-Ransomware.ps1 `
  -BasePath E:\evidence `
  -Operator "SOC" `
  -DumpMemory `
  -WinpmemPath "E:\tools\winpmem_mini_x64.exe"
```

### Preservando SACL/OWNER y endureciendo ACL final

```powershell
powershell -ExecutionPolicy Bypass `
  -File .\Collect-Evidence-Ransomware.ps1 `
  -BasePath \\srv-dfir\recolecciones `
  -Operator "SOC" `
  -PreserveSecurity `
  -FinalizeACL
```

Parámetros principales:

* `-BasePath` (obligatorio): Ruta donde se creará la carpeta de evidencia y el ZIP.
* `-Operator`: Nombre o identificador del analista.
* `-DumpMemory`: Activa el volcado de RAM.
* `-WinpmemPath`: Ruta del ejecutable de WinPMEM (requerido si `-DumpMemory`).
* `-PreserveSecurity`: Copia con `/COPY:DATSOU` (incluye SACL y owner).
* `-FinalizeACL`: Ajusta permisos finales de la carpeta y el ZIP a solo lectura para Administradores.

---

## 4. Estructura de salida

Para un host `SRV-FILES` ejecutado en `2025-11-12T21:33:58Z`, se crea:

```text
<BasePath>\SRV-FILES-20251112T213358Z\
  collection.log
  errors.log             (si hubo errores)
  manifest.json
  transcript.log
  logs\
  volatile\
  registry\  
  artifacts\
  ...
<BasePath>\SRV-FILES-20251112T213358Z.zip
```

### Archivos destacados

* `collection.log`
  Trazas de lo que hizo el script (útil para triage de errores).

* `errors.log`
  Lista los mensajes de error/advertencia si se produjeron.

* `manifest.json`
  Metadatos de la ejecución: host, hora, RAM, espacio libre, ruta del volcado de memoria, versión del script, etc.

* `transcript.log`
  Transcript de la sesión de PowerShell.

---

## 5. Artefactos recolectados y cómo analizarlos

### 5.1. Carpeta `volatile\`

Ficheros principales:

* `timestamp_utc.txt`
  Marca de tiempo en UTC de la recolección. Útil para alinear con otras evidencias.

* `os.txt`, `system.txt`, `hotfix.txt`, `timezone.txt`
  Información de sistema, hardware, parches y zona horaria.
  Uso:

  * Verificar versión de Windows y nivel de parches.
  * Identificar desfases de hora que afectan la línea de tiempo.

* `tasklist.txt`, `processes.txt`, `services.txt`
  Estado de procesos y servicios en el momento de la recolección.
  Búscalo para:

  * Procesos sospechosos (nombres extraños, rutas inusuales, ejecutables en `%TEMP%`, `%APPDATA%`, etc.).
  * Servicios recién instalados o desconocidos.

* `netstat.txt`, `arp.txt`, `ipconfig.txt`, `route.txt`
  Información de red.
  Búscalo para:

  * Conexiones externas activas durante el incidente.
  * IPs internas que puedan corresponder a máquinas de mando (p. ej. equipos del atacante).
  * Cambios inusuales en tabla ARP o rutas.

* `whoami_all.txt`, `query_user.txt`, `qwinsta.txt`
  Información de seguridad de la cuenta y sesiones interactivas/RDP.
  Útil para:

  * Ver qué usuarios estaban logueados.
  * Confirmar inicio de sesión interactivo o RDP previo al cifrado.

* `schtasks.txt`
  Todas las tareas programadas.
  Revisa:

  * Tareas con nombres ambiguos o recién creadas.
  * Acciones que apunten a ejecutables en rutas de usuario o temporales.

* `drivers.txt`
  Listado de drivers cargados.
  Útil para identificar drivers maliciosos o herramientas de EDR/AV presentes.

Herramientas sugeridas para análisis:

* Visualización manual (Notepad++, VS Code).
* Para correlación automatizada, importar en tu SIEM o en scripts personalizados.

---

### 5.2. Carpeta `logs\`

#### a) `.evtx` individuales (wevtutil)

Ficheros como:

* `Security.evtx`
* `System.evtx`
* `Application.evtx`
* `Microsoft-Windows-Sysmon_Operational.evtx`
* `Microsoft-Windows-PowerShell_Operational.evtx`
* `Microsoft-Windows-TaskScheduler_Operational.evtx`
* `Microsoft-Windows-Windows Defender_Operational.evtx`
* `Microsoft-Windows-WMI-Activity_Operational.evtx`
* `Microsoft-Windows-Bits-Client_Operational.evtx`
* `Microsoft-Windows-AppLocker_EXE and DLL.evtx`
* Logs RDP:

  * `Microsoft-Windows-TerminalServices-LocalSessionManager_Operational.evtx`
  * `Microsoft-Windows-TerminalServices-RemoteConnectionManager_Operational.evtx`
  * `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS_Operational.evtx`

Uso típico:

* **Security**:

  * Eventos de logon (4624/4625), cambios de permisos, uso de cuentas elevadas.
* **Sysmon** (si está desplegado):

  * Creación de procesos, conexiones IP, cambios en el registro.
* **PowerShell**:

  * Scripts y comandos utilizados por el atacante (por ejemplo, `Invoke-WebRequest`, `FromBase64String`, `-enc`).
* **TaskScheduler**:

  * Creación y ejecución de tareas maliciosas.
* **Windows Defender**:

  * Detecciones o bloqueos relacionados con el ransomware.
* **WMI-Activity**:

  * Uso de WMI para movimiento lateral o persistencia.
* **BITS-Client**:

  * Descarga de payloads usando BITS.
* **AppLocker**:

  * Bloqueos de ejecución (si AppLocker está configurado).
* **RDP**:

  * Sesiones RDP exitosas o fallidas (origen IP, hora).

Herramientas típicas:

* Visor de eventos (`eventvwr.msc`).
* EVTX visualizers/analizadores (Chainsaw, Timesketch, etc.).

#### b) Carpeta `logs\winevt\`

Copia completa (o casi completa) de `C:\Windows\System32\winevt\Logs\*.evtx`.

Uso:

* Cuando necesitas una imagen más amplia de eventos (no solo los canales seleccionados).
* Importable en herramientas de análisis más avanzadas.

#### c) Firewall / IIS

* `logs\Firewall\*`
* `logs\IIS\*` (si existe IIS)

Uso:

* Identificar conexiones sospechosas, escaneos internos, tráfico inusual.
* Revisar actividad HTTP previa al cifrado (posibles vectores de explotación).

---

### 5.3. Carpeta `artifacts\`

Contenido principal:

* `artifacts\Prefetch\*`
  Permite ver ejecutables corridos recientemente (incluyendo el binario de ransomware).

  * Analízalo con herramientas tipo WinPrefetchView, PECmd, etc.

* `artifacts\Tasks\*`
  Copia de las tareas programadas como ficheros XML/estructura interna.

  * Útil para confirmar persistencias (ej. tareas que ejecutan `ransom.exe` al logon).

* `artifacts\Startup_Global` y `artifacts\Startup_<Usuario>`
  Archivos en las carpetas de inicio.

  * Ver accesos directos que ejecutan binarios maliciosos.
  * Ver scripts que se disparan al inicio de sesión.

* `artifacts\WMI\*`
  Ficheros de texto con:

  * `EventFilter.txt`
  * `EventConsumer.txt`
  * `FilterToConsumerBinding.txt`

  Uso:

  * Buscar suscripciones WMI persistentes usadas por el atacante (técnicas de persistencia muy comunes).

---

### 5.4. Carpeta `registry\`

#### Hives de sistema

* `SAM.hiv`
* `SYSTEM.hiv`
* `SECURITY.hiv`
* `SOFTWARE.hiv`
* `DEFAULT.hiv`
* `Amcache.hve` (si existe)

Análisis:

* Con herramientas forenses de registro (RegRipper, Registry Explorer, etc.).
* Útil para:

  * Ver servicios instalados.
  * Revisar claves Run/RunOnce.
  * Analizar historial de programas ejecutados (Amcache).
  * Revisar cuentas de usuario, grupos, permisos.

#### Hives de usuario

Estructura:

```text
registry\Users\UsuarioX\
  NTUSER.DAT
  UsrClass.dat
```

Análisis:

* Información de ejecución por usuario (MRUs, shellbags, etc.).
* Rutas de arranque por usuario.
* Claves de persistencia específicas de cada perfil.

---

### 5.5. Volcado de memoria (opcional)

* Archivo `.raw` en la raíz de la carpeta, por ejemplo:

  * `SRV-FILES-20251112T213358Z.raw`

Análisis:

* Cargar en herramientas de memoria (Volatility, Rekall, etc.).
* Utilidad:

  * Identificar procesos del ransomware (aunque ya no estén corriendo).
  * Extraer cadenas, claves de cifrado, credenciales, etc.
  * Ver conexiones de red y módulos cargados al momento del volcado.

---

### 5.6. `manifest.json`

Ejemplo de campos:

* `Host`, `TimeUTC`, `Operator`, `Base`
* `MemoryDump`: nombre del fichero .raw (si se generó).
* `System`:

  * `OSVersion`, `Build`, `Caption`, `TotalRAMGB`, `FreeSpaceGB`
* `Tooling`:

  * `MemoryPath` (winpmem),
  * `Script`, `ScriptVersion`,
  * `WinpmemPresent` (bool).
* `Notes`: texto aclarando que es triage de ransomware sin cadena de custodia estricta.

Útil para:

* Documentar en el reporte:

  * Qué se ejecutó, cuándo y en qué host.
  * Qué versión del script y de WinPMEM se usó.
* Automatizar ingesta en plataformas de análisis (parsear JSON).

---

## 6. Buenas prácticas de uso en incidente de ransomware

1. **Ejecutar lo antes posible**:

   * Idealmente en cuanto se detecta el incidente, antes de apagar el equipo o que el atacante limpie evidencias.

2. **Minimizar cambios en el sistema**:

   * Evitar instalar software nuevo.
   * Ejecutar el script desde un medio ya disponible (p. ej. unidad de red de DFIR, USB preparado).

3. **Almacenar la evidencia en medio seguro**:

   * `BasePath` apuntar a:

     * disco USB dedicado,
     * share DFIR de solo escritura para hosts comprometidos, etc.

4. **Copiar el ZIP resultante a almacenamiento offline**:

   * Una vez generado el `.zip`, copiarlo fuera del entorno afectado (repositorio interno seguro).

5. **No eliminar la carpeta original hasta tener certeza**:

   * Mientras se procesa el ZIP, conservar la carpeta raíz (`<Host>-<Time>`).
   * El script **no borra nada** del sistema de origen.

---

## 7. Solución de problemas

* **Mensaje: “Ejecuta este script en una PowerShell elevada”**

  * Abrir PowerShell como administrador (clic derecho → “Run as administrator”).

* **Canales de eventos inexistentes**

  * Aparecerá como:

    * `NOTE: Canal inexistente o deshabilitado: Microsoft-Windows-Sysmon/Operational`
  * No es error crítico, solo indica que ese log no está habilitado.

* **WinPMEM no encontrado**

  * Si se usa `-DumpMemory` y el binario no está en la ruta:

    * `WARN: WinPMEM no encontrado… RAM omitida.`
  * Verificar `-WinpmemPath`.

* **Espacio insuficiente**

  * Para `-DumpMemory`, el script avisa si detecta poco espacio (≈120% de la RAM).
  * Solución: cambiar `BasePath` a una unidad con más espacio.

* **Errores registrados en `errors.log`**

  * Revisar `errors.log` y `collection.log` para ver qué no se pudo copiar/exportar.
  * Puede ser falta de permisos, canal de eventos deshabilitado, rutas inexistentes, etc.

---

## 8. Resumen

El script `Collect-Evidence-Ransomware.ps1` está pensado como una herramienta de **recolección rápida y estructurada** de artefactos relevantes en incidentes de ransomware, priorizando:

* Contexto del sistema.
* Evidencia volátil.
* Logs de eventos clave.
* Artefactos de ejecución y persistencia.
* Registro de sistema y usuarios.
* WMI y tareas programadas.
* Memoria (opcional).

Sin hashing y sin cadena de custodia formal, orientado a investigación técnica interna, pruebas de laboratorio y mejora de capacidades de respuesta.
