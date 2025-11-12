# Elimina E:\evidence\AORUS-PC-20251112T184947Z y todo su contenido,
# manejando ACL protegidas, rutas largas y reparse points (junctions/symlinks).

$Case = 'E:\evidence\AORUS-PC-20251112T184947Z'

# --- Comprobaciones ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).
            IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) { Write-Error "Ejecuta en PowerShell como Administrador."; exit 1 }
if (-not (Test-Path -LiteralPath $Case)) { Write-Host "[OK] La ruta no existe: $Case"; exit 0 }

# Muévete fuera de la carpeta objetivo por si está abierta en la sesión
Set-Location -Path $env:SystemDrive\

Write-Host "[*] Tomando propiedad y aplicando permisos sobre la carpeta (sin seguir enlaces)..."
cmd /c "takeown /F `"$Case`" /R /D Y" | Out-Null
cmd /c "icacls `"$Case`" /grant:r Administrators:(OI)(CI)F /T /C /L" | Out-Null
cmd /c "icacls `"$Case`" /inheritance:e /T /C /L" | Out-Null

Write-Host "[*] Quitando atributos de solo lectura/sistema/oculto..."
cmd /c "attrib -r -s -h `"$Case`" /S /D" | Out-Null

Write-Host "[*] Eliminando reparse points (junctions/symlinks) dentro de la carpeta..."
Get-ChildItem -LiteralPath $Case -Recurse -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } |
  ForEach-Object {
    $p = $_.FullName
    try { cmd /c "fsutil reparsepoint delete `"$p`"" | Out-Null } catch { }
    try { cmd /c "rmdir /q `"$p`"" | Out-Null } catch { }
    Write-Host "    - ReparsePoint eliminado: $p"
  }

# Borrado final usando prefijo de ruta extendida y fallback a CMD
$Long = if ($Case -match '^[\\]{2}\?\\') { $Case } else { "\\?\$Case" }

Write-Host "[*] Eliminando carpeta (puede tardar)..."
try {
  Remove-Item -LiteralPath $Long -Recurse -Force -ErrorAction Stop
  Write-Host "[OK] Eliminada: $Case"
} catch {
  Write-Warning "Remove-Item falló: $($_.Exception.Message). Reintentando con CMD/rmdir..."
  try {
    cmd /c "rmdir /s /q `"$Case`""
    Write-Host "[OK] Eliminada con rmdir: $Case"
  } catch {
    Write-Error "No se pudo eliminar $Case $($_.Exception.Message)"
    exit 1
  }
}
