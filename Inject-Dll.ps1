<#
.SYNOPSIS
  Injector de DLL para Windows usando PowerShell (CreateRemoteThread + LoadLibraryA).

.DESCRIPTION
  Uso educativo/legítimo: inyecta una DLL en un proceso objetivo (PID o nombre).
  Asegúrate de que la DLL y el proceso sean de la misma arquitectura y de tener permisos apropiados.

.EXAMPLE
  .\Inject-Dll.ps1 -Target 1234 -DllPath "C:\path\mi_inject.dll"
  .\Inject-Dll.ps1 -Target "notepad.exe" -DllPath "C:\path\mi_inject.dll"
#>

param(
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][string]$DllPath
)

# ---- Validaciones básicas ----
if (-not (Test-Path $DllPath)) {
    Write-Error "No se encontró la DLL: $DllPath"
    exit 1
}

# C# P/Invoke para las funciones Win32 necesarias
Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class Win32 {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetModuleHandleA(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint LowPart;
        public int HighPart;
    }

    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;
    public const string SE_DEBUG_NAME = "SeDebugPrivilege";
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}
"@ -PassThru | Out-Null

function Enable-DebugPrivilege {
    $procHandle = [Win32]::GetCurrentProcess()
    $tokenHandle = [IntPtr]::Zero
    $ok = [Win32]::OpenProcessToken($procHandle, [Win32]::TOKEN_ADJUST_PRIVILEGES -bor [Win32]::TOKEN_QUERY, [ref]$tokenHandle)
    if (-not $ok) {
        Write-Warning "OpenProcessToken falló: $(Get-LastErrorMessage)"
        return $false
    }
    $luid = New-Object Win32+LUID
    $lookup = [Win32]::LookupPrivilegeValue($null, [Win32]::SE_DEBUG_NAME, [ref]$luid)
    if (-not $lookup) {
        Write-Warning "LookupPrivilegeValue falló: $(Get-LastErrorMessage)"
        return $false
    }
    $tp = New-Object Win32+TOKEN_PRIVILEGES
    $tp.PrivilegeCount = 1
    $tp.Luid = $luid
    $tp.Attributes = [Win32]::SE_PRIVILEGE_ENABLED
    $res = [Win32]::AdjustTokenPrivileges($tokenHandle, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
    if (-not $res) {
        Write-Warning "AdjustTokenPrivileges falló: $(Get-LastErrorMessage)"
        return $false
    }
    return $true
}

function Get-PidByName([string]$name) {
    # si se pasó un número, devolverlo
    if ($name -match '^\d+$') { return [uint32]$name }
    $procs = Get-Process -Name ([System.IO.Path]::GetFileNameWithoutExtension($name)) -ErrorAction SilentlyContinue
    if (-not $procs) { return $null }
    # devolver primer PID encontrado
    return [uint32]$procs[0].Id
}

function Get-LastErrorMessage {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    return "Código $err"
}

# ---- Preparar inyección ----
$pid = Get-PidByName -name $Target
if (-not $pid) {
    Write-Error "No se encontró proceso: $Target"
    exit 1
}

Write-Host "Target PID: $pid"

# Intentar habilitar SeDebugPrivilege (no fatal si falla)
if (Enable-DebugPrivilege) {
    Write-Host "SeDebugPrivilege habilitado (o ya presente)."
} else {
    Write-Warning "No se pudo habilitar SeDebugPrivilege. Si falla la apertura del proceso, ejecuta como Administrador."
}

# Flags de acceso requeridos
$PROCESS_CREATE_THREAD = 0x0002
$PROCESS_QUERY_INFORMATION = 0x0400
$PROCESS_VM_OPERATION = 0x0008
$PROCESS_VM_WRITE = 0x0020
$PROCESS_VM_READ = 0x0010
$desired = $PROCESS_CREATE_THREAD -bor $PROCESS_QUERY_INFORMATION -bor $PROCESS_VM_OPERATION -bor $PROCESS_VM_WRITE -bor $PROCESS_VM_READ

$hProcess = [Win32]::OpenProcess($desired, $false, $pid)
if ($hProcess -eq [IntPtr]::Zero) {
    Write-Error "OpenProcess falló: $(Get-LastErrorMessage)"
    exit 1
}
Write-Host "OpenProcess OK: handle=0x{0:X}" -f $hProcess.ToInt64()

# Reservar memoria en el proceso remoto para la ruta DLL (ASCII)
$pathBytes = [System.Text.Encoding]::ASCII.GetBytes($DllPath + [char]0)
$size = [UIntPtr] $pathBytes.Length
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04

$remoteAddr = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $size, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)
if ($remoteAddr -eq [IntPtr]::Zero) {
    Write-Error "VirtualAllocEx falló: $(Get-LastErrorMessage)"
    [Win32]::CloseHandle($hProcess) | Out-Null
    exit 1
}
Write-Host "VirtualAllocEx OK: remoteAddr=0x{0:X}" -f $remoteAddr.ToInt64()

# Escribir la ruta en memoria remota
$out = [UIntPtr]::Zero
$wrote = [Win32]::WriteProcessMemory($hProcess, $remoteAddr, $pathBytes, $size, [ref]$out)
if (-not $wrote -or $out.ToUInt32() -ne $pathBytes.Length) {
    Write-Error "WriteProcessMemory falló o tamaño escrito distinto: $(Get-LastErrorMessage)"
    [Win32]::VirtualFreeEx($hProcess, $remoteAddr, [UIntPtr]::Zero, 0x8000) | Out-Null # MEM_RELEASE=0x8000
    [Win32]::CloseHandle($hProcess) | Out-Null
    exit 1
}
Write-Host "WriteProcessMemory OK ($($out.ToUInt32()) bytes)"

# Obtener dirección de LoadLibraryA en kernel32.dll (en proceso local — válida para procesos con misma arquitectura)
$hK32 = [Win32]::GetModuleHandleA("kernel32.dll")
if ($hK32 -eq [IntPtr]::Zero) {
    Write-Error "GetModuleHandleA(kernel32.dll) falló"
    [Win32]::VirtualFreeEx($hProcess, $remoteAddr, [UIntPtr]::Zero, 0x8000) | Out-Null
    [Win32]::CloseHandle($hProcess) | Out-Null
    exit 1
}
$addrLoadLib = [Win32]::GetProcAddress($hK32, "LoadLibraryA")
if ($addrLoadLib -eq [IntPtr]::Zero) {
    Write-Error "GetProcAddress(LoadLibraryA) falló"
    [Win32]::VirtualFreeEx($hProcess, $remoteAddr, [UIntPtr]::Zero, 0x8000) | Out-Null
    [Win32]::CloseHandle($hProcess) | Out-Null
    exit 1
}
Write-Host "LoadLibraryA addr: 0x{0:X}" -f $addrLoadLib.ToInt64()

# Crear hilo remoto que llama a LoadLibraryA(remoteAddr)
$threadId = 0
$hThread = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, [UIntPtr]::Zero, $addrLoadLib, $remoteAddr, 0, [ref]$threadId)
if ($hThread -eq [IntPtr]::Zero) {
    Write-Error "CreateRemoteThread falló: $(Get-LastErrorMessage)"
    [Win32]::VirtualFreeEx($hProcess, $remoteAddr, [UIntPtr]::Zero, 0x8000) | Out-Null
    [Win32]::CloseHandle($hProcess) | Out-Null
    exit 1
}
Write-Host "CreateRemoteThread OK: threadHandle=0x{0:X} threadId=$threadId" -f $hThread.ToInt64()

# Esperar a que termine (timeout opcional; aquí infinito)
$INFINITE = 0xFFFFFFFF
[Win32]::WaitForSingleObject($hThread, $INFINITE) | Out-Null

# Obtener código de salida del hilo — será el HMODULE (base) de la DLL cargada en proceso remoto si != 0
[uint32]$exitCode = 0
if (-not [Win32]::GetExitCodeThread($hThread, [ref]$exitCode)) {
    Write-Warning "GetExitCodeThread falló: $(Get-LastErrorMessage)"
} else {
    if ($exitCode -eq 0) {
        Write-Warning "LoadLibraryA en proceso remoto devolvió 0 (falló la carga)"
    } else {
        Write-Host "DLL cargada correctamente. HMODULE remoto (base): 0x{0:X}" -f $exitCode
    }
}

# Limpieza
[Win32]::CloseHandle($hThread) | Out-Null
[Win32]::VirtualFreeEx($hProcess, $remoteAddr, [UIntPtr]::Zero, 0x8000) | Out-Null
[Win32]::CloseHandle($hProcess) | Out-Null

Write-Host "Inyección completada."
