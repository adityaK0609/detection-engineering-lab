# MSHTA LOLBin Simulation — T1218.005

## Setup (one-time, run on the Windows VM in PowerShell as Administrator)
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

## Required: disable Windows Defender interference before running the test

Windows Defender's Tamper Protection and real-time/behavior monitoring block Atomic Red Team's test scripts by design — Defender correctly identifies the mshta/VBScript/PowerShell chain as suspicious and kills it before it can execute, which means no Event ID 4688 ever gets generated for Wazuh to detect. This has to be turned off first, purely so the simulation can run in this isolated lab; it is not something to do on any machine used for normal work.

**Step 1 — Turn off Tamper Protection (GUI, can't be done via PowerShell while it's on):**

Windows Security → Virus & threat protection → Virus & threat protection settings → Manage settings → Tamper Protection → **Off**

Tamper Protection specifically blocks PowerShell from changing Defender's own settings, which is why this one has to be switched off manually through the GUI before the commands below will actually take effect.

**Step 2 — Confirm current Defender state (PowerShell as Administrator):**
```powershell
Get-MpComputerStatus | Select-Object IsTamperProtected, RealTimeProtectionEnabled, BehaviorMonitorEnabled
```
Confirm `IsTamperProtected` now shows `False` before continuing — if it's still `True`, the GUI toggle above didn't take effect yet.

**Step 3 — Disable real-time and behavior monitoring:**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
```

**Re-enable afterward:** once done testing, reverse both settings (`Set-MpPreference -DisableRealtimeMonitoring $false` and `-DisableBehaviorMonitoring $false`) and turn Tamper Protection back on through the same GUI path. Leaving Defender disabled longer than needed defeats the purpose of having it, even in an isolated lab VM.

## Attack command
```powershell
Invoke-AtomicTest T1218.005 -TestNumbers 2
```

## What this does
Runs a pre-built Atomic Red Team test that launches `mshta.exe` with a VBScript payload. The VBScript calls `Wscript.Shell` to spawn `powershell.exe` — simulating an attacker using a legitimate, signed Windows binary (mshta) to indirectly launch a second process, a common technique to avoid detection tools that only watch for suspicious binaries running directly.

## Actual command line captured in the resulting Event ID 4688
```
mshta  vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -noexit -file C:\AtomicRedTeam\atomics\T1218.005\src\powershell.ps1"":close")
```

## Environment
- Run entirely on: Windows 11 VM (192.168.56.5)
- Requires: internet access temporarily enabled on the VM to download Atomic Red Team, then disabled again to keep the lab isolated during actual testing
- Requires: Windows Defender Tamper Protection, real-time protection, and behavior monitoring temporarily disabled (see above) — without this, Defender blocks the test before it can generate any log event at all

## Expected result
A single Event ID 4688 entry showing `mshta.exe` as the new process, with `cmd.exe` as the parent and the VBScript/PowerShell command line visible — matched by Wazuh rule 100011.
