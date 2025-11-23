# KovaLabs Windows Tune-Up

KovaLabs Tune-Up is a one-stop PowerShell utility that automates time sync prep, BitLocker decryption, Windows Update, Microsoft Store upgrades, DISM/SFC repairs, and cleanup routines. It is designed for hands-on technicians who need a repeatable service workflow with clear logging and optional automation of post-update reboots/resume.

## Features

- **Interactive menu or `-RunAll`** – pick individual workflows (Windows Update, Store apps, scans, cleanup, etc.) or run the full script unattended.
- **Robust logging** – main console + timestamped log file capture every helper console’s output, including helper windows that reopen for Windows Update, DISM, SFC, winget, and system prep tasks.
- **Time sync + BitLocker prep** – enforces “Set time automatically,” configures NTP peer, optionally forces a preferred time zone (default: Central), and triggers manage-bde decryption if the OS drive is encrypted.
- **Windows Update + Microsoft Store** – drives PSWindowsUpdate and winget from helper consoles, accepting agreements automatically while still showing progress in a dedicated window.
- **DISM, SFC, Cleanup** – reparative scans and cleanup routines (temp/cache folders, Windows.old, CleanMgr sweeps) run as separate helpers so their consoles remain visible.
- **Smart resume after reboot** – when updates require a restart, the script registers a RunOnce entry tied to the original log. After reboot and sign-in, it resumes automatically (skip-able via `-DisablePostUpdateResume` or menu).
- **Advanced settings menu** – toggle auto reboot, time-sync/BitLocker prep, post-update resume, reboot prompts, or change the preferred time-zone at runtime without restarting the script.

## Requirements

- Windows 10/11 with PowerShell 5.1+ (run as administrator).
- Internet access for PSWindowsUpdate and winget installations.
- Script and supporting files cloned or copied locally.

## Usage

```powershell
# Launch from an elevated PowerShell console
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
cd path\to\KLTuneUp
.\KLTuneUp.ps1

# Run all steps silently (logs to desktop or specified directory)
.\KLTuneUp.ps1 -RunAll -Quiet -LogDirectory "C:\Service Logs"
```

### Useful switches

| Switch | Description |
| --- | --- |
| `-RunAll` | Executes every workflow and exits (no menu). |
| `-Quiet` | Suppresses console chatter (log file still captures everything). |
| `-SkipRebootPrompt` | Skips the end-of-run reboot question. |
| `-AutoRestart` | Allows PSWindowsUpdate helper to restart automatically when needed. |
| `-DisableSecurityPrep` | Skips time sync + BitLocker prep. |
| `-PreferredTimeZone "<Time Zone>"` | Overrides the target time zone (default `Central Standard Time`). Use `SYSTEM` via the advanced menu to reset. |
| `-DisablePostUpdateResume` | Prevents RunOnce registration even if a reboot is required. |

### Menu overview

1. Run everything  
2. Windows Update only  
3. Microsoft Store updates only  
4. DISM + SFC scans  
5. Cleanup (component/temp/CleanMgr)  
6. Open log folder  
7. Device decryption only  
8. Advanced settings (toggles/timezone)  
0. Exit

## Logs

- A timestamped log (or an existing `-ResumeLogPath`) captures all entries.
- Each helper writes to its own temp log, which is merged into the main log on completion.
- Logs live on the desktop or in a custom `-LogDirectory`.

## Post-update resume flow

1. Windows Update detects a pending reboot and registers `HKLM\...\RunOnce\KovaLabsTuneUpResume`.
2. After reboot and sign-in, the script relaunches with `-ResumePostUpdate -ResumeLogPath "<existing log>"`.
3. Resume mode skips time sync, BitLocker, Windows Update, and Store updates; it runs DISM, SFC, and cleanup to finish the tune-up.
4. Windows removes the RunOnce value automatically, so nothing lingers after the resume completes.

## Contributing

Pull requests/issues are welcome. Please:

1. Fork/clone the repo.
2. Make changes on a branch.
3. Update tests or documentation if applicable.
4. Submit a PR describing the change.

## License

This project is distributed under the GNU General Public License v3.0. See `LICENSE` for the full text.
