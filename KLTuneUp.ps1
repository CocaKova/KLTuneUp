<#
.SYNOPSIS
    KovaLabs modern Windows tune-up utility that bundles Windows Update, Microsoft Store updates,
    DISM/SFC repairs, and component/temporary file cleanup into a single experience.

.DESCRIPTION
    Run the KovaLabs tune-up from an elevated PowerShell prompt or pass -RunAll to execute every task
    in sequence. By default an interactive menu is shown so you can pick only the workflows
    you need. A timestamped log is generated in the Logs folder alongside the script.

.EXAMPLE
    .\\ModernTuneUp.ps1 -RunAll -Quiet
    Runs all tune-up actions without prompting and writes progress only to the log file.
#>
[CmdletBinding()]
param(
    [switch]$RunAll,
    [switch]$Quiet,
    [switch]$SkipRebootPrompt,
    [switch]$AutoRestart,
    [string]$LogDirectory = '',
    [switch]$LaunchedFromScript
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ProductName = 'KovaLabs Windows Tune-Up'
$script:AutoRestartPreference = [bool]$AutoRestart

if (-not $LogDirectory) {
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    if ($desktopPath -and (Test-Path -LiteralPath $desktopPath)) {
        $LogDirectory = $desktopPath
    } else {
        $logRoot = if ($PSScriptRoot) {
            $PSScriptRoot
        } elseif ($PSCommandPath) {
            Split-Path -Path $PSCommandPath -Parent
        } else {
            (Get-Location).Path
        }
        $LogDirectory = Join-Path -Path $logRoot -ChildPath 'Logs'
    }
}

function Test-IsAdministrator {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Administrator {
    $needsConsole = $Host.Name -ne 'ConsoleHost'
    $needsAdmin = -not (Test-IsAdministrator)
    if (-not $needsConsole -and -not $needsAdmin) {
        return
    }

    if (-not $PSCommandPath) {
        throw 'An interactive, elevated PowerShell console is required to run this script.'
    }

    $arguments = "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($RunAll) { $arguments += ' -RunAll' }
    if ($Quiet) { $arguments += ' -Quiet' }
    if ($SkipRebootPrompt) { $arguments += ' -SkipRebootPrompt' }
    if ($AutoRestart) { $arguments += ' -AutoRestart' }
    $arguments += ' -LaunchedFromScript'

    $message = if ($needsAdmin) {
        'Administrative privileges are required, noob. Relaunching in an elevated console...'
    } else {
        'A standard PowerShell console window is required. Relaunching...'
    }
    Write-Host $message -ForegroundColor Yellow

    $startInfo = @{
        FilePath = 'powershell.exe'
        ArgumentList = $arguments
    }
    if ($needsAdmin) {
        $startInfo.Verb = 'RunAs'
    }

    try {
        Start-Process @startInfo
    } catch {
        Write-Host "Failed to relaunch $script:ProductName: $($_.Exception.Message)" -ForegroundColor Red
        if (-not $Quiet) {
            [void](Read-Host 'Press Enter to close this window.')
        }
        exit 1
    }
    exit
}

function Initialize-Log {
    if (-not (Test-Path -Path $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $log = Join-Path -Path $LogDirectory -ChildPath "TuneUp_$timestamp.log"
    New-Item -Path $log -ItemType File -Force | Out-Null
    return $log
}

$script:LogPath = Initialize-Log

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $levelTag = ("[{0}]" -f $Level).PadRight(8)
    $entry = "$timestamp $levelTag $Message"
    Add-Content -Path ${script:LogPath} -Value $entry
    if (-not $Quiet -or $Level -ne 'INFO') {
        switch ($Level) {
            'INFO' { $color = 'Gray' }
            'WARN' { $color = 'Yellow' }
            'ERROR' { $color = 'Red' }
        }
        Write-Host $entry -ForegroundColor $color
    }
}

function Format-ByteValue {
    param([double]$Bytes)

    if ($Bytes -le 0) { return '0 B' }
    $units = @('B','KB','MB','GB','TB','PB')
    $value = [double]$Bytes
    $index = 0
    while ($value -ge 1024 -and $index -lt ($units.Count - 1)) {
        $value /= 1024
        $index++
    }
    return '{0:N2} {1}' -f $value, $units[$index]
}

function Get-PathSizeBytes {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return 0
    }

    try {
        $items = Get-ChildItem -LiteralPath $Path -Force -Recurse -File -ErrorAction SilentlyContinue
        $size = ($items | Measure-Object -Property Length -Sum).Sum
        return [double]($size)
    } catch {
        Write-Log "Unable to measure size of ${Path}: $($_.Exception.Message)" -Level WARN
        return 0
    }
}

function Invoke-PathCleanup {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description,
        [scriptblock]$CleanupAction
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log "$Description skipped (${Path} not found)."
        return 0
    }

    $sizeBefore = Get-PathSizeBytes -Path $Path
    Write-Log "Cleaning $Description at ${Path} (approx. $(Format-ByteValue -Bytes $sizeBefore))."

    try {
        if ($CleanupAction) {
            & $CleanupAction -Path $Path
        } else {
            Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Log "Failed to clean $Description (${Path}): $($_.Exception.Message)" -Level WARN
        return 0
    }

    $remaining = if (Test-Path -LiteralPath $Path) { Get-PathSizeBytes -Path $Path } else { 0 }
    $freed = [math]::Max($sizeBefore - $remaining, 0)
    Write-Log "$Description cleanup freed $(Format-ByteValue -Bytes $freed)."
    return $freed
}

function Invoke-RecycleBinCleanup {
    $recyclePath = Join-Path -Path $env:SystemDrive -ChildPath '$Recycle.Bin'
    if (-not (Test-Path -LiteralPath $recyclePath)) {
        Write-Log 'Recycle Bin path not found; skipping.'
        return 0
    }

    $sizeBefore = Get-PathSizeBytes -Path $recyclePath
    if ($sizeBefore -le 0) {
        Write-Log 'Recycle Bin already empty.'
        return 0
    }

    Write-Log "Emptying Recycle Bin (approx. $(Format-ByteValue -Bytes $sizeBefore))."
    try {
        Clear-RecycleBin -Force -ErrorAction Stop
    } catch {
        Write-Log "Failed to empty Recycle Bin: $($_.Exception.Message)" -Level WARN
        return 0
    }

    Write-Log "Recycle Bin emptied; freed $(Format-ByteValue -Bytes $sizeBefore)."
    return $sizeBefore
}

function Get-DismResultSummary {
    param([string[]]$Lines)

    if (-not $Lines -or $Lines.Count -eq 0) {
        return 'DISM completed. Review log for additional information.'
    }

    if ($Lines | Where-Object { $_ -match 'No component store corruption detected' }) {
        return 'DISM: No component store corruption detected.'
    }
    if ($Lines | Where-Object { $_ -match 'The restore operation completed successfully' }) {
        if ($Lines | Where-Object { $_ -match 'The component store corruption was repaired' }) {
            return 'DISM repaired component store corruption.'
        }
        return 'DISM restore operation completed successfully.'
    }
    if ($Lines | Where-Object { $_ -match 'The component store cannot be repaired' }) {
        return 'DISM: Component store corruption could not be repaired. Additional remediation is required.'
    }
    return 'DISM completed. Review log for additional information.'
}

function Get-SfcResultSummary {
    param([string[]]$Lines)

    if (-not $Lines -or $Lines.Count -eq 0) {
        return 'SFC completed. Review log for additional information.'
    }

    if ($Lines | Where-Object { $_ -match 'did not find any integrity violations' }) {
        return 'SFC: No integrity violations detected.'
    }
    if ($Lines | Where-Object { $_ -match 'found corrupt files and successfully repaired them' }) {
        return 'SFC repaired system file corruption.'
    }
    if ($Lines | Where-Object { $_ -match 'found corrupt files but was unable to fix some' }) {
        return 'SFC detected corruption but could not repair some files.'
    }
    return 'SFC completed. Review log for additional information.'
}

function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments,
        [string]$Activity = 'Running command',
        [switch]$CaptureOutput
    )

    Test-Cancellation
    $argDisplay = if ($Arguments) { $Arguments -join ' ' } else { '' }
    Write-Log "${Activity}: $FilePath $argDisplay"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    if ($Arguments) { $psi.Arguments = ($Arguments -join ' ') }
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $script:CurrentExternalProcess = $process

    $outputQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[System.String]'
    $errorQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[System.String]'
    $stdOutBuffer = if ($CaptureOutput) { [System.Collections.Generic.List[string]]::new() } else { $null }
    $stdErrBuffer = if ($CaptureOutput) { [System.Collections.Generic.List[string]]::new() } else { $null }
    $stdOutHandler = [System.Diagnostics.DataReceivedEventHandler]{ param($sender,$eventArgs) if ($eventArgs.Data) { $null = $outputQueue.Enqueue($eventArgs.Data) } }
    $stdErrHandler = [System.Diagnostics.DataReceivedEventHandler]{ param($sender,$eventArgs) if ($eventArgs.Data) { $null = $errorQueue.Enqueue($eventArgs.Data) } }
    try {
        $null = $process.add_OutputDataReceived($stdOutHandler)
        $null = $process.add_ErrorDataReceived($stdErrHandler)

        $null = $process.Start()
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()

        while (-not $process.HasExited -or -not $outputQueue.IsEmpty -or -not $errorQueue.IsEmpty) {
            Test-Cancellation
            $line = $null
            while ($outputQueue.TryDequeue([ref]$line)) {
                if ($null -ne $line -and $line.Length -gt 0) {
                    Write-Log $line
                    if ($CaptureOutput -and $stdOutBuffer) { $null = $stdOutBuffer.Add($line) }
                }
                $line = $null
            }
            $line = $null
            while ($errorQueue.TryDequeue([ref]$line)) {
                if ($null -ne $line -and $line.Length -gt 0) {
                    Write-Log $line -Level WARN
                    if ($CaptureOutput -and $stdErrBuffer) { $null = $stdErrBuffer.Add($line) }
                }
                $line = $null
            }

            if (-not $process.HasExited) {
                Start-Sleep -Milliseconds 100
            }
        }
    } finally {
        try {
            $process.CancelOutputRead()
            $process.CancelErrorRead()
        } catch {
            # ignore cleanup errors
        }
        try {
            $process.remove_OutputDataReceived($stdOutHandler)
            $process.remove_ErrorDataReceived($stdErrHandler)
        } catch {
            # ignore cleanup errors
        }
        $script:CurrentExternalProcess = $null
    }

    if ($process.ExitCode -ne 0) {
        Write-Log "$Activity failed with exit code $($process.ExitCode)" -Level ERROR
        throw "$Activity failed. See log at ${script:LogPath}"
    }

    Test-Cancellation
    if ($CaptureOutput) {
        return [PSCustomObject]@{
            ExitCode = $process.ExitCode
            StdOut = if ($stdOutBuffer) { $stdOutBuffer.ToArray() } else { @() }
            StdErr = if ($stdErrBuffer) { $stdErrBuffer.ToArray() } else { @() }
        }
    }
}

$script:CancellationRequested = $false
$script:OperationCancelled = $false
$script:ConsoleBreakRegistration = $null
$script:CurrentExternalProcess = $null

function Initialize-CancellationHandling {
    if ($script:ConsoleBreakRegistration) { return }

    $script:ConsoleBreakRegistration = Register-EngineEvent -SourceIdentifier ConsoleBreak -SupportEvent -Action {
        $eventArgs = $event.SourceEventArgs
        if ($eventArgs) { $eventArgs.Cancel = $true }
        if (-not $script:CancellationRequested) {
            $script:CancellationRequested = $true
            Write-Log 'Ctrl+C detected. Attempting to cancel running operations...Buzzkill...' -Level WARN
        }

        if ($script:CurrentExternalProcess -and -not $script:CurrentExternalProcess.HasExited) {
            try {
                $script:CurrentExternalProcess.Kill()
                Write-Log 'Active external command terminated due to cancellation.' -Level WARN
            } catch {
                Write-Log "Unable to terminate running command: $($_.Exception.Message)" -Level WARN
            }
        }
    }
}

function Unregister-CancellationHandling {
    if (-not $script:ConsoleBreakRegistration) { return }

    try {
        Unregister-Event -SubscriptionId $script:ConsoleBreakRegistration.Id -ErrorAction SilentlyContinue
        Remove-Job -Id $script:ConsoleBreakRegistration.Id -Force -ErrorAction SilentlyContinue
    } catch {
        # Best-effort cleanup only.
    }

    $script:ConsoleBreakRegistration = $null
}

function Test-Cancellation {
    if ($script:CancellationRequested) {
        throw [System.OperationCanceledException]::new('Operation cancelled by user (Ctrl+C). Unsure why...')
    }
}

function Ensure-PSWindowsUpdateModule {
    Write-Log 'Ensuring PSWindowsUpdate module is available.'
    try {
        try {
            Get-PackageProvider -Name NuGet -ForceBootstrap -ErrorAction Stop | Out-Null
        } catch {
            Write-Log "NuGet provider bootstrap failed or is unavailable: $($_.Exception.Message)" -Level WARN
        }

        $module = Get-Module -ListAvailable -Name 'PSWindowsUpdate' | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $module) {
            Write-Log 'PSWindowsUpdate module not found. Installing from PSGallery.'
            Install-Module -Name 'PSWindowsUpdate' -Force -Confirm:$false -Scope AllUsers -ErrorAction Stop | Out-Null
            Write-Log 'PSWindowsUpdate module installed successfully.'
        } else {
            Write-Log "PSWindowsUpdate module already installed (Version $($module.Version))."
        }

        Import-Module -Name 'PSWindowsUpdate' -Force -ErrorAction Stop | Out-Null
        Write-Log 'PSWindowsUpdate module imported.'
    } catch {
        Write-Log "Unable to prepare PSWindowsUpdate module: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

function Invoke-WindowsUpdate {
    Write-Log '----- Windows Update Workflow (PSWindowsUpdate) -----'
    Ensure-PSWindowsUpdateModule

    try {
        Write-Log 'Scanning for updates via PSWindowsUpdate.'
        $availableUpdates = Get-WindowsUpdate -ErrorAction Stop
        if (-not $availableUpdates) {
            Write-Log 'No applicable Windows Updates were detected.'
            return
        }

        foreach ($update in $availableUpdates) {
            $kbList = if ($update.KBArticleIDs) { $update.KBArticleIDs -join ', ' } elseif ($update.KB) { $update.KB } else { 'N/A' }
            Write-Log "Detected update: $($update.Title) (KB: $kbList)"
        }

        $installArgs = @('-AcceptAll','-Install')
        if ($script:AutoRestartPreference) {
            Write-Log 'Installing updates via PSWindowsUpdate with automatic reboot enabled.'
            $installArgs += '-AutoReboot'
        } else {
            Write-Log 'Installing updates via PSWindowsUpdate (manual reboot required).'
        }

        $installResults = Get-WindowsUpdate @installArgs -ErrorAction Stop
        if ($installResults) {
            foreach ($result in $installResults) {
                $kbList = if ($result.KBArticleIDs) { $result.KBArticleIDs -join ', ' } elseif ($result.KB) { $result.KB } else { 'N/A' }
                $status = if ($result.Result) { $result.Result } else { 'Completed' }
                Write-Log "Installation result: $($result.Title) (KB: $kbList) => $status"
            }
        } else {
            Write-Log 'PSWindowsUpdate did not return per-update installation details.'
        }
    } catch {
        Write-Log "PSWindowsUpdate workflow failed: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

function Invoke-MicrosoftStoreUpdate {
    Write-Log '----- Microsoft Store Updates -----'
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($null -eq $winget) {
        Write-Log 'winget is not available. Triggering Store UI for manual updates.' -Level WARN
        Start-Process 'explorer.exe' 'ms-windows-store://downloadsandupdates'
        return
    }

    Invoke-ExternalCommand -FilePath $winget.Source -Arguments @('upgrade','--all','--accept-package-agreements','--accept-source-agreements') -Activity 'Updating applications via winget'
    Write-Log 'Microsoft Store (and winget) update sweep completed.'
}

function Invoke-DismRestoreHealth {
    Write-Log '----- DISM RestoreHealth -----'
    $result = Invoke-ExternalCommand -FilePath 'dism.exe' -Arguments @('/Online','/Cleanup-Image','/RestoreHealth') -Activity 'Running DISM RestoreHealth' -CaptureOutput
    $summary = Get-DismResultSummary -Lines $result.StdOut
    Write-Log $summary
}

function Invoke-SfcScan {
    Write-Log '----- SFC /SCANNOW -----'
    $result = Invoke-ExternalCommand -FilePath 'sfc.exe' -Arguments '/scannow' -Activity 'Running System File Checker' -CaptureOutput
    $summary = Get-SfcResultSummary -Lines $result.StdOut
    Write-Log $summary
}

function Invoke-SystemCleanup {
    Write-Log '----- System Cleanup -----'
    Invoke-ExternalCommand -FilePath 'dism.exe' -Arguments @('/Online','/Cleanup-Image','/StartComponentCleanup') -Activity 'Component cleanup'

    $targets = @(
        @{ Path = "$env:windir\SoftwareDistribution\Download"; Description = 'Windows Update download cache' },
        @{ Path = "$env:windir\Temp"; Description = 'Windows Temp directory' },
        @{ Path = "$env:TEMP"; Description = 'System TEMP directory' },
        @{
            Path = "$env:SystemDrive\Windows.old"
            Description = 'Previous Windows installation'
            CleanupAction = { param($Path) Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue }
        },
        @{
            Path = (Join-Path -Path $env:SystemDrive -ChildPath '$WINDOWS.~BT')
            Description = 'Windows setup files ($WINDOWS.~BT)'
            CleanupAction = { param($Path) Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue }
        },
        @{
            Path = (Join-Path -Path $env:SystemDrive -ChildPath '$WINDOWS.~WS')
            Description = 'Windows setup files ($WINDOWS.~WS)'
            CleanupAction = { param($Path) Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue }
        }
    )

    $totalFreed = 0
    foreach ($target in $targets) {
        $cleanupAction = if ($target.ContainsKey('CleanupAction')) { $target['CleanupAction'] } else { $null }
        $totalFreed += Invoke-PathCleanup -Path $target['Path'] -Description $target['Description'] -CleanupAction $cleanupAction
    }

    $totalFreed += Invoke-RecycleBinCleanup
    Write-Log ("Manual cleanup freed approximately {0}." -f (Format-ByteValue -Bytes $totalFreed))

    Invoke-ExternalCommand -FilePath 'cleanmgr.exe' -Arguments @('/AUTOCLEAN') -Activity 'Running CleanMgr (AutoClean)'
    Invoke-ExternalCommand -FilePath 'cleanmgr.exe' -Arguments @('/VERYLOWDISK') -Activity 'Running CleanMgr (VeryLowDisk)'
    Write-Log 'Disk cleanup completed (CleanMgr).' 
}

function Invoke-TimeSynchronization {
    Write-Log '----- Time Synchronization -----'
    try {
        $timeService = Get-Service -Name 'W32Time' -ErrorAction Stop
        if ($timeService.Status -ne 'Running') {
            Write-Log 'Starting Windows Time (W32Time) service.'
            Start-Service -Name 'W32Time' -ErrorAction Stop
        }
    } catch {
        Write-Log "Unable to verify or start the Windows Time service: $($_.Exception.Message)" -Level WARN
    }

    try {
        Invoke-ExternalCommand -FilePath 'w32tm.exe' -Arguments @('/resync','/force') -Activity 'Synchronizing system time'
        Write-Log 'System time synchronized with configured time source.'
    } catch {
        Write-Log "Time synchronization failed: $($_.Exception.Message)" -Level WARN
    }
}

function Invoke-DeviceDecryption {
    Write-Log '----- Device Decryption -----'
    $bitLockerCommands = @(Get-Command -Name 'Get-BitLockerVolume','Disable-BitLocker' -ErrorAction SilentlyContinue)
    if ($bitLockerCommands.Count -lt 2) {
        Write-Log 'BitLocker cmdlets are not available on this system. Skipping device decryption.' -Level WARN
        return
    }

    try {
        $osVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    } catch {
        Write-Log "Unable to query BitLocker status: $($_.Exception.Message)" -Level WARN
        return
    }

    if (-not $osVolume) {
        Write-Log 'No BitLocker volume information returned for the system drive.' -Level WARN
        return
    }

    $protectionStatus = "$($osVolume.ProtectionStatus)"
    $volumeStatus = "$($osVolume.VolumeStatus)"
    if ($protectionStatus -eq 'Off' -or $volumeStatus -eq 'FullyDecrypted') {
        Write-Log 'System drive is already decrypted.'
        return
    }
    if ($volumeStatus -eq 'DecryptionInProgress') {
        Write-Log 'System drive decryption is already in progress.'
        return
    }

    try {
        Disable-BitLocker -MountPoint $env:SystemDrive -ErrorAction Stop | Out-Null
        Write-Log 'BitLocker has been disabled; full volume decryption has begun.'
    } catch {
        Write-Log "Failed to disable BitLocker and start decryption: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

function Invoke-TuneUp {
    param(
        [switch]$IncludeTimeSync = $true,
        [switch]$IncludeDeviceDecryption = $true,
        [switch]$IncludeWindowsUpdate = $true,
        [switch]$IncludeStore = $true,
        [switch]$IncludeScans = $true,
        [switch]$IncludeCleanup = $true
    )

    if ($IncludeTimeSync) {
        Test-Cancellation
        Invoke-TimeSynchronization
    }
    if ($IncludeDeviceDecryption) {
        Test-Cancellation
        Invoke-DeviceDecryption
    }
    if ($IncludeWindowsUpdate) {
        Test-Cancellation
        Invoke-WindowsUpdate
    }
    if ($IncludeStore) {
        Test-Cancellation
        Invoke-MicrosoftStoreUpdate
    }
    if ($IncludeScans) {
        Test-Cancellation
        Invoke-DismRestoreHealth
        Test-Cancellation
        Invoke-SfcScan
    }
    if ($IncludeCleanup) {
        Test-Cancellation
        Invoke-SystemCleanup
    }
}

function Toggle-AutoRestartPreference {
    $script:AutoRestartPreference = -not $script:AutoRestartPreference
    $status = if ($script:AutoRestartPreference) { 'enabled' } else { 'disabled' }
    Write-Log "Automatic Windows Update reboot $status via menu selection."
    Write-Host "Automatic Windows Update reboot is now $status." -ForegroundColor Yellow
}

function Show-Menu {
    Write-Host ''
    Write-Host "======== $script:ProductName ========" -ForegroundColor Cyan
    Write-Host '1) Run everything'
    Write-Host '2) Windows Update only'
    Write-Host '3) Microsoft Store updates only'
    Write-Host '4) System scan (DISM + SFC)'
    Write-Host '5) Cleanup (component + temp + CleanMgr)'
    Write-Host '6) Open log folder'
    Write-Host '7) Device decryption only'
    $autoRebootState = if ($script:AutoRestartPreference) { 'ON' } else { 'OFF' }
    Write-Host "8) Toggle automatic Windows Update reboot (Currently: $autoRebootState)"
    Write-Host '0) Exit'
    Write-Host '========================================'
    return Read-Host 'Choose an option'
}

function Open-LogFolder {
    Invoke-Item -Path $LogDirectory
}

Ensure-Administrator
Initialize-CancellationHandling

$script:TuneUpCompleted = $false
$script:FatalError = $false
$script:WorkPerformed = $false

try {
    Write-Log "Starting $script:ProductName sequence."

    if ($RunAll) {
        Test-Cancellation
        Invoke-TuneUp
        $script:WorkPerformed = $true
    } else {
        $stayInMenu = $true
        while ($stayInMenu) {
            $selection = Show-Menu
            Test-Cancellation
            $handled = $true
            switch ($selection) {
                '1' {
                    Invoke-TuneUp
                    $script:WorkPerformed = $true
                }
                '2' {
                    Invoke-TuneUp -IncludeStore:$false -IncludeScans:$false -IncludeCleanup:$false
                    $script:WorkPerformed = $true
                }
                '3' {
                    Invoke-TuneUp -IncludeWindowsUpdate:$false -IncludeScans:$false -IncludeCleanup:$false
                    $script:WorkPerformed = $true
                }
                '4' {
                    Invoke-TuneUp -IncludeWindowsUpdate:$false -IncludeStore:$false -IncludeCleanup:$false
                    $script:WorkPerformed = $true
                }
                '5' {
                    Invoke-TuneUp -IncludeWindowsUpdate:$false -IncludeStore:$false -IncludeScans:$false
                    $script:WorkPerformed = $true
                }
                '6' {
                    Open-LogFolder
                    $handled = $false
                }
                '7' {
                    Invoke-TuneUp -IncludeTimeSync:$false -IncludeDeviceDecryption:$true -IncludeWindowsUpdate:$false -IncludeStore:$false -IncludeScans:$false -IncludeCleanup:$false
                    $script:WorkPerformed = $true
                }
                '8' {
                    Toggle-AutoRestartPreference
                    $handled = $false
                }
                '0' {
                    $stayInMenu = $false
                    continue
                }
                default {
                    Write-Host 'Invalid selection. Please choose again.' -ForegroundColor Yellow
                    $handled = $false
                }
            }

            if ($handled -and $stayInMenu) {
                Write-Host ''
                Write-Host 'Returning to main menu...' -ForegroundColor DarkGray
            }
        }
    }

    if ($script:WorkPerformed) {
        $script:TuneUpCompleted = $true
    }
    Write-Log "$script:ProductName complete."
}
catch {
    if ($_.Exception -is [System.OperationCanceledException]) {
        $script:OperationCancelled = $true
        Write-Log $_.Exception.Message -Level WARN
    } else {
        $script:FatalError = $true
        Write-Log "Fatal error: $($_.Exception.Message)" -Level ERROR
        if ($_.ScriptStackTrace) {
            Write-Log $_.ScriptStackTrace -Level ERROR
        }
    }
}
finally {
    Unregister-CancellationHandling

    $alreadyPrompted = $false
    if ($script:OperationCancelled) {
        Write-Host ''
        Write-Host "$script:ProductName cancelled by user via Ctrl+C." -ForegroundColor Yellow
    } elseif ($script:TuneUpCompleted -and -not $SkipRebootPrompt) {
        $response = Read-Host 'Would you like to reboot now? (Y/N)'
        $alreadyPrompted = $true
        if ($response -match '^(Y|y)') {
            Restart-Computer -Force
        }
    } elseif ($script:FatalError -and -not $Quiet) {
        Write-Host ''
        Write-Host "$script:ProductName encountered a problem. Review the log, then press Enter to close this window." -ForegroundColor Red
        [void](Read-Host)
        $alreadyPrompted = $true
    }

    Write-Host "Log saved to ${script:LogPath}"
    if ($LaunchedFromScript -and -not $Quiet -and -not $alreadyPrompted) {
        [void](Read-Host 'Press Enter to close this window.')
    }
}

if ($script:FatalError) {
    exit 1
}
