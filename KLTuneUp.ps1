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
    [switch]$LaunchedFromScript,
    [switch]$DisableSecurityPrep,
    [string]$PreferredTimeZone = 'Central Standard Time',
    [switch]$ResumePostUpdate,
    [switch]$DisablePostUpdateResume,
    [string]$ResumeLogPath = ''
)

Set-StrictMode -Version Latest
$script:StrictModeVersion = 'Latest'
$ErrorActionPreference = 'Stop'
$script:ProductName = 'KovaLabs Windows Tune-Up'
$script:AutoRestartPreference = [bool]$AutoRestart
$script:SecurityPrepEnabled = -not [bool]$DisableSecurityPrep
$script:PreferredTimeZone = $PreferredTimeZone
$script:IsPostUpdateResume = [bool]$ResumePostUpdate
$script:DisablePostUpdateResume = [bool]$DisablePostUpdateResume
$script:PostUpdateResumeScheduled = $false
$script:WindowsUpdateRebootRequired = $false
$script:ResumeLogPath = $ResumeLogPath
$script:SkipRebootPromptPreference = [bool]$SkipRebootPrompt

if ($ResumePostUpdate -and $DisablePostUpdateResume) {
    throw '-ResumePostUpdate cannot be combined with -DisablePostUpdateResume.'
}

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
    if ($DisableSecurityPrep) { $arguments += ' -DisableSecurityPrep' }
    if ($PreferredTimeZone) { $arguments += " -PreferredTimeZone `"$PreferredTimeZone`"" }
    if ($ResumePostUpdate) { $arguments += ' -ResumePostUpdate' }
    if ($DisablePostUpdateResume) { $arguments += ' -DisablePostUpdateResume' }
    if ($ResumeLogPath) { $arguments += " -ResumeLogPath `"$ResumeLogPath`"" }
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
    if ($script:ResumeLogPath) {
        if (Test-Path -LiteralPath $script:ResumeLogPath) {
            return $script:ResumeLogPath
        } else {
            Write-Host ("Requested resume log path '{0}' was not found. Creating a fresh log." -f $script:ResumeLogPath) -ForegroundColor Yellow
        }
    }

    if (-not (Test-Path -Path $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $log = Join-Path -Path $LogDirectory -ChildPath "TuneUp_$timestamp.log"
    try {
        # Create the log immediately so launches never exit due to path errors.
        if (-not (Test-Path -LiteralPath $log)) {
            New-Item -Path $log -ItemType File -Force | Out-Null
        }
    } catch {
        Write-Host ("Failed to initialize log file at {0}: {1}" -f $log, $_.Exception.Message) -ForegroundColor Red
        throw
    }
    return $log
}

$script:LogPath = Initialize-Log
$script:LogLock = New-Object System.Object

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

    if (-not $script:LogLock) {
        $script:LogLock = New-Object System.Object
    }

    [System.Threading.Monitor]::Enter($script:LogLock)
    try {
        Add-Content -Path ${script:LogPath} -Value $entry
        if (-not $Quiet -or $Level -ne 'INFO') {
            switch ($Level) {
                'INFO' { $color = 'Gray' }
                'WARN' { $color = 'Yellow' }
                'ERROR' { $color = 'Red' }
            }
            Write-Host $entry -ForegroundColor $color
        }
    } finally {
        [System.Threading.Monitor]::Exit($script:LogLock)
    }
}

function Write-ExceptionDetail {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$Context = ''
    )

    if (-not $ErrorRecord) { return }
    $detailLines = ($ErrorRecord | Format-List * | Out-String) -split "`r?`n"
    $detailLines = $detailLines | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if (-not $detailLines) { return }
    $prefix = if ($Context) { "$Context detail" } else { 'Detail' }
    foreach ($line in $detailLines) {
        Write-Log ("{0}: {1}" -f $prefix, $line) -Level ERROR
    }
}

function Write-LogLinesFromHelper {
    param([string[]]$Lines)

    if (-not $Lines -or $Lines.Count -eq 0) { return }
    if (-not $script:LogLock) {
        $script:LogLock = New-Object System.Object
    }

    [System.Threading.Monitor]::Enter($script:LogLock)
    try {
        Add-Content -Path $script:LogPath -Value $Lines
    } finally {
        [System.Threading.Monitor]::Exit($script:LogLock)
    }

    if ($Quiet) { return }

    foreach ($line in $Lines) {
        if (-not $line) { continue }
        $match = [regex]::Match($line,'\[(INFO|WARN|ERROR)\]')
        $color = 'Gray'
        if ($match.Success) {
            switch ($match.Groups[1].Value) {
                'INFO' { $color = 'Gray' }
                'WARN' { $color = 'Yellow' }
                'ERROR' { $color = 'Red' }
            }
        }
        Write-Host $line -ForegroundColor $color
    }
}

function Invoke-HelperConsole {
    param(
        [Parameter(Mandatory)][string]$ScriptTemplate,
        [Parameter(Mandatory)][string]$Activity,
        [hashtable]$Replacements
    )

    $helperLogPath = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ("KLTuneUp_{0}.log" -f ([guid]::NewGuid()))
    $scriptBody = $ScriptTemplate.Replace('__HELPER_LOG__',$helperLogPath.Replace('"','""'))
    if ($Replacements) {
        foreach ($key in $Replacements.Keys) {
            $value = $Replacements[$key]
            if ($null -eq $value) { $value = '' }
            $scriptBody = $scriptBody.Replace($key, $value)
        }
    }

    $encodedScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($scriptBody))
    $argumentList = @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encodedScript)
    Write-Log "Launching $Activity helper console (ExecutionPolicy Bypass)."
    try {
        $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $argumentList -WindowStyle Normal -Wait -PassThru -ErrorAction Stop
        Write-Log "$Activity helper console exited with code $($process.ExitCode)."
        if ($process.ExitCode -ne 0) {
            Write-Log "$Activity helper reported a non-zero exit code. Review the helper window output for details." -Level WARN
        }
    } catch {
        Write-Log ("Failed to launch $Activity helper console: {0}" -f $_.Exception.Message) -Level ERROR
        return
    }
    if (Test-Path -LiteralPath $helperLogPath) {
        try {
            $helperLines = Get-Content -Path $helperLogPath -ErrorAction Stop
            Write-LogLinesFromHelper $helperLines
        } catch {
        Write-Log ("Failed to read helper log for ${Activity}: {0}" -f $_.Exception.Message) -Level WARN
        } finally {
            Remove-Item -LiteralPath $helperLogPath -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Log "$Activity helper log was not generated." -Level WARN
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

function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments,
        [string]$Activity = 'Running command',
        [switch]$CaptureOutput,
        [int]$HeartbeatSeconds = 30
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
    $startTime = Get-Date
    try {
        $null = $process.add_OutputDataReceived($stdOutHandler)
        $null = $process.add_ErrorDataReceived($stdErrHandler)

        $null = $process.Start()
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()

        $heartbeatInterval = if ($HeartbeatSeconds -gt 0) { [TimeSpan]::FromSeconds($HeartbeatSeconds) } else { $null }
        $lastHeartbeat = Get-Date

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
                if ($heartbeatInterval -and ((Get-Date) - $lastHeartbeat) -ge $heartbeatInterval) {
                    $elapsed = (Get-Date) - $startTime
                    $elapsedText = ('{0:hh\:mm\:ss}' -f $elapsed)
                    Write-Log "$Activity is still running (elapsed $elapsedText)."
                    $lastHeartbeat = Get-Date
                }
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

    $totalDuration = if ($startTime) { (Get-Date) - $startTime } else { [TimeSpan]::Zero }
    Write-Log ("$Activity completed successfully in {0:mm\:ss} (exit code $($process.ExitCode))." -f $totalDuration)

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

function Get-ManageBdeValue {
    param(
        [string[]]$Lines,
        [Parameter(Mandatory)][string]$Label
    )

    if (-not $Lines) { return $null }

    $pattern = "^\s*{0}\s*[:：]\s*(.+)$" -f [regex]::Escape($Label)
    foreach ($line in $Lines) {
        if ($line -match $pattern) {
            return $Matches[1].Trim()
        }
    }
    return $null
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

function Test-PendingReboot {
    $rebootMarkers = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Updates\UpdateExeVolatile'
    )

    foreach ($path in $rebootMarkers) {
        try {
            if (Test-Path -LiteralPath $path) {
                return $true
            }
        } catch {
            # ignore access errors
        }
    }

    try {
        $sessionManager = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction Stop
        if ($sessionManager.PendingFileRenameOperations) {
            return $true
        }
    } catch {
        # no pending rename operations
    }

    return $false
}

function Register-PostUpdateResume {
    param(
        [Parameter(Mandatory)][string]$LogPath
    )

    if (-not (Test-Path -LiteralPath $LogPath)) {
        throw "Cannot schedule resume because log path '$LogPath' was not found."
    }
    if (-not $PSCommandPath) {
        throw 'Cannot register resume run because PSCommandPath is unavailable.'
    }

    $argumentTokens = New-Object System.Collections.Generic.List[string]
    $argumentTokens.Add('-NoLogo')
    $argumentTokens.Add('-NoProfile')
    $argumentTokens.Add('-ExecutionPolicy')
    $argumentTokens.Add('Bypass')
    $argumentTokens.Add('-File')
    $argumentTokens.Add($PSCommandPath)
    $argumentTokens.Add('-ResumePostUpdate')

    if ($Quiet) { $argumentTokens.Add('-Quiet') }
    if ($script:SkipRebootPromptPreference) { $argumentTokens.Add('-SkipRebootPrompt') }
    if ($script:AutoRestartPreference) { $argumentTokens.Add('-AutoRestart') }
    if (-not $script:SecurityPrepEnabled) { $argumentTokens.Add('-DisableSecurityPrep') }
    if ($LogDirectory) {
        $argumentTokens.Add('-LogDirectory')
        $argumentTokens.Add($LogDirectory)
    }
    if ($script:PreferredTimeZone) {
        $argumentTokens.Add('-PreferredTimeZone')
        $argumentTokens.Add($script:PreferredTimeZone)
    }

    $argumentTokens.Add('-ResumeLogPath')
    $argumentTokens.Add($LogPath)
    $argumentTokens.Add('-LaunchedFromScript')

    $escapedArguments = foreach ($token in $argumentTokens) {
        if ($null -eq $token -or $token -eq '') {
            '""'
        } elseif ($token -match '[\s"]') {
            '"' + $token.Replace('"','""') + '"'
        } else {
            $token
        }
    }

    $commandLine = 'powershell.exe ' + ($escapedArguments -join ' ')
    $runOnceKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    try {
        Set-ItemProperty -Path $runOnceKey -Name 'KovaLabsTuneUpResume' -Value $commandLine -ErrorAction Stop
        Write-Log ("Registered RunOnce entry to resume tune-up after reboot (`"{0}`")." -f $commandLine)
    } catch {
        throw "Failed to register RunOnce entry for resume: $($_.Exception.Message)"
    }
}

function Invoke-PostUpdateResumeGate {
    param(
        [switch]$PendingWork
    )

    if ($script:IsPostUpdateResume -or -not $PendingWork) {
        return $false
    }

    $pendingReboot = $script:WindowsUpdateRebootRequired -or (Test-PendingReboot)
    if (-not $pendingReboot) {
        return $false
    }

    if ($script:DisablePostUpdateResume) {
        Write-Log 'Pending reboot detected but automatic post-update resume is disabled. Continuing immediately.' -Level WARN
        return $false
    }

    try {
        Register-PostUpdateResume -LogPath $script:LogPath
    } catch {
        Write-Log ("Failed to schedule post-update resume: {0}" -f $_) -Level ERROR
        return $false
    }

    $script:PostUpdateResumeScheduled = $true
    Write-Log 'Post-update reboot is required before DISM/SFC can continue. The script will resume automatically after restart.'
    if (-not $Quiet) {
        Write-Host ''
        Write-Host 'Post-update reboot required. The tune-up will resume automatically after you sign back in.' -ForegroundColor Yellow
    }

    if ($script:AutoRestartPreference) {
        Write-Log 'Automatic reboot preference enabled; restarting now to finish the tune-up.'
        try {
            Restart-Computer -Force
        } catch {
            Write-Log ("Unable to restart automatically: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    return $true
}

function Invoke-WindowsUpdate {
    Write-Log '----- Windows Update Workflow (PSWindowsUpdate) -----'

    $resultPath = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ("KLTuneUp_WU_{0}.json" -f ([guid]::NewGuid()))
    $helperTemplate = @'
Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
$logPath = "__HELPER_LOG__"
$resultPath = "__RESULT_PATH__"
$autoRestartPref = __AUTO_RESTART__
$rebootRequired = $false
$exitCode = 0

function Write-ChildLog {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $levelTag = ("[{0}]" -f $Level).PadRight(8)
    $entry = "$timestamp $levelTag $Message"
    try {
        Add-Content -Path $logPath -Value $entry
    } catch {
        Write-Host ("Failed to append to helper log: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }

    switch ($Level) {
        'INFO' { $color = 'Gray' }
        'WARN' { $color = 'Yellow' }
        'ERROR' { $color = 'Red' }
    }
    Write-Host $entry -ForegroundColor $color
}

function Write-ChildExceptionDetail {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    if (-not $ErrorRecord) { return }
    $detailLines = ($ErrorRecord | Format-List * | Out-String) -split "`r?`n"
    foreach ($line in $detailLines) {
        if ($line.Trim().Length -gt 0) {
            Write-ChildLog ("Detail: {0}" -f $line.Trim()) 'ERROR'
        }
    }
}

function Ensure-PSWindowsUpdateModule {
    Write-ChildLog 'Ensuring PSWindowsUpdate module is available.'
    try {
        try {
            Get-PackageProvider -Name NuGet -ForceBootstrap -ErrorAction Stop | Out-Null
        } catch {
            Write-ChildLog ("NuGet provider bootstrap failed or is unavailable: {0}" -f $_.Exception.Message) 'WARN'
        }

        $module = Get-Module -ListAvailable -Name 'PSWindowsUpdate' | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $module) {
            Write-ChildLog 'PSWindowsUpdate module not found. Installing from PSGallery.'
            Install-Module -Name 'PSWindowsUpdate' -Force -Confirm:$false -Scope AllUsers -ErrorAction Stop | Out-Null
            Write-ChildLog 'PSWindowsUpdate module installed successfully.'
        } else {
            Write-ChildLog ("PSWindowsUpdate module already installed (Version {0})." -f $module.Version)
        }

        Import-Module -Name 'PSWindowsUpdate' -Force -ErrorAction Stop | Out-Null
        Write-ChildLog 'PSWindowsUpdate module imported.'
    } catch {
        Write-ChildLog ("Unable to prepare PSWindowsUpdate module: {0}" -f $_.Exception.Message) 'ERROR'
        Write-ChildExceptionDetail $_
        throw
    }
}

function Test-PendingReboot {
    $rebootMarkers = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Updates\UpdateExeVolatile'
    )

    foreach ($path in $rebootMarkers) {
        try {
            if (Test-Path -LiteralPath $path) {
                return $true
            }
        } catch { }
    }

    try {
        $sessionManager = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction Stop
        if ($sessionManager.PendingFileRenameOperations) {
            return $true
        }
    } catch { }

    return $false
}

try {
    Ensure-PSWindowsUpdateModule

    Write-ChildLog 'Scanning for updates via PSWindowsUpdate.'
    $availableUpdates = Get-WindowsUpdate -ErrorAction Stop
    if (-not $availableUpdates) {
        Write-ChildLog 'No applicable Windows Updates were detected.'
        return
    }

    foreach ($update in $availableUpdates) {
        $kbList = if ($update.KBArticleIDs) { $update.KBArticleIDs -join ', ' } elseif ($update.KB) { $update.KB } else { 'N/A' }
        Write-ChildLog ("Detected update: {0} (KB: {1})" -f $update.Title, $kbList)
    }

    $installParams = @{
        AcceptAll = $true
        ErrorAction = 'Stop'
        IgnoreReboot = $true
    }
    if ($autoRestartPref) {
        Write-ChildLog 'Installing updates via PSWindowsUpdate (automatic reboot handled by tune-up workflow).'
    } else {
        Write-ChildLog 'Installing updates via PSWindowsUpdate (manual reboot required).'
    }

    $installResults = Install-WindowsUpdate @installParams
    if ($installResults) {
        foreach ($result in $installResults) {
            $kbList = if ($result.KBArticleIDs) { $result.KBArticleIDs -join ', ' } elseif ($result.KB) { $result.KB } else { 'N/A' }
            $status = if ($result.Result) { $result.Result } else { 'Completed' }
            Write-ChildLog ("Installation result: {0} (KB: {1}) => {2}" -f $result.Title, $kbList, $status)
            $needsReboot = $false
            if ($result.PSObject.Properties.Match('RebootRequired')) {
                $needsReboot = [bool]$result.RebootRequired
            } elseif ($result.PSObject.Properties.Match('Reboot')) {
                $needsReboot = [bool]$result.Reboot
            }
            if ($needsReboot) {
                $rebootRequired = $true
            }
        }
    } else {
        Write-ChildLog 'PSWindowsUpdate did not return per-update installation details.'
    }

    if (-not $rebootRequired -and (Test-PendingReboot)) {
        $rebootRequired = $true
        Write-ChildLog 'Pending reboot detected after installing Windows Updates.'
    }
} catch {
    $exitCode = 1
    Write-ChildLog ("PSWindowsUpdate workflow failed: {0}" -f $_.Exception.Message) 'ERROR'
    if ($_.InvocationInfo) {
        Write-ChildLog $_.InvocationInfo.PositionMessage 'ERROR'
    }
    Write-ChildExceptionDetail $_
} finally {
    try {
        $result = @{ RebootRequired = $rebootRequired }
        $json = $result | ConvertTo-Json -Compress
        Set-Content -Path $resultPath -Value $json -Encoding UTF8 -Force
    } catch {
        Write-ChildLog ("Failed to write Windows Update result file: {0}" -f $_.Exception.Message) 'WARN'
    }
    Write-ChildLog 'Windows Update helper finished.'
}
exit $exitCode
'@

    $replacements = @{
        '__RESULT_PATH__' = $resultPath.Replace('"','""')
        '__AUTO_RESTART__' = if ($script:AutoRestartPreference) { '$true' } else { '$false' }
    }

    Invoke-HelperConsole -ScriptTemplate $helperTemplate -Activity 'Windows Update' -Replacements $replacements

    if (Test-Path -LiteralPath $resultPath) {
        try {
            $resultData = Get-Content -Path $resultPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($resultData -and $resultData.RebootRequired) {
                $script:WindowsUpdateRebootRequired = $true
            }
        } catch {
            Write-Log ("Unable to interpret Windows Update helper result: {0}" -f $_.Exception.Message) -Level WARN
        } finally {
            Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Log 'Windows Update helper result file was not found; reboot requirement could not be confirmed.' -Level WARN
    }
}

function Invoke-MicrosoftStoreUpdate {
    Write-Log '----- Microsoft Store Updates -----'
    $helperTemplate = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$logPath = "__HELPER_LOG__"

function Write-ChildLog {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $levelTag = ("[{0}]" -f $Level).PadRight(8)
    $entry = "$timestamp $levelTag $Message"
    try {
        Add-Content -Path $logPath -Value $entry
    } catch {
        Write-Host ("Failed to append to helper log: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }

    switch ($Level) {
        'INFO' { $color = 'Gray' }
        'WARN' { $color = 'Yellow' }
        'ERROR' { $color = 'Red' }
    }
    Write-Host $entry -ForegroundColor $color
}

try {
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($null -eq $winget) {
        Write-ChildLog 'winget is not available. Triggering Store UI for manual updates.' 'WARN'
        Start-Process 'explorer.exe' 'ms-windows-store://downloadsandupdates'
        return
    }

    Write-ChildLog 'Launching winget upgrade --all.'
    & $winget.Source upgrade --all --accept-package-agreements --accept-source-agreements
    $exitCode = $LASTEXITCODE
    Write-ChildLog ("winget upgrade completed with exit code {0}." -f $exitCode)
} catch {
    Write-ChildLog ("winget upgrade encountered an issue: {0}" -f $_.Exception.Message) 'ERROR'
} finally {
    Write-ChildLog 'Microsoft Store helper finished.'
}
'@

    Invoke-HelperConsole -ScriptTemplate $helperTemplate -Activity 'Microsoft Store updates'
}



function Invoke-DismRestoreHealth {
    Write-Log '----- DISM RestoreHealth -----'

    $dismTemplate = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$logPath = "__HELPER_LOG__"

function Write-ChildLog {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $levelTag = ("[{0}]" -f $Level).PadRight(8)
    $entry = "$timestamp $levelTag $Message"
    try {
        Add-Content -Path $logPath -Value $entry
    } catch {
        Write-Host ("Failed to append to helper log: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }

    switch ($Level) {
        'INFO' { $color = 'Gray' }
        'WARN' { $color = 'Yellow' }
        'ERROR' { $color = 'Red' }
    }
    Write-Host $entry -ForegroundColor $color
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

try {
    Write-ChildLog 'Running DISM /Online /Cleanup-Image /RestoreHealth. This can take a while.'
    $output = & dism.exe /Online /Cleanup-Image /RestoreHealth 2>&1
    $exitCode = $LASTEXITCODE
    if ($output) {
        $summary = Get-DismResultSummary -Lines $output
        Write-ChildLog $summary
    }
    Write-ChildLog ("DISM exited with code {0}." -f $exitCode)
} catch {
    Write-ChildLog ("DISM RestoreHealth encountered an issue: {0}" -f $_.Exception.Message) 'ERROR'
} finally {
    Write-ChildLog 'DISM helper finished.'
}
'@

    Invoke-HelperConsole -ScriptTemplate $dismTemplate -Activity 'DISM RestoreHealth'
}



function Invoke-SfcScan {
    Write-Log '----- SFC /SCANNOW -----'

    $sfcTemplate = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$logPath = "__HELPER_LOG__"

function Write-ChildLog {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $levelTag = ("[{0}]" -f $Level).PadRight(8)
    $entry = "$timestamp $levelTag $Message"
    try {
        Add-Content -Path $logPath -Value $entry
    } catch {
        Write-Host ("Failed to append to helper log: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }

    switch ($Level) {
        'INFO' { $color = 'Gray' }
        'WARN' { $color = 'Yellow' }
        'ERROR' { $color = 'Red' }
    }
    Write-Host $entry -ForegroundColor $color
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

try {
    Write-ChildLog 'Running SFC /SCANNOW. This can take several minutes.'
    $output = & sfc.exe /scannow 2>&1
    $exitCode = $LASTEXITCODE
    if ($output) {
        $summary = Get-SfcResultSummary -Lines $output
        Write-ChildLog $summary
    }
    Write-ChildLog ("SFC exited with code {0}." -f $exitCode)
} catch {
    Write-ChildLog ("SFC scan encountered an issue: {0}" -f $_.Exception.Message) 'ERROR'
} finally {
    Write-ChildLog 'SFC helper finished.'
}
'@

    Invoke-HelperConsole -ScriptTemplate $sfcTemplate -Activity 'SFC scan'
}



function Invoke-SystemCleanup {
    Write-Log '----- System Cleanup -----'
    # We used to call DISM with /StartComponentCleanup here to clean up superseded component store entries.
    # However, this can take a long time and sometimes returns non‑zero exit codes, leading to premature script termination.
    # CleanMgr will handle removing temporary files and old installations more reliably, so the DISM call has been removed.

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
        try {
            $cleanupAction = if ($target.ContainsKey('CleanupAction')) { $target['CleanupAction'] } else { $null }
            $totalFreed += Invoke-PathCleanup -Path $target['Path'] -Description $target['Description'] -CleanupAction $cleanupAction
        } catch {
            Write-Log "Cleanup target failed (${target['Description']} at ${target['Path']}): $($_.Exception.Message)" -Level WARN
        }
    }

    $totalFreed += Invoke-RecycleBinCleanup
    Write-Log ("Manual cleanup freed approximately {0}." -f (Format-ByteValue -Bytes $totalFreed))

    Invoke-CleanMgrSweep
}

function Invoke-CleanMgrSweep {
    $cleanMgrPath = Get-Command cleanmgr.exe -ErrorAction SilentlyContinue
    if (-not $cleanMgrPath) {
        Write-Log 'CleanMgr (cleanmgr.exe) is not available on this system; skipping built-in disk cleanup.' -Level WARN
        return
    }

    $modes = @(
        @{ Arguments = '/AUTOCLEAN'; Label = 'AutoClean' },
        @{ Arguments = '/VERYLOWDISK'; Label = 'VeryLowDisk' }
    )

    foreach ($mode in $modes) {
        $label = $mode.Label
        $args = $mode.Arguments
        Write-Log "Launching CleanMgr ($label) with arguments $args."
        try {
            $process = Start-Process -FilePath $cleanMgrPath.Source -ArgumentList $args -WindowStyle Normal -PassThru -Wait -ErrorAction Stop
            Write-Log "CleanMgr ($label) exited with code $($process.ExitCode)."
        } catch {
            Write-Log "CleanMgr ($label) encountered an issue: $($_.Exception.Message)" -Level WARN
        }
    }

    Write-Log 'Disk cleanup sweep completed (CleanMgr).'
}

function Invoke-TimeSynchronization {
    Write-Log '----- Time Synchronization -----'

    $timeSyncTemplate = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$logPath = "__HELPER_LOG__"
$preferredTimeZone = __TIME_ZONE__

function Write-ChildLog {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $levelTag = ("[{0}]" -f $Level).PadRight(8)
    $entry = "$timestamp $levelTag $Message"
    try {
        Add-Content -Path $logPath -Value $entry
    } catch {
        Write-Host ("Failed to append to helper log: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }

    switch ($Level) {
        'INFO' { $color = 'Gray' }
        'WARN' { $color = 'Yellow' }
        'ERROR' { $color = 'Red' }
    }
    Write-Host $entry -ForegroundColor $color
}

try {
    if ($preferredTimeZone) {
        try {
            $currentZone = (Get-TimeZone -ErrorAction Stop).Id
        } catch {
            $currentZone = $null
            Write-ChildLog ("Unable to determine current time zone: {0}" -f $_.Exception.Message) 'WARN'
        }

        if (-not $currentZone -or $currentZone -ne $preferredTimeZone) {
            try {
                Write-ChildLog ("Setting time zone to {0}." -f $preferredTimeZone)
                Set-TimeZone -Name $preferredTimeZone -ErrorAction Stop
            } catch {
                Write-ChildLog ("Failed to apply requested time zone ({0}): {1}" -f $preferredTimeZone, $_.Exception.Message) 'WARN'
            }
        }
    }

    Write-ChildLog 'Ensuring automatic time synchronization is enabled.'
    $ntpClientPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'
    try {
        $currentValue = (Get-ItemProperty -Path $ntpClientPath -Name Enabled -ErrorAction Stop).Enabled
        if ($currentValue -ne 1) {
            Set-ItemProperty -Path $ntpClientPath -Name Enabled -Value 1 -ErrorAction Stop
            Write-ChildLog 'Enabled the Windows NTP client (Set time automatically).'
        }
    } catch {
        Write-ChildLog ("Unable to verify automatic time sync registry state: {0}" -f $_.Exception.Message) 'WARN'
    }

    $isDomainJoined = $null
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $isDomainJoined = [bool]$computerSystem.PartOfDomain
    } catch {
        Write-ChildLog ("Unable to determine domain membership: {0}" -f $_.Exception.Message) 'WARN'
    }

    if ($isDomainJoined -eq $false) {
        $parametersPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
        try {
            $currentType = (Get-ItemProperty -Path $parametersPath -Name Type -ErrorAction Stop).Type
            if ($currentType -ne 'NTP') {
                Set-ItemProperty -Path $parametersPath -Name Type -Value 'NTP' -ErrorAction Stop
                Write-ChildLog 'Configured Windows Time service to use the NTP client.'
            }
            $desiredPeer = 'time.windows.com,0x8'
            $currentPeer = (Get-ItemProperty -Path $parametersPath -Name NtpServer -ErrorAction Stop).NtpServer
            if ($desiredPeer -ne $currentPeer) {
                Set-ItemProperty -Path $parametersPath -Name NtpServer -Value $desiredPeer -ErrorAction Stop
                Write-ChildLog ("Configured Windows Time server to {0}." -f $desiredPeer)
            }
        } catch {
            Write-ChildLog ("Unable to confirm Windows Time configuration: {0}" -f $_.Exception.Message) 'WARN'
        }
    } elseif ($isDomainJoined) {
        Write-ChildLog 'Domain-joined device detected; leaving Windows Time source configured by the domain.'
    }

    try {
        $timeService = Get-Service -Name 'W32Time' -ErrorAction Stop
        if ($timeService.Status -ne 'Running') {
            Write-ChildLog 'Starting Windows Time (W32Time) service.'
            Start-Service -Name 'W32Time' -ErrorAction Stop
        }
    } catch {
        Write-ChildLog ("Unable to verify or start the Windows Time service: {0}" -f $_.Exception.Message) 'WARN'
    }

    try {
        Write-ChildLog 'Refreshing Windows Time configuration via w32tm.exe.'
        & w32tm.exe /config /update
        Write-ChildLog 'Windows Time configuration refresh complete.'
    } catch {
        Write-ChildLog ("Failed to refresh Windows Time configuration: {0}" -f $_.Exception.Message) 'WARN'
    }

    try {
        Write-ChildLog 'Synchronizing system time via w32tm.exe /resync /force.'
        & w32tm.exe /resync /force
        Write-ChildLog 'System time synchronized with configured time source.'
    } catch {
        Write-ChildLog ("Time synchronization failed: {0}" -f $_.Exception.Message) 'WARN'
    }
} finally {
    Write-ChildLog 'Time synchronization helper finished.'
}
'@

    $timeZoneLiteral = if ([string]::IsNullOrWhiteSpace($script:PreferredTimeZone)) { '$null' } else { "'" + $script:PreferredTimeZone.Replace("'","''") + "'" }
    $replacements = @{ '__TIME_ZONE__' = $timeZoneLiteral }
    Invoke-HelperConsole -ScriptTemplate $timeSyncTemplate -Activity 'Time synchronization' -Replacements $replacements
}
function Invoke-DeviceDecryption {
    Write-Log '----- Device Decryption -----'

    $helperTemplate = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$logPath = "__HELPER_LOG__"
$mountPoint = "__MOUNT_POINT__"

function Write-ChildLog {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $levelTag = ("[{0}]" -f $Level).PadRight(8)
    $entry = "$timestamp $levelTag $Message"
    try {
        Add-Content -Path $logPath -Value $entry
    } catch {
        Write-Host ("Failed to append to helper log: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }

    switch ($Level) {
        'INFO' { $color = 'Gray' }
        'WARN' { $color = 'Yellow' }
        'ERROR' { $color = 'Red' }
    }
    Write-Host $entry -ForegroundColor $color
}

function Get-ManageBdeValue {
    param(
        [string[]]$Lines,
        [Parameter(Mandatory)][string]$Label
    )

    if (-not $Lines) { return $null }
    $pattern = "^\s*{0}\s*[:：]\s*(.+)$" -f [regex]::Escape($Label)
    foreach ($line in $Lines) {
        if ($line -match $pattern) {
            return $Matches[1].Trim()
        }
    }
    return $null
}

try {
    $manageBdePath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\manage-bde.exe'
    if (-not (Test-Path -LiteralPath $manageBdePath)) {
        Write-ChildLog 'manage-bde.exe was not found on this system. Skipping device decryption.' 'WARN'
        return
    }

    Write-ChildLog "Querying BitLocker status via manage-bde -status $mountPoint."
    $statusOutput = & $manageBdePath -status $mountPoint 2>&1
    $statusExit = $LASTEXITCODE
    if ($statusExit -ne 0) {
        Write-ChildLog ("manage-bde -status exited with code {0}. See helper window for details." -f $statusExit) 'WARN'
        return
    }

    $conversionStatus = Get-ManageBdeValue -Lines $statusOutput -Label 'Conversion Status'
    $percentageEncrypted = Get-ManageBdeValue -Lines $statusOutput -Label 'Percentage Encrypted'
    $protectionStatus = Get-ManageBdeValue -Lines $statusOutput -Label 'Protection Status'

    if (-not $conversionStatus -and -not $percentageEncrypted -and -not $protectionStatus) {
        Write-ChildLog 'BitLocker status information was not reported for this volume. Assuming it is not encrypted and skipping decryption.'
        return
    }

    $protectionDisplay = if ($protectionStatus) { $protectionStatus } else { 'Unknown' }
    $percentDisplay = if ($percentageEncrypted) { $percentageEncrypted } else { 'Unknown' }
    $conversionDisplay = if ($conversionStatus) { $conversionStatus } else { 'Unknown' }
    Write-ChildLog ("BitLocker status: Conversion={0}; Protection={1}; Encrypted={2}" -f $conversionDisplay, $protectionDisplay, $percentDisplay)

    if (-not $conversionStatus -or $conversionStatus -match 'Fully Decrypted') {
        Write-ChildLog 'System drive is already decrypted.'
        return
    }
    if ($conversionStatus -match 'Decryption in Progress') {
        Write-ChildLog 'System drive decryption is already in progress.'
        return
    }

    Write-ChildLog "Disabling BitLocker on $mountPoint via manage-bde -off."
    & $manageBdePath -off $mountPoint 2>&1 | ForEach-Object { Write-ChildLog $_ }
    $disableExit = $LASTEXITCODE
    if ($disableExit -ne 0) {
        Write-ChildLog ("manage-bde -off exited with code {0}." -f $disableExit) 'ERROR'
    } else {
        Write-ChildLog 'BitLocker has been disabled; full volume decryption has begun.'
    }
} finally {
    Write-ChildLog 'Device decryption helper finished.'
}
'@

    $mountLiteral = $env:SystemDrive.Replace('"','""')
    $replacements = @{ '__MOUNT_POINT__' = $mountLiteral }
    Invoke-HelperConsole -ScriptTemplate $helperTemplate -Activity 'BitLocker decryption' -Replacements $replacements
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

    if (-not $script:IsPostUpdateResume) {
        $script:WindowsUpdateRebootRequired = $false
    } else {
        $IncludeTimeSync = $false
        $IncludeDeviceDecryption = $false
        $IncludeWindowsUpdate = $false
        $IncludeStore = $false
    }

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

    $postUpdateWorkPending = ($IncludeScans -or $IncludeCleanup) -and $IncludeWindowsUpdate
    if (Invoke-PostUpdateResumeGate -PendingWork:$postUpdateWorkPending) {
        return
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

function Toggle-SecurityPrepPreference {
    $script:SecurityPrepEnabled = -not $script:SecurityPrepEnabled
    $status = if ($script:SecurityPrepEnabled) { 'enabled' } else { 'disabled' }
    Write-Log "Time sync and device decryption $status via menu selection."
    Write-Host "Time synchronization + device decryption are now $status." -ForegroundColor Yellow
}

function Toggle-PostUpdateResumePreference {
    $script:DisablePostUpdateResume = -not $script:DisablePostUpdateResume
    $state = if ($script:DisablePostUpdateResume) { 'disabled' } else { 'enabled' }
    Write-Log "Automatic post-update resume $state via menu selection."
    $display = if ($script:DisablePostUpdateResume) { 'DISABLED (manual continuation)' } else { 'ENABLED (auto resume)' }
    Write-Host "Automatic post-update resume is now $display." -ForegroundColor Yellow
}

function Toggle-RebootPromptPreference {
    $script:SkipRebootPromptPreference = -not $script:SkipRebootPromptPreference
    $SkipRebootPrompt = $script:SkipRebootPromptPreference
    $state = if ($script:SkipRebootPromptPreference) { 'skipped' } else { 'shown' }
    Write-Log "End-of-run reboot prompt will now be $state via menu selection."
    Write-Host "End-of-run reboot prompt will now be $state." -ForegroundColor Yellow
}

function Set-PreferredTimeZoneInteractive {
    $currentDisplay = if ([string]::IsNullOrWhiteSpace($script:PreferredTimeZone)) {
        'System default'
    } else {
        $script:PreferredTimeZone
    }
    Write-Host ''
    Write-Host "Current preferred time zone: $currentDisplay" -ForegroundColor Cyan
    $newZone = Read-Host 'Enter Windows time zone ID (blank to cancel, type SYSTEM to use device default)'
    if ([string]::IsNullOrWhiteSpace($newZone)) {
        Write-Host 'Time zone preference unchanged.'
        return
    }
    if ($newZone.Trim().ToUpperInvariant() -eq 'SYSTEM') {
        $script:PreferredTimeZone = ''
        Write-Log 'Time zone preference cleared; device default will be used.'
        Write-Host 'Time zone override cleared; will use system default.' -ForegroundColor Yellow
        return
    }
    try {
        Get-TimeZone -Id $newZone -ErrorAction Stop | Out-Null
    } catch {
        Write-Host ("'{0}' is not a valid Windows time zone ID. Use Get-TimeZone -ListAvailable for valid options." -f $newZone) -ForegroundColor Red
        return
    }
    $script:PreferredTimeZone = $newZone
    Write-Log "Preferred time zone updated to $newZone via menu selection."
    Write-Host "Preferred time zone set to $newZone." -ForegroundColor Yellow
}

function Show-AdvancedSettingsMenu {
    while ($true) {
        Write-Host ''
        Write-Host '--- Advanced Settings ---' -ForegroundColor Cyan
        $autoState = if ($script:AutoRestartPreference) { 'ON' } else { 'OFF' }
        $securityState = if ($script:SecurityPrepEnabled) { 'ON' } else { 'OFF' }
        $resumeState = if ($script:DisablePostUpdateResume) { 'DISABLED (manual continuation)' } else { 'ENABLED (auto resume)' }
        $promptState = if ($script:SkipRebootPromptPreference) { 'SKIPPED' } else { 'SHOWN' }
        $tzDisplay = if ([string]::IsNullOrWhiteSpace($script:PreferredTimeZone)) { 'System default' } else { $script:PreferredTimeZone }
        Write-Host "1) Toggle automatic Windows Update reboot (Currently: $autoState)"
        Write-Host "2) Toggle time sync + device decryption (Currently: $securityState)"
        Write-Host "3) Toggle automatic post-update resume (Currently: $resumeState)"
        Write-Host "4) Toggle end-of-run reboot prompt (Currently: $promptState)"
        Write-Host "5) Set preferred time zone (Currently: $tzDisplay)"
        Write-Host '0) Return to main menu'
        $selection = Read-Host 'Choose an advanced option'
        switch ($selection) {
            '1' { Toggle-AutoRestartPreference }
            '2' { Toggle-SecurityPrepPreference }
            '3' { Toggle-PostUpdateResumePreference }
            '4' { Toggle-RebootPromptPreference }
            '5' { Set-PreferredTimeZoneInteractive }
            '0' { return }
            default {
                Write-Host 'Invalid selection. Try again.' -ForegroundColor Yellow
            }
        }
    }
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
    Write-Host '8) Configure advanced settings'
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
    if (-not $script:SecurityPrepEnabled) {
        Write-Log 'Time synchronization and device decryption are currently disabled.'
    }
    if ($script:DisablePostUpdateResume) {
        Write-Log 'Automatic post-update resume has been disabled via parameter.'
    }
    if ($script:IsPostUpdateResume) {
        Write-Log 'Resume mode detected; skipping Windows/Microsoft Store updates and running scans + cleanup only.'
    }

    if ($RunAll -or $script:IsPostUpdateResume) {
        Test-Cancellation
        if ($script:IsPostUpdateResume) {
            Invoke-TuneUp -IncludeTimeSync:$false -IncludeDeviceDecryption:$false -IncludeWindowsUpdate:$false -IncludeStore:$false -IncludeScans:$true -IncludeCleanup:$true
        } else {
            Invoke-TuneUp -IncludeTimeSync:$script:SecurityPrepEnabled -IncludeDeviceDecryption:$script:SecurityPrepEnabled
        }
        $script:WorkPerformed = $true
    } else {
        while ($true) {
            $selection = Show-Menu
            Test-Cancellation
            $handled = $true
            $returnToMenu = $true
            switch ($selection) {
                '1' {
                    Write-Log 'Menu option 1 selected: Run everything.'
                    try {
                        Invoke-TuneUp -IncludeTimeSync:$script:SecurityPrepEnabled -IncludeDeviceDecryption:$script:SecurityPrepEnabled
                        $script:WorkPerformed = $true
                        Write-Log 'Menu option 1 completed successfully.'
                    } catch {
                        Write-Log "Menu option 1 failed: $($_.Exception.Message)" -Level ERROR
                        if ($_.ScriptStackTrace) { Write-Log $_.ScriptStackTrace -Level ERROR }
                        Write-Host "Menu option 1 failed: $($_.Exception.Message)" -ForegroundColor Red
                        $handled = $false
                    }
                }
                '2' {
                    Write-Log 'Menu option 2 selected: Windows Update only.'
                    try {
                        Invoke-TuneUp -IncludeTimeSync:$script:SecurityPrepEnabled -IncludeDeviceDecryption:$script:SecurityPrepEnabled -IncludeStore:$false -IncludeScans:$false -IncludeCleanup:$false
                        $script:WorkPerformed = $true
                        Write-Log 'Menu option 2 completed successfully.'
                    } catch {
                        Write-Log "Menu option 2 failed: $($_.Exception.Message)" -Level ERROR
                        if ($_.ScriptStackTrace) { Write-Log $_.ScriptStackTrace -Level ERROR }
                        Write-Host "Menu option 2 failed: $($_.Exception.Message)" -ForegroundColor Red
                        $handled = $false
                    }
                }
                '3' {
                    Write-Log 'Menu option 3 selected: Microsoft Store updates only.'
                    try {
                        Invoke-TuneUp -IncludeTimeSync:$script:SecurityPrepEnabled -IncludeDeviceDecryption:$script:SecurityPrepEnabled -IncludeWindowsUpdate:$false -IncludeScans:$false -IncludeCleanup:$false
                        $script:WorkPerformed = $true
                        Write-Log 'Menu option 3 completed successfully.'
                    } catch {
                        Write-Log "Menu option 3 failed: $($_.Exception.Message)" -Level ERROR
                        if ($_.ScriptStackTrace) { Write-Log $_.ScriptStackTrace -Level ERROR }
                        Write-Host "Menu option 3 failed: $($_.Exception.Message)" -ForegroundColor Red
                        $handled = $false
                    }
                }
                '4' {
                    Write-Log 'Menu option 4 selected: System scans.'
                    try {
                        Invoke-TuneUp -IncludeTimeSync:$script:SecurityPrepEnabled -IncludeDeviceDecryption:$script:SecurityPrepEnabled -IncludeWindowsUpdate:$false -IncludeStore:$false -IncludeCleanup:$false
                        $script:WorkPerformed = $true
                        Write-Log 'Menu option 4 completed successfully.'
                    } catch {
                        Write-Log "Menu option 4 failed: $($_.Exception.Message)" -Level ERROR
                        if ($_.ScriptStackTrace) { Write-Log $_.ScriptStackTrace -Level ERROR }
                        Write-Host "Menu option 4 failed: $($_.Exception.Message)" -ForegroundColor Red
                        $handled = $false
                    }
                }
                '5' {
                    Write-Log 'Menu option 5 selected: Cleanup workflow.'
                    try {
                        Invoke-TuneUp -IncludeTimeSync:$script:SecurityPrepEnabled -IncludeDeviceDecryption:$script:SecurityPrepEnabled -IncludeWindowsUpdate:$false -IncludeStore:$false -IncludeScans:$false
                        $script:WorkPerformed = $true
                        Write-Log 'Menu option 5 completed successfully.'
                    } catch {
                        Write-Log "Menu option 5 failed: $($_.Exception.Message)" -Level ERROR
                        if ($_.ScriptStackTrace) { Write-Log $_.ScriptStackTrace -Level ERROR }
                        Write-Host "Menu option 5 failed: $($_.Exception.Message)" -ForegroundColor Red
                        $handled = $false
                    }
                }
                '6' {
                    Write-Log 'Menu option 6 selected: Open log folder.'
                    Open-LogFolder
                    $handled = $false
                }
                '7' {
                    Write-Log 'Menu option 7 selected: Device decryption.'
                    try {
                        Invoke-TuneUp -IncludeTimeSync:$false -IncludeDeviceDecryption:$true -IncludeWindowsUpdate:$false -IncludeStore:$false -IncludeScans:$false -IncludeCleanup:$false
                        $script:WorkPerformed = $true
                        Write-Log 'Menu option 7 completed successfully.'
                    } catch {
                        Write-Log "Menu option 7 failed: $($_.Exception.Message)" -Level ERROR
                        if ($_.ScriptStackTrace) { Write-Log $_.ScriptStackTrace -Level ERROR }
                        Write-Host "Menu option 7 failed: $($_.Exception.Message)" -ForegroundColor Red
                        $handled = $false
                    }
                }
                '8' {
                    Write-Log 'Menu option 8 selected: Advanced settings.'
                    Show-AdvancedSettingsMenu
                    $handled = $false
                }
                '0' {
                    Write-Log 'Menu option 0 selected: Exit requested.'
                    $returnToMenu = $false
                }
                default {
                    Write-Log "Invalid menu selection ('$selection')." -Level WARN
                    Write-Host 'Invalid selection. Please choose again.' -ForegroundColor Yellow
                    $handled = $false
                }
            }

            if (-not $returnToMenu) {
                break
            }

            if ($handled) {
                Write-Host ''
                Write-Host 'Returning to main menu...' -ForegroundColor DarkGray
                Write-Log 'Menu loop awaiting next selection.'
            }
        }
    }

    if ($script:WorkPerformed -and -not $script:PostUpdateResumeScheduled) {
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
    } elseif ($script:TuneUpCompleted -and -not $script:SkipRebootPromptPreference) {
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
    if (-not $Quiet -and -not $alreadyPrompted) {
        if ($LaunchedFromScript) {
            [void](Read-Host 'Press Enter to close this window.')
        } else {
            [void](Read-Host 'Press Enter to return to the PowerShell prompt.')
        }
    }
}

# Do not call `exit` at the end of the script.  When running under a console host
# with `-NoExit` (as invoked from the launcher), using `exit` will close the
# entire PowerShell session immediately, making it impossible to see log output or error messages.
# Instead, rely on the final prompts above to keep the window open.  If a caller
# needs the exit code, consider using `$host.SetShouldExit()` instead of `exit`.

if ($script:FatalError) {
    # A fatal error occurred.  We deliberately avoid calling `exit` or `SetShouldExit` here
    # so that the console remains open (especially when the script is launched with
    # the `-NoExit` flag).  Review the log for details and close the window manually.
    # You can still determine that a fatal error occurred by examining the
    # `$script:FatalError` variable or by parsing the log file.
}
