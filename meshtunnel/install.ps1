<#
meshtunnel setup for Windows (PowerShell 7 on Linux and macOS works too). MeshCentral serves this file with its address
filled in and the clients inside, so nothing else is downloaded. Use the one-line setup command from the web UI
(Terminal tab > Local Terminal) and paste it into PowerShell.

It installs meshtunnel for the current user only, no administrator rights needed: in %LOCALAPPDATA%\meshtunnel, with
its bin folder added to your PATH. Then it signs in with the one-time setup code and sets up ssh so that
"ssh <user>@<device>.mesh" works. "meshtunnel uninstall" undoes all of it.

Author: Jugurtha-Green. License: Apache-2.0.
#>
param([string]$Code = '', [string]$Runtime = 'powershell')

# Runs inside the PowerShell window the command was pasted into: no "exit", and nothing leaks out of this block.
& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $SERVER = '__MESHTUNNEL_SERVER__'
    $PIN = '__MESHTUNNEL_PIN__'
    $LOGINKEY = '__MESHTUNNEL_LOGINKEY__'
    $SOURCE_PS1 = '__MESHTUNNEL_SOURCE_PS1__'
    $SOURCE_JS = '__MESHTUNNEL_SOURCE_JS__'

    function Say([string]$Text) { Write-Host ('meshtunnel setup: ' + $Text) }

    # The user's PATH, with its registry type kept (it usually holds %VARIABLES%).
    function Add-UserPath([string]$Dir) {
        $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
        try {
            $old = [string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $parts = @($old.Split(';') | Where-Object { $_ -ne '' })
            if (@($parts | Where-Object { $_.TrimEnd('\') -eq $Dir.TrimEnd('\') }).Count -gt 0) { return $false }
            $kind = if ($old -ne '') { $k.GetValueKind('Path') } else { [Microsoft.Win32.RegistryValueKind]::ExpandString }
            $k.SetValue('Path', (@($parts + $Dir) -join ';'), $kind)
        } finally { $k.Close() }
        [Environment]::SetEnvironmentVariable('MESHTUNNEL_PATH_REFRESH', [NullString]::Value, 'User') # Tells Explorer and new windows
        return $true
    }

    try {
        $isWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
        if ($SERVER -notlike 'https://*') { throw 'run the setup command from the web UI (Terminal tab > Local Terminal), not this file directly' }
        if (($Code -ne '') -and ($Code -cnotmatch '^[A-Za-z0-9]{20}$')) { throw ('"' + $Code + '" is not a setup code, copy the command again from the web UI') }
        if (@('powershell', 'node') -notcontains $Runtime) { throw ('unknown client "' + $Runtime + '", use powershell or node') }
        if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'PowerShell runs in Constrained Language Mode on this computer (a security policy): choose the Node.js client in the web UI instead' }

        if ($isWin) {
            $dir = Join-Path $env:LOCALAPPDATA 'meshtunnel'
            $bin = Join-Path $dir 'bin'
            $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' # Always there, starts faster than pwsh
        } else {
            if ($Runtime -eq 'node') { throw 'on Linux and macOS, use the curl command from the web UI for the Node.js client' }
            $dir = Join-Path $HOME '.local/share/meshtunnel'
            $bin = Join-Path $HOME '.local/bin'
            $ps = (Get-Process -Id $PID).Path
        }
        foreach ($d in @($dir, $bin)) { if (-not [IO.Directory]::Exists($d)) { [void][IO.Directory]::CreateDirectory($d) } }

        if ($Runtime -eq 'node') {
            $node = $null
            foreach ($c in @(Get-Command node -CommandType Application -ErrorAction SilentlyContinue)) {
                & $c.Source -e 'process.exit(parseInt(process.versions.node) >= 16 ? 0 : 1)' 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) { $node = $c.Source; break }
            }
            if ($null -eq $node) { throw 'Node.js 16 or newer was not found (https://nodejs.org), or choose the PowerShell client in the web UI. The setup code stays valid for 15 minutes.' }
            $client = Join-Path $dir 'meshtunnel.js'
            [IO.File]::WriteAllBytes($client, [Convert]::FromBase64String($SOURCE_JS))
            $version = 'Node.js ' + (& $node -p 'process.versions.node')
            $shim = '@"' + $node + '" "%~dp0..\meshtunnel.js" %*'
        } else {
            $client = Join-Path $dir 'meshtunnel.ps1'
            # With a BOM: Windows PowerShell 5.1 reads a script without one in the local code page.
            [IO.File]::WriteAllBytes($client, [byte[]](@(0xEF, 0xBB, 0xBF) + [Convert]::FromBase64String($SOURCE_PS1)))
            $version = if ($isWin) { 'Windows PowerShell' } else { 'PowerShell ' + $PSVersionTable.PSVersion }
            $shim = '@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0..\meshtunnel.ps1" %*'
        }
        if ($isWin) {
            [IO.File]::WriteAllText((Join-Path $bin 'meshtunnel.cmd'), ($shim + "`r`n"), (New-Object Text.ASCIIEncoding))
            $command = Join-Path $bin 'meshtunnel.cmd'
        } else {
            $command = Join-Path $bin 'meshtunnel'
            [IO.File]::WriteAllText($command, ("#!/bin/sh`nexec '" + $ps.Replace("'", "'\''") + "' -NoProfile -File '" + $client.Replace("'", "'\''") + "' `"`$@`"`n"))
            & chmod 755 $command
        }
        Say ('installed the ' + $version + ' client as ' + $client)

        # Run it: the first run also compiles the PowerShell client's network engine, so later commands start fast.
        $invoke = {
            param([string[]]$ArgList)
            if ($Runtime -eq 'node') { & $node $client @ArgList | Out-Host } else { & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $client @ArgList | Out-Host }
            return $LASTEXITCODE
        }
        $url = if ($LOGINKEY -ne '') { $SERVER + '?key=' + $LOGINKEY } else { $SERVER }
        if ($Code -eq '') {
            $hint = if ($PIN -ne '') { " --pin '" + $PIN + "'" } else { '' }
            Say ("no setup code given, sign in with: meshtunnel login '" + $url + "'" + $hint)
        } else {
            $loginArgs = @('login', $url, '--code', $Code)
            if ($PIN -ne '') { $loginArgs += @('--pin', $PIN) }
            if ((& $invoke $loginArgs) -ne 0) { throw 'signing in failed (see above). Create a new setup command in the web UI and paste it again.' }
        }
        if ((& $invoke @('ssh-config', '--install')) -ne 0) { Say 'could not set up ssh, run later: meshtunnel ssh-config --install' }
        if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) { Say 'note: no ssh client is installed here ("Settings > Apps > Optional features > OpenSSH Client" on Windows); "meshtunnel shell <device>" works without one' }
        if ($isWin) {
            if ((& $invoke @('install-handler')) -ne 0) { Say '"Open in my terminal" links are not set up, run later: meshtunnel install-handler' }
            $added = Add-UserPath $bin
            if ($added) { Say ('added ' + $bin + ' to your PATH') }
            Say 'done. Open a new terminal window to use the meshtunnel command (ssh to <device>.mesh works right away).'
        } elseif ((':' + $env:PATH + ':') -like ('*:' + $bin + ':*')) {
            Say 'done. Try: meshtunnel ls'
        } else {
            Say ('done. Add ' + $bin + ' to your PATH to use the meshtunnel command (ssh to <device>.mesh works right away).')
        }
    } catch {
        Write-Host ('meshtunnel setup: ' + $_.Exception.Message) -ForegroundColor Red
    }
}
