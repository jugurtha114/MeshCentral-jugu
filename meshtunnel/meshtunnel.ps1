<#
meshtunnel: reach MeshCentral devices from your own terminal (PowerShell edition).

An ssh ProxyCommand (so ssh, scp, sftp and VS Code work as usual), a local port forwarder and a client for the agent's
own shell. Everything goes through the server's relay on its HTTPS port, so devices behind NAT or a firewall work
without opening anything. Windows PowerShell 5.1 (part of Windows 10 and 11) or PowerShell 7: nothing to install.
Same commands, settings file, certificate pins and device names as meshtunnel.js (Node.js) and meshtunnel.py (Python).
The network part is the small C# engine at the end of this file, compiled on first use and cached.

Author: Jugurtha-Green. License: Apache-2.0.
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$VERSION = '1.1.0'
$IsWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
$EXIT_OK = 0; $EXIT_USAGE = 1; $EXIT_AUTH = 2; $EXIT_NOTFOUND = 3; $EXIT_REFUSED = 4; $EXIT_TLS = 5
$script:ExitCode = 0
$TerminalProtocols = @(1, 6, 8, 9) # Admin shell, admin PowerShell, user shell, user PowerShell
$ScriptFile = [IO.Path]::GetFullPath($PSCommandPath)

# Everything a command prints goes through these: the pipeline itself must stay silent, it is the ssh data stream.
function Write-Note([string]$Message) { [Console]::Error.WriteLine('meshtunnel: ' + $Message) }
function Write-Err([string]$Text) { [Console]::Error.Write($Text) }
function Write-Out([string]$Text) { [Console]::Out.Write($Text) }

function New-MtError([string]$Message, [int]$Code = 1, [hashtable]$Extra = $null) {
    $e = New-Object System.Exception $Message
    $e.Data['mtcode'] = $Code
    if ($null -ne $Extra) { foreach ($k in $Extra.Keys) { $e.Data[$k] = $Extra[$k] } }
    return $e
}
function Fail([string]$Message, [int]$Code = 1, [hashtable]$Extra = $null) { throw (New-MtError $Message $Code $Extra) }

# The meshtunnel error inside whatever PowerShell wrapped around it: @{ message; code; relayEarly; timedOut; closeInfo;
# data }, or $null when it is not one of ours (a bug).
function Get-MtError($err) {
    $ex = if ($err -is [System.Management.Automation.ErrorRecord]) { $err.Exception } else { $err }
    while ($null -ne $ex) {
        if ($ex.GetType().FullName -eq 'MeshTunnel.MtException') { return @{ message = $ex.Message; code = $ex.Code; relayEarly = $ex.RelayEarly; timedOut = $ex.TimedOut; closeInfo = $ex.CloseInfo; data = @{} } }
        if ($ex.Data.Contains('mtcode')) { return @{ message = $ex.Message; code = [int]$ex.Data['mtcode']; relayEarly = [bool]$ex.Data['relayEarly']; timedOut = [bool]$ex.Data['timedOut']; closeInfo = $ex.Data['closeInfo']; data = $ex.Data } }
        $ex = $ex.InnerException
    }
    return $null
}

#
# Files
#

function Get-HomeDir { if ($IsWin) { return $env:USERPROFILE } return $env:HOME }

function Get-ConfigFile {
    if ($env:MESHTUNNEL_CONFIG) { return [IO.Path]::GetFullPath($env:MESHTUNNEL_CONFIG) }
    if ($IsWin) { $base = if ($env:APPDATA) { $env:APPDATA } else { Join-Path (Get-HomeDir) 'AppData\Roaming' } }
    else { $base = if ($env:XDG_CONFIG_HOME) { $env:XDG_CONFIG_HOME } else { Join-Path (Get-HomeDir) '.config' } }
    return [IO.Path]::Combine($base, 'meshtunnel', 'config.json')
}

function Get-CacheDir {
    if ($IsWin) { $base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path (Get-HomeDir) 'AppData\Local' } }
    else { $base = if ($env:XDG_CACHE_HOME) { $env:XDG_CACHE_HOME } else { Join-Path (Get-HomeDir) '.cache' } }
    return Join-Path $base 'meshtunnel'
}

# Where the setup command installs this script: the uninstall removes it only from there.
function Get-InstallDir {
    if ($IsWin) { return Get-CacheDir }
    $base = if ($env:XDG_DATA_HOME) { $env:XDG_DATA_HOME } else { Join-Path (Get-HomeDir) '.local/share' }
    return Join-Path $base 'meshtunnel'
}

function New-Dir([string]$Path, [bool]$Private = $true) {
    if (-not [IO.Directory]::Exists($Path)) {
        [void][IO.Directory]::CreateDirectory($Path)
        if ((-not $IsWin) -and $Private) { & chmod 700 $Path }
    }
}

# Write through a temporary file and a rename, so concurrent readers (parallel ssh sessions) never see a partial file.
function Write-FileAtomic([string]$Path, [string]$Text, [string]$Mode = '600', [bool]$Bom = $false) {
    $dir = [IO.Path]::GetDirectoryName($Path)
    $tmp = Join-Path $dir ('.' + [IO.Path]::GetFileName($Path) + '.' + $PID + '.' + [Guid]::NewGuid().ToString('n').Substring(0, 8) + '.tmp')
    try {
        [IO.File]::WriteAllText($tmp, $Text, (New-Object Text.UTF8Encoding($Bom)))
        if (-not $IsWin) { & chmod $Mode $tmp }
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($tmp, $Path, [NullString]::Value) } else { [IO.File]::Move($tmp, $Path) }
    } catch {
        try { [IO.File]::Delete($tmp) } catch { }
        throw
    }
}

function Read-Config([bool]$Required) {
    $file = Get-ConfigFile
    if (-not [IO.File]::Exists($file)) {
        if ($Required) { Fail 'not logged in yet, run: meshtunnel login <server-url>' $EXIT_AUTH }
        return $null
    }
    $cfg = $null
    try { $cfg = [MeshTunnel.Json]::Parse([IO.File]::ReadAllText($file)) } catch { Fail ('cannot read ' + $file + ': ' + $_.Exception.GetBaseException().Message) }
    if ($cfg -isnot [Collections.Hashtable]) { Fail ('cannot read ' + $file) }
    if ($Required -and (($cfg['url'] -isnot [string]) -or ($cfg['user'] -isnot [string]) -or ($cfg['pass'] -isnot [string]))) { Fail ($file + ' is incomplete, run meshtunnel login again') $EXIT_AUTH }
    return $cfg
}

function Save-Config($cfg) {
    $file = Get-ConfigFile
    New-Dir ([IO.Path]::GetDirectoryName($file))
    Write-FileAtomic $file ([MeshTunnel.Json]::Pretty($cfg) + "`n")
    return $file
}

#
# Server address, pins and requests
#

# Accepts "host", "host:port" or a pasted https://, wss:// or page URL. Returns the server base URL (ending with the
# domain path and a slash) and the optional 3FA login key from "?key=".
function ConvertFrom-ServerUrl([string]$Value) {
    $s = ([string]$Value).Trim()
    if ($s -eq '') { Fail 'missing server URL, e.g. https://mesh.example.com' }
    if ($s -notmatch '^[a-z][a-z0-9+.-]*://') { $s = 'https://' + $s }
    $u = $null
    if (-not [Uri]::TryCreate($s, [UriKind]::Absolute, [ref]$u)) { Fail ('invalid server URL: ' + $Value) }
    $scheme = $u.Scheme.ToLowerInvariant()
    if ($scheme -eq 'wss') { $scheme = 'https' }
    if ($scheme -ne 'https') { Fail ('the server URL must use https://, got ' + $scheme + '://') }
    if ($u.UserInfo -ne '') { Fail ('invalid server URL: ' + $Value) }
    $p = $u.AbsolutePath -replace '[^/]*\.(ashx|html?|js)$', ''
    if (-not $p.EndsWith('/')) { $p += '/' }
    $key = $null
    foreach ($pair in $u.Query.TrimStart('?').Split('&')) {
        $kv = $pair.Split(@('='), 2, [StringSplitOptions]::None)
        if (($kv.Count -eq 2) -and ([Uri]::UnescapeDataString($kv[0]) -ceq 'key')) { $key = [Uri]::UnescapeDataString($kv[1].Replace('+', ' ')) }
    }
    if ($key -eq '') { $key = $null }
    return @{ url = ('https://' + $u.Authority.ToLowerInvariant() + $p); loginkey = $key }
}

function Get-BasePath($cfg) { return ([Uri]$cfg['url']).AbsolutePath }
function Get-KeyQuery($cfg) { if ($cfg['loginkey']) { return '?key=' + [Uri]::EscapeDataString([string]$cfg['loginkey']) } return '' }
function Get-Pin($cfg) { if ($cfg['pin']) { return [string]$cfg['pin'] } return [NullString]::Value }

function ConvertTo-Pin([string]$Pin) {
    if ($Pin.Trim() -cnotmatch '^sha256//([A-Za-z0-9+/]{43}=)$') { Fail 'invalid --pin, expected sha256//<44 base64 characters> as shown in the web UI' }
    return 'sha256//' + $Matches[1]
}

function Get-MeshAuth([string]$User, [string]$Pass, $Token) {
    $v = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($User)) + ',' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Pass))
    if ($null -ne $Token) { $v += ',' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$Token)) }
    return $v
}

function Invoke-MtRequest($cfg, [string]$Method, [string]$PathAndQuery, [hashtable]$Form) {
    $body = [NullString]::Value
    if ($null -ne $Form) { $body = (@($Form.Keys | ForEach-Object { [Uri]::EscapeDataString([string]$_) + '=' + [Uri]::EscapeDataString([string]$Form[$_]) }) -join '&') }
    return [MeshTunnel.Tls]::Request([string]$cfg['url'], (Get-Pin $cfg), $Method, $PathAndQuery, $body)
}

function ConvertFrom-JsonBody($r) { try { $j = [MeshTunnel.Json]::Parse($r.Text); if ($j -is [Collections.Hashtable]) { return $j } } catch { } return $null }

# Trade a setup code from the web UI (Terminal tab > Local Terminal) for a login token: no password, no second factor.
function Invoke-Redeem($cfg, [string]$Code, $previous) {
    $form = @{ code = $Code; name = ('meshtunnel@' + [Environment]::MachineName.ToLowerInvariant()) }
    if ($form.name.Length -gt 100) { $form.name = $form.name.Substring(0, 100) }
    if (($null -ne $previous) -and ($previous['createdToken'] -eq $true) -and ($previous['url'] -ceq $cfg['url']) -and ($previous['user'] -is [string]) -and ($previous['pass'] -is [string])) { $form.replaceuser = $previous['user']; $form.replacepass = $previous['pass'] }
    $r = Invoke-MtRequest $cfg 'POST' ((Get-BasePath $cfg) + 'meshtunnel-redeem' + (Get-KeyQuery $cfg)) $form
    $j = ConvertFrom-JsonBody $r
    if (($r.Status -eq 200) -and ($null -ne $j) -and ($j['user'] -is [string]) -and ($j['pass'] -is [string])) { return $j }
    if ($r.Status -eq 404) { Fail ('this server does not accept setup codes (is it older than this tool?), sign in with your password instead: meshtunnel login ' + $cfg['url']) $EXIT_AUTH }
    if (($null -ne $j) -and $j['error']) { Fail ([string]$j['error']) $EXIT_AUTH }
    Fail ('the server refused the setup code: ' + $r.StatusLine) $EXIT_AUTH
}

# Revoke the stored login token by presenting it: $true when it is gone on the server, $null for an older server.
function Invoke-Revoke($cfg) {
    $r = Invoke-MtRequest $cfg 'POST' ((Get-BasePath $cfg) + 'meshtunnel-revoke' + (Get-KeyQuery $cfg)) @{ user = $cfg['user']; pass = $cfg['pass'] }
    if (($r.Status -eq 200) -or ($r.Status -eq 403)) { return $true }
    if ($r.Status -eq 404) { return $null }
    $j = ConvertFrom-JsonBody $r
    if (($null -ne $j) -and $j['error']) { Fail ([string]$j['error']) $EXIT_AUTH }
    Fail ('the server answered ' + $r.StatusLine) $EXIT_AUTH
}

function Invoke-RevokeStored($cfg) {
    $r = Invoke-Revoke $cfg
    if ($null -ne $r) { return $r }
    $ctl = Connect-Control $cfg $cfg['user'] $cfg['pass'] $null # Older server: ask over the control channel
    try {
        $list = Invoke-Control $ctl @{ action = 'loginTokens'; remove = @($cfg['user']) } { param($m) $m['action'] -eq 'loginTokens' } 15000
        foreach ($t in @($list['loginTokens'])) { if (($t -is [Collections.Hashtable]) -and ($t['tokenUser'] -ceq $cfg['user'])) { return $false } }
        return $true
    } finally { Close-Control $ctl }
}

#
# MeshCentral control channel (control.ashx)
#

function Get-AuthError($m) {
    $cause = $m['cause']; $msg = $m['msg']
    if ($cause -eq 'banned') { return New-MtError 'the server is refusing logins from this IP address for a while, after too many failures' $EXIT_AUTH }
    if ($cause -eq 'notools') { return New-MtError 'this account is not allowed to use MeshCentral tools, ask the administrator' $EXIT_AUTH }
    if ($cause -eq 'emailvalidation') { return New-MtError 'this account must verify its email address first, log in to the web UI once' $EXIT_AUTH }
    if ($cause -eq 'expired') { return New-MtError 'the session expired, run: meshtunnel login' $EXIT_AUTH }
    if ($msg -eq 'tokenrequired') { return New-MtError 'a two-factor code is required' $EXIT_AUTH @{ twoFactor = $true; email2fa = ($m['email2fa'] -eq $true); sms2fa = ($m['sms2fa'] -eq $true); msg2fa = ($m['msg2fa'] -eq $true) } }
    $what = if ($msg) { $msg } else { $cause }
    return New-MtError ('authentication failed (' + $what + '): wrong credentials, or the login token was revoked or has expired; run: meshtunnel login') $EXIT_AUTH
}

function Connect-Control($cfg, [string]$User, [string]$Pass, $Token) {
    $ws = [MeshTunnel.WsConn]::Connect([string]$cfg['url'], (Get-Pin $cfg), ((Get-BasePath $cfg) + 'control.ashx' + (Get-KeyQuery $cfg)), (Get-MeshAuth $User $Pass $Token))
    $ctl = @{ ws = $ws; closeInfo = $null; userinfo = $null; serverinfo = $null; backlog = (New-Object System.Collections.ArrayList) }
    try { [void](Wait-Control $ctl { param($m) $m['action'] -eq 'userinfo' } 20000) } # Sent right after "serverinfo" once logged in
    catch { $ws.Destroy(); throw }
    return $ctl
}

function Wait-Control($ctl, [scriptblock]$Match, [int]$TimeoutMs = 20000) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ($true) {
        for ($i = 0; $i -lt $ctl.backlog.Count; $i++) {
            $m = $ctl.backlog[$i]
            if (& $Match $m) { $ctl.backlog.RemoveAt($i); return $m }
        }
        $left = [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds
        if ($left -le 0) { Fail 'the server did not answer in time' $EXIT_NOTFOUND }
        $msg = $ctl.ws.Read($left)
        if ($null -eq $msg) { continue }
        if ($msg.Kind -eq 'close') {
            if ($null -ne $ctl.closeInfo) { throw (Get-AuthError $ctl.closeInfo) }
            if ($ctl.ws.Error) { Fail ('connection lost: ' + $ctl.ws.Error) $EXIT_NOTFOUND }
            Fail 'the server closed the connection' $EXIT_NOTFOUND
        }
        if ($msg.Kind -ne 'text') { continue }
        $m = $null
        try { $m = [MeshTunnel.Json]::Parse($msg.Text) } catch { continue }
        if ($m -isnot [Collections.Hashtable]) { continue }
        switch -CaseSensitive ([string]$m['action']) {
            'close' { $ctl.closeInfo = $m }
            'serverinfo' { $ctl.serverinfo = $m['serverinfo'] }
            'userinfo' { $ctl.userinfo = $m['userinfo'] }
        }
        [void]$ctl.backlog.Add($m)
        while ($ctl.backlog.Count -gt 200) { $ctl.backlog.RemoveAt(0) }
    }
}

function Send-Control($ctl, $obj) { [void]$ctl.ws.SendText([MeshTunnel.Json]::Stringify($obj)) }
function Invoke-Control($ctl, $obj, [scriptblock]$Match, [int]$TimeoutMs = 20000) { Send-Control $ctl $obj; return (Wait-Control $ctl $Match $TimeoutMs) }
function Close-Control($ctl) { $ctl.ws.Close(1000); $ctl.ws.Destroy() }

#
# Devices
#

function Test-WindowsAgent($agent) { return ($agent -is [Collections.Hashtable]) -and (@(1, 2, 3, 4, 21, 22, 34, 42, 43) -contains [int]$agent['id']) }

# Same rule as meshTunnelSlug() in the web UI, slugify() in meshtunnel.js and meshtunnel.py: keep them in sync.
function ConvertTo-Slug([string]$Name) {
    $s = [string]$Name
    try { $s = $s.Normalize([Text.NormalizationForm]::FormKD) } catch { }
    $s = [regex]::Replace($s, '[\u0300-\u036f]', '').ToLowerInvariant()
    $s = [regex]::Replace($s, '[^a-z0-9._-]+', '-')
    $s = [regex]::Replace($s, '^[-.]+|[-.]+$', '')
    if ($s -eq '') { return 'device' }
    return $s
}

function Get-IdHex([string]$Id) {
    $b = $Id.Split('/')[-1].Replace('@', '+').Replace('$', '/')
    $b = [regex]::Replace($b, '[^A-Za-z0-9+/]', '')
    if (($b.Length % 4) -eq 1) { $b = $b.Substring(0, $b.Length - 1) }
    while (($b.Length % 4) -ne 0) { $b += '=' }
    try { return [BitConverter]::ToString([Convert]::FromBase64String($b)).Replace('-', '').ToLowerInvariant() } catch { return '' }
}

function Set-Handles($list) {
    $count = New-Object Collections.Hashtable ([StringComparer]::Ordinal)
    foreach ($d in $list) { $d.slug = ConvertTo-Slug $d.name; $count[$d.slug] = [int]$count[$d.slug] + 1 }
    foreach ($d in $list) {
        if ($count[$d.slug] -gt 1) { $h = Get-IdHex $d.id; $d.handle = $d.slug + '-' + $h.Substring(0, [Math]::Min(6, $h.Length)) } else { $d.handle = $d.slug }
    }
}

function Get-DeviceCacheFile { return Join-Path (Get-CacheDir) 'devices.json' }
function Get-CacheKey($cfg) {
    $sha = [Security.Cryptography.SHA256]::Create()
    return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$cfg['url'] + "`n" + [string]$cfg['user']))).Replace('-', '').ToLowerInvariant()
}

function Read-DeviceCache($cfg) {
    try {
        $c = [MeshTunnel.Json]::Parse([IO.File]::ReadAllText((Get-DeviceCacheFile)))
        if (($c -is [Collections.Hashtable]) -and ($c['key'] -ceq (Get-CacheKey $cfg)) -and ($c['devices'] -is [array])) { return , @($c['devices'] | Where-Object { $_ -is [Collections.Hashtable] }) }
    } catch { }
    return $null
}

function Save-DeviceCache($cfg, $list) {
    try {
        New-Dir (Get-CacheDir)
        Write-FileAtomic (Get-DeviceCacheFile) ([MeshTunnel.Json]::Stringify(@{ key = (Get-CacheKey $cfg); time = [long]([DateTime]::UtcNow - [DateTime]'1970-01-01').TotalMilliseconds; devices = $list }))
    } catch { }
}

function Get-Devices($cfg) {
    $ctl = Connect-Control $cfg $cfg['user'] $cfg['pass'] $null
    try {
        $meshes = Invoke-Control $ctl @{ action = 'meshes' } { param($m) $m['action'] -eq 'meshes' } 30000
        $nodes = Invoke-Control $ctl @{ action = 'nodes'; responseid = 'meshtunnel' } { param($m) ($m['action'] -eq 'nodes') -and ($m['responseid'] -eq 'meshtunnel') } 30000
    } finally { Close-Control $ctl }
    if (($null -ne $nodes['result']) -and ($nodes['result'] -ne 'ok')) { Fail ('the server refused the device list: ' + $nodes['result']) $EXIT_AUTH }
    $groups = New-Object Collections.Hashtable ([StringComparer]::Ordinal)
    foreach ($m in @($meshes['meshes'])) { if ($m -is [Collections.Hashtable]) { $groups[[string]$m['_id']] = [string]$m['name'] } }
    $list = New-Object System.Collections.ArrayList
    $byMesh = $nodes['nodes']
    if ($byMesh -is [Collections.Hashtable]) {
        foreach ($meshid in $byMesh.Keys) {
            foreach ($n in @($byMesh[$meshid])) {
                if (($n -isnot [Collections.Hashtable]) -or ($n['_id'] -isnot [string])) { continue }
                $name = if ($null -ne $n['name']) { [string]$n['name'] } else { $n['_id'] }
                $group = if ($groups.ContainsKey($meshid)) { $groups[$meshid] } else { '' }
                $conn = if ($null -ne $n['conn']) { [long]$n['conn'] } else { 0 }
                [void]$list.Add(@{ id = $n['_id']; name = $name; group = $group; os = [string]$n['osdesc']; conn = $conn; windows = (Test-WindowsAgent $n['agent']) })
            }
        }
    }
    Set-Handles $list
    $sorted = @($list | Sort-Object -Property @{ Expression = { $_.group } }, @{ Expression = { $_.name } })
    Save-DeviceCache $cfg $sorted
    return , $sorted
}

function Find-Device($list, [string]$Query) {
    $q = ([regex]::Replace($Query.Trim(), '\.mesh$', '', 'IgnoreCase')).ToLowerInvariant()
    $ambiguous = {
        param($m)
        $names = @($m | ForEach-Object { $_.handle + $(if ($_.group -ne '') { ' (' + $_.group + ')' } else { '' }) }) -join ', '
        Fail ('"' + $Query + '" matches ' + $m.Count + ' devices, use one of: ' + $names) $EXIT_NOTFOUND
    }
    $m = @($list | Where-Object { $_.handle -ceq $q })
    if ($m.Count -eq 1) { return $m[0] }
    $m = @($list | Where-Object { ([string]$_.name).ToLowerInvariant() -ceq $q })
    if ($m.Count -eq 1) { return $m[0] }
    if ($m.Count -gt 1) { & $ambiguous $m }
    $m = @($list | Where-Object { $_.slug -ceq $q })
    if ($m.Count -eq 1) { return $m[0] }
    if ($m.Count -gt 1) { & $ambiguous $m }
    return $null
}

function Get-Device($cfg, [string]$Query) {
    if (-not $Query) { Fail 'missing device: a handle from "meshtunnel ls", a device name or a node id' }
    if ($Query.StartsWith('node/')) {
        $cached = Read-DeviceCache $cfg
        if ($null -ne $cached) { foreach ($d in $cached) { if ($d['id'] -ceq $Query) { return $d } } }
        return @{ id = $Query; name = $Query; handle = $Query; group = ''; conn = 1; windows = $false }
    }
    $found = $null
    $cached = Read-DeviceCache $cfg
    if ($null -ne $cached) { $found = Find-Device $cached $Query }
    if ($null -eq $found) { $found = Find-Device (Get-Devices $cfg) $Query }
    if ($null -eq $found) { Fail ('no device matches "' + $Query + '", see: meshtunnel ls') $EXIT_NOTFOUND }
    return $found
}

#
# Relay sessions
#

# The server closes a relay it will not route without saying why: find the reason from the device list.
function Resolve-TunnelFailure($cfg, $dev, $e, [bool]$ForShell) {
    if ($null -ne $e.closeInfo) { return Get-AuthError $e.closeInfo }
    if (-not $e.relayEarly) { return New-MtError $e.message $e.code }
    $list = $null
    try { $list = Get-Devices $cfg } catch { $x = Get-MtError $_; if ($null -eq $x) { throw }; return New-MtError $x.message $x.code }
    $d = $null
    foreach ($x in $list) { if ($x.id -ceq $dev.id) { $d = $x } }
    if ($null -eq $d) { return New-MtError ($dev.name + ' is not visible to this account anymore (removed, or access was revoked)') $EXIT_NOTFOUND }
    if (($d.conn -band 1) -eq 0) { return New-MtError ($d.name + ' is offline: its agent is not connected to the server') $EXIT_NOTFOUND }
    if ($e.timedOut) { return New-MtError ($d.name + ' did not answer the tunnel request in time, try again') $EXIT_NOTFOUND }
    if ($ForShell) { return New-MtError ('the server refused the terminal on ' + $d.name + ': this account needs "Remote Control" without the "No Terminal" restriction') $EXIT_AUTH }
    return New-MtError ('the server refused the tunnel to ' + $d.name + ': this account needs "Remote Control" or "Relay" rights on it') $EXIT_AUTH
}

function ConvertTo-Port($Value, [string]$What = 'port') {
    $p = 0
    if ((-not [int]::TryParse(([string]$Value).Trim(), [ref]$p)) -or ($p -lt 1) -or ($p -gt 65535) -or ([string]$p -ne ([string]$Value).Trim())) { Fail ('invalid ' + $What + ': ' + $Value) }
    return $p
}

function ConvertTo-TargetHost($Value) {
    if ($null -eq $Value) { return $null }
    if ([string]$Value -cnotmatch '^[A-Za-z0-9.:_-]{1,253}$') { Fail ('invalid --to host: ' + $Value) }
    return [string]$Value
}

function Open-PortTunnel($cfg, $dev, [int]$Port, $ToHost) {
    try { return [MeshTunnel.Relay]::OpenPortTunnel([string]$cfg['url'], (Get-Pin $cfg), (Get-MeshAuth $cfg['user'] $cfg['pass'] $null), [string]$dev.id, $Port, [string]$ToHost) }
    catch { $e = Get-MtError $_; if ($null -eq $e) { throw }; throw (Resolve-TunnelFailure $cfg $dev $e $false) }
}

function Get-RefusedMessage($dev, [int]$Port, $ToHost) {
    $where = if ($ToHost) { $ToHost } else { '127.0.0.1' }
    $what = if ($Port -eq 22) { 'SSH server (sshd)' } else { 'service' }
    return 'nothing answered on ' + $where + ':' + $Port + ' of ' + $dev.name + ' (refused, or closed at once). Is the ' + $what + ' running there?'
}

#
# Prompts
#

function Test-Interactive { return (-not [Console]::IsInputRedirected) -and (-not [Console]::IsErrorRedirected) }

function Read-Prompt([string]$Question, [bool]$Secret = $false) {
    Write-Err $Question
    if ([Console]::IsInputRedirected) {
        $line = [Console]::In.ReadLine()
        if ($null -eq $line) { Fail 'aborted' }
        return $line
    }
    if ($Secret) { $ss = Read-Host -AsSecureString; return (New-Object Net.NetworkCredential('', $ss)).Password }
    return Read-Host
}

#
# Commands. Each one sets $script:ExitCode when it is not 0; errors are thrown.
#

function Invoke-Login($a) {
    if ($a._.Count -ne 1) { Fail 'usage: meshtunnel login <server-url> [--pin sha256//...] [--code CODE | --user name] [--expire-days N]' }
    $server = ConvertFrom-ServerUrl $a._[0]
    $previous = Read-Config $false
    $pin = if ($null -ne $a.flags['pin']) { ConvertTo-Pin $a.flags['pin'] } else { $null }
    $expireDays = 0
    if ($null -ne $a.flags['expire-days']) { if ((-not [int]::TryParse([string]$a.flags['expire-days'], [ref]$expireDays)) -or ($expireDays -lt 0)) { Fail 'invalid --expire-days' } }

    # Decide whether to trust the server before sending anything to it.
    $probe = [MeshTunnel.Tls]::Connect($server.url, [NullString]::Value, $true)
    $probe.Close()
    if (-not $probe.Authorized) {
        if ($null -ne $pin) {
            if ($pin -cne $probe.Fingerprint) { Fail ("the server certificate does not match --pin`n  --pin:  " + $pin + "`n  server: " + $probe.Fingerprint) $EXIT_TLS }
        } else {
            Write-Note ('the certificate of ' + ([Uri]$server.url).Authority + ' is not signed by a trusted authority (' + $probe.Reason + ')')
            Write-Note ('its public key fingerprint is ' + $probe.Fingerprint)
            if (-not (Test-Interactive)) { Fail ('not trusting it without confirmation; if that fingerprint is right, run again with --pin ' + $probe.Fingerprint) $EXIT_TLS }
            $answer = Read-Prompt 'Check it against the fingerprint shown in the web UI (Terminal tab > Local Terminal). Trust it (yes/no)? '
            if ($answer.Trim() -notmatch '^y(es)?$') { Fail 'aborted' $EXIT_TLS }
            $pin = $probe.Fingerprint
        }
    }

    $cfg = [ordered]@{ url = $server.url; loginkey = $server.loginkey; pin = $pin }
    if ($null -ne $a.flags['code']) {
        $r = Invoke-Redeem $cfg ([string]$a.flags['code']).Trim() $previous
        $cfg.user = $r['user']; $cfg.pass = $r['pass']; $cfg.tokenName = $r['name']; $cfg.createdToken = $true; $cfg.account = $r['account']
        Complete-Login $cfg $true
        return
    }
    $user = if ($null -ne $a.flags['user']) { [string]$a.flags['user'] } else { (Read-Prompt 'Username (or a ~t: login token): ').Trim() }
    if ($user -eq '') { Fail 'no username given' }
    $pass = Read-Prompt $(if ($user.StartsWith('~t:')) { 'Token password: ' } else { 'Password: ' }) $true

    if ($user.StartsWith('~t:')) {
        # A login token made in the web UI (My Account > Login Tokens), for accounts that use SSO or hardware keys.
        $ctl = Connect-Control $cfg $user $pass $null
        $account = if (($ctl.userinfo -is [Collections.Hashtable]) -and $ctl.userinfo['name']) { $ctl.userinfo['name'] } else { $null }
        Close-Control $ctl
        $cfg.user = $user; $cfg.pass = $pass; $cfg.account = $account
        Complete-Login $cfg $false
        return
    }
    $token = $null; $ctl = $null
    for ($attempt = 0; ; $attempt++) {
        try { $ctl = Connect-Control $cfg $user $pass $token; break }
        catch {
            $e = Get-MtError $_
            if (($null -eq $e) -or ($e.data['twoFactor'] -ne $true) -or ($attempt -ge 5)) { throw }
            if (-not (Test-Interactive)) { Fail 'this account uses two-factor authentication: log in from a terminal, or use a setup code from the web UI (Terminal tab > Local Terminal)' $EXIT_AUTH }
            $ways = @()
            if ($e.data['email2fa']) { $ways += '"email"' }
            if ($e.data['sms2fa']) { $ways += '"sms"' }
            if ($e.data['msg2fa']) { $ways += '"msg"' }
            $hint = if ($ways.Count -gt 0) { ' (or ' + ($ways -join ', ') + ' to receive one)' } else { '' }
            $code = (Read-Prompt ('Two-factor code' + $hint + ': ')).Trim()
            $token = switch ($code.ToLowerInvariant()) { 'email' { '**email**' } 'sms' { '**sms**' } 'msg' { '**msg**' } default { $code } }
        }
    }
    $account = if (($ctl.userinfo -is [Collections.Hashtable]) -and $ctl.userinfo['name']) { $ctl.userinfo['name'] } else { $user }
    $tokenName = 'meshtunnel@' + [Environment]::MachineName.ToLowerInvariant()
    try {
        $r = Invoke-Control $ctl @{ action = 'createLoginToken'; name = $tokenName; expire = ($expireDays * 1440); responseid = 'meshtunnel' } { param($m) $m['action'] -eq 'createLoginToken' } 20000
        # Logging in again replaces the token this tool made before: revoke that one rather than leave it valid and forgotten.
        if ($r['tokenUser'] -and ($null -ne $previous) -and ($previous['createdToken'] -eq $true) -and ($previous['url'] -ceq $cfg.url) -and ($previous['user'] -is [string]) -and ($previous['user'] -cne $r['tokenUser'])) {
            try { [void](Invoke-Control $ctl @{ action = 'loginTokens'; remove = @($previous['user']) } { param($m) $m['action'] -eq 'loginTokens' } 10000) } catch { }
        }
    } finally { Close-Control $ctl }
    if ((-not $r['tokenUser']) -or (-not $r['tokenPass'])) {
        $why = if ($r['result']) { $r['result'] } else { 'no reason given' }
        Fail ('the server refused to create a login token (' + $why + '). An administrator can allow them (domains > passwordRequirements > loginTokens); a setup code from the web UI or an existing token from My Account > Login Tokens also works.') $EXIT_AUTH
    }
    $cfg.user = $r['tokenUser']; $cfg.pass = $r['tokenPass']; $cfg.tokenName = $tokenName; $cfg.createdToken = $true; $cfg.account = $account
    Complete-Login $cfg $false
}

function Complete-Login($cfg, [bool]$Quiet) {
    $file = Save-Config $cfg
    $devices = Get-Devices $cfg
    $online = @($devices | Where-Object { ($_.conn -band 1) -ne 0 }).Count
    $who = if ($cfg.account) { $cfg.account } else { 'token user' }
    Write-Err ('Logged in to ' + $cfg.url + ' as ' + $who + ', ' + $devices.Count + ' device(s), ' + $online + " online.`n")
    $what = if ($cfg.createdToken) { 'login token "' + $cfg.tokenName + '"' } else { 'login token' }
    $how = if ($cfg.createdToken) { ' or with: meshtunnel logout' } else { '' }
    Write-Err ('The ' + $what + ' is stored in ' + $file + ', revoke it any time in My Account > Login Tokens' + $how + ".`n")
    if ((-not $Quiet) -and (-not [IO.File]::Exists((Join-Path (Join-Path (Get-HomeDir) '.ssh') 'meshtunnel.conf')))) { Write-Err "Next: meshtunnel ssh-config --install   (then: ssh <user>@<device>.mesh)`n" }
}

function Invoke-Logout($a) {
    $cfg = Read-Config $false
    if ($null -eq $cfg) { Write-Note 'not logged in'; return }
    $revoked = $false
    if ($cfg['createdToken'] -eq $true) {
        try { $revoked = Invoke-RevokeStored $cfg } catch { $e = Get-MtError $_; if ($null -eq $e) { throw }; Write-Note ('could not revoke the login token on the server: ' + $e.message) }
    }
    foreach ($f in @((Get-ConfigFile), (Get-DeviceCacheFile))) { try { [IO.File]::Delete($f) } catch { } }
    if ($revoked) { Write-Note ('logged out, login token "' + $cfg['tokenName'] + '" revoked') }
    elseif ($cfg['tokenName']) { Write-Note ('logged out on this computer, revoke login token "' + $cfg['tokenName'] + '" in My Account > Login Tokens') }
    else { Write-Note 'logged out on this computer' }
}

function Invoke-Ls($a) {
    $cfg = Read-Config $true
    $list = Get-Devices $cfg
    if ($a._.Count -gt 0) {
        $f = ($a._ -join ' ').ToLowerInvariant()
        $list = @($list | Where-Object { $_.handle.Contains($f) -or ([string]$_.name).ToLowerInvariant().Contains($f) -or ([string]$_.group).ToLowerInvariant().Contains($f) })
    }
    if ($a.flags['json']) {
        $out = @($list | ForEach-Object { [ordered]@{ handle = $_.handle; name = $_.name; group = $_.group; os = $_.os; online = (($_.conn -band 1) -ne 0); id = $_.id } })
        Write-Out ([MeshTunnel.Json]::Pretty($out) + "`n")
        return
    }
    $rows = New-Object System.Collections.ArrayList
    [void]$rows.Add(@('HANDLE', 'NAME', 'GROUP', 'OS', 'STATE'))
    foreach ($d in $list) { [void]$rows.Add(@([string]$d.handle, [string]$d.name, [string]$d.group, [string]$d.os, $(if (($d.conn -band 1) -ne 0) { 'online' } else { 'offline' }))) }
    $widths = @(0, 0, 0, 0)
    foreach ($r in $rows) { for ($i = 0; $i -lt 4; $i++) { $widths[$i] = [Math]::Min([Math]::Max($widths[$i], $r[$i].Length), 40) } }
    $sb = New-Object Text.StringBuilder
    foreach ($r in $rows) {
        for ($i = 0; $i -lt 4; $i++) {
            $c = $r[$i]
            if ($c.Length -gt 40) { $c = $c.Substring(0, 39) + '~' }
            [void]$sb.Append($c).Append(' ', $widths[$i] - $c.Length + 2)
        }
        [void]$sb.Append($r[4]).Append("`n")
    }
    Write-Out $sb.ToString()
    if ($list.Count -eq 0) { Write-Note 'no devices' }
}

function Invoke-Proxy($a) {
    if (($a._.Count -lt 1) -or ($a._.Count -gt 2)) { Fail 'usage: meshtunnel proxy <device> [port] [--to host]' }
    $cfg = Read-Config $true
    $port = ConvertTo-Port $(if ($a._.Count -gt 1) { $a._[1] } else { '22' })
    $to = ConvertTo-TargetHost $a.flags['to']
    $dev = Get-Device $cfg $a._[0]
    $ws = Open-PortTunnel $cfg $dev $port $to
    $started = [Diagnostics.Stopwatch]::StartNew()
    $r = [MeshTunnel.Relay]::Proxy($ws)
    if ($null -ne $ws.Error) { Write-Note ('connection lost: ' + $ws.Error); $script:ExitCode = $EXIT_NOTFOUND; return }
    if (($r[0] -eq 0) -and ($r[1] -eq 0) -and ($started.ElapsedMilliseconds -lt 15000)) { Write-Note (Get-RefusedMessage $dev $port $to); $script:ExitCode = $EXIT_REFUSED }
}

function Invoke-Forward($a) {
    if ($a._.Count -ne 3) { Fail 'usage: meshtunnel forward <local-port> <device> <remote-port> [--bind address] [--to host]' }
    $cfg = Read-Config $true
    $lport = if ($a._[0] -eq '0') { 0 } else { ConvertTo-Port $a._[0] 'local port' }
    $rport = ConvertTo-Port $a._[2] 'remote port'
    $bind = if ($null -ne $a.flags['bind']) { [string]$a.flags['bind'] } else { '127.0.0.1' }
    $to = ConvertTo-TargetHost $a.flags['to']
    $list = Get-Devices $cfg # Also proves the login still works before listening
    $dev = Find-Device $list $a._[1]
    if ($null -eq $dev) {
        if (([string]$a._[1]).StartsWith('node/')) { $dev = @{ id = [string]$a._[1]; name = [string]$a._[1]; conn = 1 } }
        else { Fail ('no device matches "' + $a._[1] + '", see: meshtunnel ls') $EXIT_NOTFOUND }
    }
    if (($dev.conn -band 1) -eq 0) { Write-Note ('warning: ' + $dev.name + ' is offline right now, connections will fail until its agent is back') }
    $target = $dev.name + ':' + $(if ($to) { $to + ':' } else { '' }) + $rport
    $toArg = if ($to) { $to } else { [NullString]::Value }
    $fwd = [MeshTunnel.Forwarder]::new([string]$cfg['url'], (Get-Pin $cfg), (Get-MeshAuth $cfg['user'] $cfg['pass'] $null), [string]$dev.id, $rport, $toArg, $bind, $lport)
    try { $fwd.Start() } catch { Fail ('cannot listen on ' + $bind + ':' + $lport + ': ' + $_.Exception.GetBaseException().Message) }
    Write-Note ('forwarding ' + $bind + ':' + $fwd.Port + ' -> ' + $target + ', press Ctrl-C to stop')
    try {
        while (-not $fwd.Stopped) {
            $n = $fwd.TakeNote()
            if ($null -eq $n) { Start-Sleep -Milliseconds 200; continue }
            $kind = $n[0]; $label = $n[1]
            if ($kind -eq 'refused') { Write-Note ($label + ': ' + (Get-RefusedMessage $dev $rport $to)); continue }
            $e = @{ message = $n[2]; code = [int]$n[3]; relayEarly = ($kind -eq 'early'); timedOut = ($n[4] -eq '1'); closeInfo = $null }
            $err = Resolve-TunnelFailure $cfg $dev $e $false
            Write-Note ($label + ': ' + $err.Message)
            if ([int]$err.Data['mtcode'] -eq $EXIT_AUTH) { Write-Note 'stopping, the server no longer accepts this login or refuses this tunnel'; $fwd.Stop($EXIT_AUTH) }
        }
        $script:ExitCode = $fwd.StopCode
    } finally { if (-not $fwd.Stopped) { $fwd.Stop(0) } }
}

function Invoke-Shell($a) {
    $hold = ($a.flags['hold-on-error'] -eq $true)
    try { $code = Start-ShellSession $a }
    catch {
        if ((-not $hold) -or (-not (Test-Interactive))) { throw }
        # Opened from a meshtunnel:// link: keep the error on screen instead of closing the window at once.
        $e = Get-MtError $_
        Write-Note $(if ($null -ne $e) { $e.message } else { $_.Exception.GetBaseException().Message })
        Wait-Window
        $script:ExitCode = $(if ($null -ne $e) { $e.code } else { $EXIT_USAGE })
        return
    }
    if ($hold -and ($code -ne 0) -and (Test-Interactive)) { Wait-Window }
    $script:ExitCode = $code
}

function Wait-Window { Write-Err 'Press Enter to close this window.'; try { [void][Console]::In.ReadLine() } catch { } }

function Start-ShellSession($a) {
    if ($a._.Count -ne 1) { Fail 'usage: meshtunnel shell <device> [--user] [--powershell] [--login]' }
    $cfg = Read-Config $true
    $dev = Get-Device $cfg $a._[0]
    $protocol = 1
    if ($a.flags['powershell']) { $protocol = if ($a.flags['user']) { 9 } else { 6 } } elseif ($a.flags['user']) { $protocol = 8 }
    $base = Get-BasePath $cfg
    $ctl = Connect-Control $cfg $cfg['user'] $cfg['pass'] $null
    try {
        $cookie = Invoke-Control $ctl @{ action = 'authcookie' } { param($m) $m['action'] -eq 'authcookie' } 20000
        $rid = [Guid]::NewGuid().ToString('n').Substring(0, 16)
        $node = [Uri]::EscapeDataString([string]$dev.id)
        Send-Control $ctl @{ action = 'msg'; type = 'tunnel'; nodeid = [string]$dev.id; usage = $protocol; responseid = 'meshtunnel'; value = ('*' + $base + 'meshrelay.ashx?p=' + $protocol + '&nodeid=' + $node + '&id=' + $rid + '&rauth=' + [Uri]::EscapeDataString([string]$cookie['rcookie'])) }
        $ws = [MeshTunnel.WsConn]::Connect([string]$cfg['url'], (Get-Pin $cfg), ($base + 'meshrelay.ashx?browser=1&p=' + $protocol + '&nodeid=' + $node + '&id=' + $rid), (Get-MeshAuth $cfg['user'] $cfg['pass'] $null))
        # The server answers "OK" right away and "Unable to route" once its rights check fails: only a failure counts.
        try { $ws.WaitRelayStart(20000, $ctl.ws) }
        catch { $e = Get-MtError $_; if ($null -eq $e) { throw }; throw (Resolve-TunnelFailure $cfg $dev $e $true) }
        return [MeshTunnel.Relay]::Terminal($ws, $ctl.ws, $protocol, ($a.flags['login'] -eq $true), [string]$dev.name)
    } finally { Close-Control $ctl }
}

function Get-SshDir { return Join-Path (Get-HomeDir) '.ssh' }

function Get-SshConfigText {
    $quote = { param($p) if ($p.Contains('"')) { Fail ('cannot write an ssh config for a path containing a double quote: ' + $p) }; '"' + $p.Replace('%', '%%') + '"' }
    $exe = (Get-Process -Id $PID).Path
    $lines = @(
        '# meshtunnel: reach MeshCentral devices as <device>.mesh (ssh, scp, sftp), through the server "meshtunnel login" chose.',
        '# Written by "meshtunnel ssh-config"; run it again if PowerShell or meshtunnel moves.',
        'Host *.mesh',
        ('    ProxyCommand ' + (& $quote $exe) + ' -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + (& $quote $ScriptFile) + ' proxy %n %p'),
        '    ServerAliveInterval 30',
        '    ServerAliveCountMax 3'
    )
    # Reuse one tunnel for later connections to the same device (not supported by the Windows ssh client).
    if (-not $IsWin) { $lines += @('    ControlMaster auto', '    ControlPath ~/.ssh/meshtunnel-%C', '    ControlPersist 10m') }
    return ($lines -join "`n") + "`n"
}

$IncludePattern = '^\s*Include\s+("?)(~/\.ssh/)?meshtunnel\.conf\1\s*$'

function Invoke-SshConfig($a) {
    $text = Get-SshConfigText
    if ($a.flags['install'] -ne $true) { Write-Out $text; return }
    $dir = Get-SshDir
    New-Dir $dir
    $conf = Join-Path $dir 'meshtunnel.conf'
    Write-FileAtomic $conf $text
    # Include it from the TOP of ~/.ssh/config: an Include placed after a Host line would only apply to that host.
    $main = Join-Path $dir 'config'
    $current = ''
    if ([IO.File]::Exists($main)) { $current = [IO.File]::ReadAllText($main) }
    if ($current -notmatch ('(?mi)' + $IncludePattern)) {
        $new = 'Include meshtunnel.conf' + "`n" + $(if ($current.Length -gt 0) { "`n" + $current } else { '' })
        Write-FileAtomic $main $new
        Write-Note ('added "Include meshtunnel.conf" at the top of ' + $main)
    }
    Write-Note ('wrote ' + $conf)
    $ex = "  ssh root@web01.mesh`n  scp .\file.txt root@web01.mesh:/tmp/`n"
    if (-not $IsWin) { $ex = "  ssh root@web01.mesh`n  scp ./file.txt root@web01.mesh:/tmp/`n  rsync -avz ./folder/ root@web01.mesh:/srv/folder/`n" }
    Write-Err ("Now use devices as <handle>.mesh (handles are listed by ""meshtunnel ls""), e.g.:`n" + $ex)
}

# Remove what "ssh-config --install" added: meshtunnel.conf and its Include line (with the blank line written after it).
function Remove-SshConfig {
    $dir = Get-SshDir
    $conf = Join-Path $dir 'meshtunnel.conf'
    if ([IO.File]::Exists($conf)) { [IO.File]::Delete($conf); Write-Note ('removed ' + $conf) }
    $main = Join-Path $dir 'config'
    if (-not [IO.File]::Exists($main)) { return }
    $lines = [IO.File]::ReadAllText($main).Split("`n")
    $isInclude = { param($l) $l.TrimEnd("`r") -match ('(?i)' + $IncludePattern) }
    if (($lines.Count -gt 1) -and (& $isInclude $lines[0]) -and ($lines[1].TrimEnd("`r") -eq '')) { $kept = @($lines | Select-Object -Skip 2) }
    else { $kept = @($lines | Where-Object { -not (& $isInclude $_) }) }
    if ($kept.Count -ne $lines.Count) { Write-FileAtomic $main ($kept -join "`n"); Write-Note ('removed "Include meshtunnel.conf" from ' + $main) }
}

#
# meshtunnel:// links from the web UI ("Open in my terminal"), Windows only
#

$HandlerKey = 'HKCU:\Software\Classes\meshtunnel'

function Invoke-InstallHandler($a) {
    if (-not $IsWin) { Fail 'with the PowerShell client, "Open in my terminal" links work on Windows only; on Linux use the Python or Node.js client' }
    $exe = (Get-Process -Id $PID).Path
    $cmd = '"' + $exe + '" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $ScriptFile + '" open "%1"'
    [void](New-Item -Path $HandlerKey -Force)
    Set-ItemProperty -Path $HandlerKey -Name '(default)' -Value 'URL:meshtunnel'
    Set-ItemProperty -Path $HandlerKey -Name 'URL Protocol' -Value ''
    [void](New-Item -Path ($HandlerKey + '\shell\open\command') -Force)
    Set-ItemProperty -Path ($HandlerKey + '\shell\open\command') -Name '(default)' -Value $cmd
    $wt = Get-Command 'wt.exe' -ErrorAction SilentlyContinue
    Write-Note ('meshtunnel:// links now open in ' + $(if ($wt) { 'Windows Terminal' } else { 'a console window' }))
}

function Invoke-UninstallHandler($a) {
    if ($IsWin -and (Test-Path $HandlerKey)) { Remove-Item -Path $HandlerKey -Recurse -Force; Write-Note 'meshtunnel:// handler removed' }
}

function Write-HandlerFailure([string]$Message) {
    Write-Note $Message
    try { New-Dir (Get-CacheDir); [IO.File]::AppendAllText((Join-Path (Get-CacheDir) 'handler.log'), [DateTime]::UtcNow.ToString('o') + ' ' + $Message + "`n") } catch { }
}

function ConvertTo-CmdArg([string]$s) { if ($s -match '[\s"]') { return '"' + $s.Replace('"', '\"') + '"' } return $s }

function Invoke-Open($a) {
    try {
        if ($a._.Count -ne 1) { Fail 'usage: meshtunnel open <meshtunnel://...>' }
        $u = $null
        if ((-not [Uri]::TryCreate([string]$a._[0], [UriKind]::Absolute, [ref]$u)) -or ($u.Scheme -ne 'meshtunnel')) { Fail 'not a meshtunnel:// link' }
        $q = @{}
        foreach ($pair in $u.Query.TrimStart('?').Split('&')) { $kv = $pair.Split(@('='), 2, [StringSplitOptions]::None); if ($kv.Count -eq 2) { $q[[Uri]::UnescapeDataString($kv[0])] = [Uri]::UnescapeDataString($kv[1].Replace('+', ' ')) } }
        $cfg = Read-Config $false
        $server = [string]$q['s']
        if ($null -eq $cfg) { Fail ('meshtunnel is not logged in on this computer, run: meshtunnel login ' + $server) }
        # The link comes from a web page: never let it point the stored credentials at another server.
        $target = $null
        try { $target = (ConvertFrom-ServerUrl $server).url } catch { }
        if ($target -cne $cfg['url']) { Fail ('refusing a link for ' + $server + ': meshtunnel is logged in to ' + $cfg['url']) }
        $nodeid = [string]$q['n']
        if ($nodeid -cnotmatch '^node/[A-Za-z0-9._-]*/[A-Za-z0-9@$]+$') { Fail 'the link has an invalid device id' }
        $protocol = 0
        if ((-not [int]::TryParse([string]$q['p'], [ref]$protocol)) -or ($TerminalProtocols -notcontains $protocol)) { Fail 'the link asks for an unknown shell type' }
        $title = [regex]::Replace([string]$q['t'], '[^A-Za-z0-9 ._-]', '')
        if ($title.Length -gt 60) { $title = $title.Substring(0, 60) }
        if ($title -eq '') { $title = 'meshtunnel' }
        $exe = (Get-Process -Id $PID).Path
        $cmdArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptFile, 'shell', $nodeid)
        if (($protocol -eq 8) -or ($protocol -eq 9)) { $cmdArgs += '--user' }
        if (($protocol -eq 6) -or ($protocol -eq 9)) { $cmdArgs += '--powershell' }
        if ($q['l'] -eq '1') { $cmdArgs += '--login' }
        $cmdArgs += '--hold-on-error'
        if (-not $IsWin) { Fail 'with the PowerShell client, "Open in my terminal" links work on Windows only' }
        $wt = Get-Command 'wt.exe' -ErrorAction SilentlyContinue
        if ($wt) { Start-Process -FilePath $wt.Source -ArgumentList (@('-w', '0', 'new-tab', '--title', (ConvertTo-CmdArg $title), (ConvertTo-CmdArg $exe)) + @($cmdArgs | ForEach-Object { ConvertTo-CmdArg $_ })) }
        else { Start-Process -FilePath $exe -ArgumentList @($cmdArgs | ForEach-Object { ConvertTo-CmdArg $_ }) }
    } catch {
        $e = Get-MtError $_
        Write-HandlerFailure $(if ($null -ne $e) { $e.message } else { $_.Exception.GetBaseException().Message })
        $script:ExitCode = $(if ($null -ne $e) { $e.code } else { $EXIT_USAGE })
    }
}

function Invoke-Update($a) {
    $cfg = Read-Config $true
    $r = Invoke-MtRequest $cfg 'GET' ((Get-BasePath $cfg) + 'meshtunnel.ps1' + (Get-KeyQuery $cfg)) $null
    if ($r.Status -ne 200) { Fail ('the server answered ' + $r.StatusLine + ' for meshtunnel.ps1') $EXIT_NOTFOUND }
    $text = [Text.Encoding]::UTF8.GetString($r.Body)
    if ($text -cnotmatch '(?m)^\$VERSION = ''([^'']+)''') { Fail 'the server did not send a meshtunnel script' $EXIT_NOTFOUND }
    $newVersion = $Matches[1]
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
    if (($null -ne $errors) -and ($errors.Count -gt 0)) { Fail 'the downloaded script does not parse, keeping the current one' }
    Write-FileAtomic $ScriptFile $text '755' $true
    if ($newVersion -ceq $VERSION) { Write-Note ('already up to date (' + $VERSION + ')') } else { Write-Note ('updated from ' + $VERSION + ' to ' + $newVersion) }
}

function Get-UserPath { $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment'); try { return [string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } finally { $k.Close() } }

# Remove a folder from the user's PATH (the setup command added its bin folder), keeping the value's registry type.
function Remove-UserPath([string]$Dir) {
    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    try {
        $old = [string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $parts = @($old.Split(';') | Where-Object { ($_ -ne '') -and ($_.TrimEnd('\') -ne $Dir.TrimEnd('\')) })
        if ($parts.Count -eq @($old.Split(';') | Where-Object { $_ -ne '' }).Count) { return $false }
        $k.SetValue('Path', ($parts -join ';'), $k.GetValueKind('Path'))
    } finally { $k.Close() }
    [Environment]::SetEnvironmentVariable('MESHTUNNEL_PATH_REFRESH', [NullString]::Value, 'User') # Tells running programs that the environment changed
    return $true
}

# Undo the setup on this computer: revoke the login token, remove the ssh config, the link handler, the settings, and
# the copy of meshtunnel the setup command installed (a copy run from anywhere else is left alone).
function Invoke-Uninstall($a) {
    $cfg = Read-Config $false
    if (($null -ne $cfg) -and ($cfg['createdToken'] -eq $true)) {
        try {
            if (Invoke-RevokeStored $cfg) { Write-Note ('login token "' + $cfg['tokenName'] + '" revoked') } else { Write-Note ('revoke login token "' + $cfg['tokenName'] + '" in My Account > Login Tokens') }
        } catch { $e = Get-MtError $_; $m = if ($null -ne $e) { $e.message } else { $_.Exception.Message }; Write-Note ('could not revoke the login token on the server (' + $m + '), revoke "' + $cfg['tokenName'] + '" in My Account > Login Tokens') }
    }
    Invoke-UninstallHandler $a
    Remove-SshConfig
    foreach ($f in @((Get-ConfigFile), (Get-DeviceCacheFile), (Join-Path (Get-CacheDir) 'handler.log'))) { try { [IO.File]::Delete($f) } catch { } }
    try { [IO.Directory]::Delete([IO.Path]::GetDirectoryName((Get-ConfigFile))) } catch { } # Only if empty
    $dir = Get-InstallDir
    if ([IO.Path]::GetDirectoryName($ScriptFile) -eq $dir) {
        if ($IsWin) {
            if (Remove-UserPath (Join-Path $dir 'bin')) { Write-Note ('removed ' + (Join-Path $dir 'bin') + ' from your PATH') }
            # This process has files of that folder open (the engine): delete it right after exiting.
            Start-Process -FilePath ($env:ComSpec) -ArgumentList @('/d', '/c', 'ping -n 3 127.0.0.1 >nul & rmdir /s /q "' + $dir + '"') -WindowStyle Hidden
            Write-Note ('removing ' + $dir)
        } else {
            $wrapper = Join-Path (Get-HomeDir) '.local/bin/meshtunnel'
            if ([IO.File]::Exists($wrapper) -and ([IO.File]::ReadAllText($wrapper).Contains($ScriptFile))) { [IO.File]::Delete($wrapper); Write-Note ('removed ' + $wrapper) }
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Note ('removed ' + $dir)
        }
        $engine = Join-Path (Get-CacheDir) 'engine'
        if ((-not $IsWin) -and [IO.Directory]::Exists($engine)) { Remove-Item -LiteralPath $engine -Recurse -Force -ErrorAction SilentlyContinue }
    } else { Write-Note ('left ' + $ScriptFile + ' in place, it was not installed by the setup command') }
    try { [IO.Directory]::Delete((Get-CacheDir)) } catch { }
    Write-Note 'meshtunnel is uninstalled from this computer'
}

#
# Command line
#

$HELP = @"
meshtunnel $VERSION (PowerShell): your own terminal and ssh for MeshCentral devices

Setup (once per computer; the web UI gives a one-line setup command in the Terminal tab > Local Terminal)
  login <server-url> [--pin sha256//...] [--code CODE | --user NAME] [--expire-days N]
                      Sign in with a setup code from the web UI, or with your password.
                      Stores a revocable login token, never your password
  ssh-config [--install]
                      Print, or install into ~/.ssh, the config that makes <device>.mesh hosts work
  install-handler     Let the web UI's "Open in my terminal" button open your terminal (Windows)
  uninstall-handler   Remove that link handler
  logout              Revoke the stored login token and forget the server
  uninstall           Undo the setup: revoke the token, remove the ssh config, the link handler and this tool
  update              Replace this script with the version served by the server

Devices
  ls [filter] [--json]
                      List devices with the handle to use in commands
  shell <device> [--user] [--powershell] [--login]
                      The agent's own shell in this terminal, no SSH server needed; ~. disconnects
  forward <local-port> <device> <remote-port> [--bind ADDRESS] [--to HOST]
                      Forward a local port to a port of the device, or of HOST in its network
  proxy <device> [port] [--to HOST]
                      Relay stdin/stdout to a port of the device (the ssh ProxyCommand)

Examples
  ssh root@web01.mesh                            SSH (VS Code Remote-SSH and sftp use web01.mesh too)
  scp .\app.zip root@web01.mesh:/tmp/            copy a file to the device
  scp root@web01.mesh:/var/log/syslog .          copy a file from the device
  ssh -D 1080 -N root@web01.mesh                 SOCKS proxy into the device's network
  meshtunnel shell web01                         the agent's own shell, no SSH server needed
  meshtunnel forward 13389 win01 3389            then connect Remote Desktop to localhost:13389

A device is a handle from "meshtunnel ls", its exact name, or its node id.
Exit codes: 0 ok, 1 usage, 2 login or rights, 3 device not found or offline, 4 nothing listening on the device port, 5 certificate problem.

"@

$COMMANDS = @{
    'login' = @{ spec = @{ 'pin' = 'value'; 'user' = 'value'; 'expire-days' = 'value'; 'code' = 'value' }; run = ${function:Invoke-Login} }
    'logout' = @{ spec = @{}; run = ${function:Invoke-Logout} }
    'uninstall' = @{ spec = @{}; run = ${function:Invoke-Uninstall} }
    'ls' = @{ spec = @{ 'json' = 'bool' }; run = ${function:Invoke-Ls} }
    'proxy' = @{ spec = @{ 'to' = 'value' }; run = ${function:Invoke-Proxy} }
    'forward' = @{ spec = @{ 'bind' = 'value'; 'to' = 'value' }; run = ${function:Invoke-Forward} }
    'shell' = @{ spec = @{ 'user' = 'bool'; 'powershell' = 'bool'; 'login' = 'bool'; 'hold-on-error' = 'bool' }; run = ${function:Invoke-Shell} }
    'ssh-config' = @{ spec = @{ 'install' = 'bool' }; run = ${function:Invoke-SshConfig} }
    'install-handler' = @{ spec = @{}; run = ${function:Invoke-InstallHandler} }
    'uninstall-handler' = @{ spec = @{}; run = ${function:Invoke-UninstallHandler} }
    'open' = @{ spec = @{}; run = ${function:Invoke-Open} }
    'update' = @{ spec = @{}; run = ${function:Invoke-Update} }
}

function ConvertFrom-Args($Argv, $Spec) {
    $Argv = @($Argv)
    $out = @{ _ = (New-Object System.Collections.ArrayList); flags = @{} }
    for ($i = 0; $i -lt $Argv.Count; $i++) {
        $arg = [string]$Argv[$i]
        if ($arg -ceq '--') { for ($j = $i + 1; $j -lt $Argv.Count; $j++) { [void]$out._.Add([string]$Argv[$j]) }; break }
        if ($arg.StartsWith('--')) {
            $name = $arg.Substring(2); $value = $null
            $eq = $name.IndexOf('=')
            if ($eq -ge 0) { $value = $name.Substring($eq + 1); $name = $name.Substring(0, $eq) }
            if (-not $Spec.ContainsKey($name)) { Fail ('unknown option --' + $name + ', see: meshtunnel help') }
            if ($Spec[$name] -eq 'bool') {
                if ($null -ne $value) { Fail ('--' + $name + ' takes no value') }
                $out.flags[$name] = $true
            } else {
                if ($null -eq $value) {
                    if (($i + 1) -ge $Argv.Count) { Fail ('--' + $name + ' needs a value') }
                    $i++
                    $value = [string]$Argv[$i]
                }
                $out.flags[$name] = $value
            }
        } elseif (($arg.Length -gt 1) -and $arg.StartsWith('-')) { Fail ('unknown option ' + $arg + ', see: meshtunnel help') }
        else { [void]$out._.Add($arg) }
    }
    return $out
}

# Compile the engine once (per engine version and PowerShell edition) and load it from the cache afterwards.
function Import-Engine {
    if ('MeshTunnel.Relay' -as [type]) { return }
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { Fail 'PowerShell runs in Constrained Language Mode on this computer (a security policy), so the PowerShell client cannot work here: use the Node.js client instead (the Local Terminal dialog of the web UI has its setup command)' }
    $sha = [Security.Cryptography.SHA256]::Create()
    $id = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($EngineSource + '|' + $PSVersionTable.PSVersion + '|' + $PSVersionTable.PSEdition))).Replace('-', '').Substring(0, 16).ToLowerInvariant()
    $dir = Join-Path (Get-CacheDir) 'engine'
    $dll = Join-Path $dir ('engine-' + $id + '.dll')
    if (-not [IO.File]::Exists($dll)) {
        New-Dir (Get-CacheDir)
        New-Dir $dir
        $mutex = [Threading.Mutex]::new($false, ('meshtunnel-engine-' + $id))
        try {
            try { [void]$mutex.WaitOne(120000) } catch [Threading.AbandonedMutexException] { }
            if (-not [IO.File]::Exists($dll)) {
                Add-Type -TypeDefinition $EngineSource -OutputAssembly $dll -OutputType Library -IgnoreWarnings
                foreach ($old in [IO.Directory]::GetFiles($dir, 'engine-*.dll')) { if ($old -ne $dll) { try { [IO.File]::Delete($old) } catch { } } }
            }
        } finally { try { $mutex.ReleaseMutex() } catch { }; $mutex.Dispose() }
    }
    if (-not ('MeshTunnel.Relay' -as [type])) { Add-Type -Path $dll }
    [MeshTunnel.Tls]::UserAgent = 'meshtunnel/' + $VERSION + ' (powershell)'
}

function Invoke-Main($Argv) {
    $Argv = @($Argv)
    $cmd = if ($Argv.Count -gt 0) { [string]$Argv[0] } else { $null }
    if (($null -eq $cmd) -or (@('help', '--help', '-h', '-?', '/?') -contains $cmd)) { Write-Out $HELP; return }
    if (@('version', '--version') -contains $cmd) { Write-Out ('meshtunnel ' + $VERSION + "`n"); return }
    $c = $COMMANDS[$cmd]
    if ($null -eq $c) { Fail ('unknown command "' + $cmd + '", see: meshtunnel help') }
    $spec = @{ 'help' = 'bool' }
    foreach ($k in $c.spec.Keys) { $spec[$k] = $c.spec[$k] }
    $a = ConvertFrom-Args @($Argv | Select-Object -Skip 1) $spec
    if ($a.flags['help']) { Write-Out $HELP; return }
    Import-Engine
    & $c.run $a
}

#
# The engine (C# 5, compiled by Import-Engine)
#

$EngineSource = @'
// meshtunnel engine: TLS with key pinning, an RFC 6455 WebSocket client, the relay pumps and the Windows console.
// C# 5 on purpose: Windows PowerShell 5.1 compiles it with the .NET Framework compiler; PowerShell 7 with Roslyn.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace MeshTunnel
{
    public static class Exit { public const int OK = 0, USAGE = 1, AUTH = 2, NOTFOUND = 3, REFUSED = 4, TLS = 5; }

    public class MtException : Exception
    {
        public int Code;
        public bool RelayEarly;
        public bool TimedOut;
        public Hashtable CloseInfo; // The {"action":"close"} message the server sent before closing, if any
        public MtException(string message, int code) : base(message) { Code = code; }
    }

    static class Clock
    {
        static readonly Stopwatch watch = Stopwatch.StartNew();
        public static long Now() { return watch.ElapsedMilliseconds; }
    }

    // JSON with Hashtable (ordinal keys) for objects, object[] for arrays, string, bool, long, double and null.
    public static class Json
    {
        public static object Parse(string s)
        {
            int i = 0;
            object v = Value(s, ref i);
            Ws(s, ref i);
            if (i != s.Length) { throw new FormatException("unexpected text after JSON value at " + i); }
            return v;
        }

        static void Ws(string s, ref int i) { while ((i < s.Length) && ((s[i] == ' ') || (s[i] == '\t') || (s[i] == '\r') || (s[i] == '\n'))) { i++; } }

        static object Value(string s, ref int i)
        {
            Ws(s, ref i);
            if (i >= s.Length) { throw new FormatException("unexpected end of JSON"); }
            char c = s[i];
            if (c == '{')
            {
                Hashtable o = new Hashtable(StringComparer.Ordinal);
                i++; Ws(s, ref i);
                if ((i < s.Length) && (s[i] == '}')) { i++; return o; }
                while (true)
                {
                    Ws(s, ref i);
                    if ((i >= s.Length) || (s[i] != '"')) { throw new FormatException("expected a property name at " + i); }
                    string k = Str(s, ref i);
                    Ws(s, ref i);
                    if ((i >= s.Length) || (s[i] != ':')) { throw new FormatException("expected ':' at " + i); }
                    i++;
                    o[k] = Value(s, ref i);
                    Ws(s, ref i);
                    if (i >= s.Length) { throw new FormatException("unexpected end of JSON"); }
                    if (s[i] == ',') { i++; continue; }
                    if (s[i] == '}') { i++; return o; }
                    throw new FormatException("expected ',' or '}' at " + i);
                }
            }
            if (c == '[')
            {
                List<object> a = new List<object>();
                i++; Ws(s, ref i);
                if ((i < s.Length) && (s[i] == ']')) { i++; return a.ToArray(); }
                while (true)
                {
                    a.Add(Value(s, ref i));
                    Ws(s, ref i);
                    if (i >= s.Length) { throw new FormatException("unexpected end of JSON"); }
                    if (s[i] == ',') { i++; continue; }
                    if (s[i] == ']') { i++; return a.ToArray(); }
                    throw new FormatException("expected ',' or ']' at " + i);
                }
            }
            if (c == '"') { return Str(s, ref i); }
            if (Word(s, ref i, "true")) { return true; }
            if (Word(s, ref i, "false")) { return false; }
            if (Word(s, ref i, "null")) { return null; }
            int st = i;
            while ((i < s.Length) && ("+-0123456789.eE".IndexOf(s[i]) >= 0)) { i++; }
            if (st == i) { throw new FormatException("unexpected character in JSON at " + st); }
            string num = s.Substring(st, i - st);
            long l;
            if ((num.IndexOfAny(new char[] { '.', 'e', 'E' }) < 0) && long.TryParse(num, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out l)) { return l; }
            return double.Parse(num, NumberStyles.Float, CultureInfo.InvariantCulture);
        }

        static bool Word(string s, ref int i, string w)
        {
            if ((i + w.Length <= s.Length) && (string.CompareOrdinal(s, i, w, 0, w.Length) == 0)) { i += w.Length; return true; }
            return false;
        }

        static string Str(string s, ref int i)
        {
            i++;
            StringBuilder sb = new StringBuilder();
            while (true)
            {
                if (i >= s.Length) { throw new FormatException("unterminated JSON string"); }
                char c = s[i++];
                if (c == '"') { return sb.ToString(); }
                if (c != '\\') { sb.Append(c); continue; }
                if (i >= s.Length) { throw new FormatException("unterminated JSON string"); }
                char e = s[i++];
                switch (e)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        if (i + 4 > s.Length) { throw new FormatException("bad \\u escape in JSON"); }
                        sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        i += 4;
                        break;
                    default: throw new FormatException("bad escape in JSON string");
                }
            }
        }

        public static string Stringify(object v) { StringBuilder sb = new StringBuilder(); Write(sb, v, null, ""); return sb.ToString(); }
        public static string Pretty(object v) { StringBuilder sb = new StringBuilder(); Write(sb, v, "  ", ""); return sb.ToString(); }

        static object Unwrap(object v)
        {
            // PowerShell may hand over its PSObject wrapper: use the object inside.
            if ((v != null) && (v.GetType().FullName == "System.Management.Automation.PSObject"))
            {
                object b = v.GetType().GetProperty("BaseObject").GetValue(v, null);
                if (b != null) { return b; }
            }
            return v;
        }

        static void Write(StringBuilder sb, object v, string indent, string cur)
        {
            v = Unwrap(v);
            if (v == null) { sb.Append("null"); return; }
            if (v is string) { Quote(sb, (string)v); return; }
            if (v is char) { Quote(sb, v.ToString()); return; }
            if (v is bool) { sb.Append(((bool)v) ? "true" : "false"); return; }
            if ((v is int) || (v is long) || (v is short) || (v is byte) || (v is uint) || (v is ulong) || (v is ushort) || (v is sbyte)) { sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); return; }
            if ((v is double) || (v is float) || (v is decimal)) { sb.Append(Convert.ToDouble(v, CultureInfo.InvariantCulture).ToString("R", CultureInfo.InvariantCulture)); return; }
            string next = (indent != null) ? (cur + indent) : null;
            IDictionary d = v as IDictionary;
            if (d != null)
            {
                sb.Append('{');
                bool first = true;
                foreach (DictionaryEntry e in d)
                {
                    if (Unwrap(e.Value) == null) { continue; } // Like JSON.stringify of undefined: absent
                    if (!first) { sb.Append(','); }
                    first = false;
                    if (next != null) { sb.Append('\n').Append(next); }
                    Quote(sb, Convert.ToString(Unwrap(e.Key), CultureInfo.InvariantCulture));
                    sb.Append((next != null) ? ": " : ":");
                    Write(sb, e.Value, indent, next);
                }
                if ((next != null) && !first) { sb.Append('\n').Append(cur); }
                sb.Append('}');
                return;
            }
            IEnumerable a = v as IEnumerable;
            if (a != null)
            {
                sb.Append('[');
                bool first = true;
                foreach (object x in a)
                {
                    if (!first) { sb.Append(','); }
                    first = false;
                    if (next != null) { sb.Append('\n').Append(next); }
                    Write(sb, x, indent, next);
                }
                if ((next != null) && !first) { sb.Append('\n').Append(cur); }
                sb.Append(']');
                return;
            }
            Quote(sb, v.ToString());
        }

        static void Quote(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < ' ') { sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture)); } else { sb.Append(c); }
                        break;
                }
            }
            sb.Append('"');
        }
    }

    public class TlsConn
    {
        public TcpClient Tcp;
        public SslStream Ssl;
        public string Fingerprint;
        public bool Authorized;
        public string Reason;
        public void Close()
        {
            try { if (Ssl != null) { Ssl.Close(); } } catch (Exception) { }
            try { Tcp.Close(); } catch (Exception) { }
        }
    }

    public class HttpResult
    {
        public int Status;
        public string StatusLine;
        public Hashtable Headers;
        public byte[] Body;
        public string Text { get { return Encoding.UTF8.GetString(Body); } }
    }

    public static class Tls
    {
        public static string UserAgent = "meshtunnel";

        static string Inner(Exception ex) { while (ex.InnerException != null) { ex = ex.InnerException; } return ex.Message; }

        // curl's --pinnedpubkey format: "sha256//" + base64 of the SHA-256 of the certificate's SubjectPublicKeyInfo.
        public static string CertPin(byte[] der)
        {
            int vp, vl;
            Tlv(der, 0, out vp, out vl);                  // Certificate
            Tlv(der, vp, out vp, out vl);                 // tbsCertificate
            int p = vp;
            if (Tlv(der, p, out vp, out vl) == 0xA0) { p = vp + vl; } // [0] version, optional
            for (int i = 0; i < 5; i++) { Tlv(der, p, out vp, out vl); p = vp + vl; } // serial, signature, issuer, validity, subject
            Tlv(der, p, out vp, out vl);                  // subjectPublicKeyInfo
            using (SHA256 sha = SHA256.Create()) { return "sha256//" + Convert.ToBase64String(sha.ComputeHash(der, p, vp + vl - p)); }
        }

        static int Tlv(byte[] b, int pos, out int valuePos, out int length)
        {
            int tag = b[pos];
            int l = b[pos + 1];
            pos += 2;
            if ((l & 0x80) != 0)
            {
                int n = l & 0x7f;
                if ((n == 0) || (n > 3)) { throw new FormatException("unsupported DER length"); }
                l = 0;
                for (int i = 0; i < n; i++) { l = (l << 8) | b[pos + i]; }
                pos += n;
            }
            if (pos + l > b.Length) { throw new FormatException("truncated DER"); }
            valuePos = pos;
            length = l;
            return tag;
        }

        static bool IsWindows() { return Environment.OSVersion.Platform == PlatformID.Win32NT; }

        static bool NoProxyFor(string h)
        {
            string np = Environment.GetEnvironmentVariable("NO_PROXY");
            if (string.IsNullOrEmpty(np)) { np = Environment.GetEnvironmentVariable("no_proxy"); }
            if (string.IsNullOrEmpty(np)) { return false; }
            foreach (string entry in np.Split(','))
            {
                string n = entry.Trim().ToLowerInvariant();
                int colon = n.LastIndexOf(':');
                if ((colon > 0) && (n.IndexOf(']') < colon) && (n.IndexOf(':') == colon)) { n = n.Substring(0, colon); }
                if (n == "") { continue; }
                if (n == "*") { return true; }
                if (n.StartsWith("*.")) { n = n.Substring(2); } else if (n.StartsWith(".")) { n = n.Substring(1); }
                if ((h == n) || h.EndsWith("." + n)) { return true; }
            }
            return false;
        }

        // The HTTP proxy for this server: HTTPS_PROXY (and NO_PROXY) first, then on Windows the system proxy settings.
        static Uri ProxyFor(string host, int port)
        {
            string h = host.ToLowerInvariant();
            if ((h == "localhost") || (h == "127.0.0.1") || (h == "::1")) { return null; }
            string p = Environment.GetEnvironmentVariable("HTTPS_PROXY");
            if (string.IsNullOrEmpty(p)) { p = Environment.GetEnvironmentVariable("https_proxy"); }
            if (!string.IsNullOrEmpty(p))
            {
                if (NoProxyFor(h)) { return null; }
                Uri u;
                if (!Uri.TryCreate((p.IndexOf("://") >= 0) ? p : ("http://" + p), UriKind.Absolute, out u) || (u.Scheme != "http"))
                {
                    Console.Error.WriteLine("meshtunnel: ignoring HTTPS_PROXY " + p + ", only http:// proxies are supported");
                    return null;
                }
                return u;
            }
            if (IsWindows())
            {
                try
                {
                    Uri target = new Uri("https://" + ((h.IndexOf(':') >= 0) ? ("[" + h + "]") : h) + ":" + port + "/");
                    IWebProxy sys = WebRequest.GetSystemWebProxy();
                    if ((sys != null) && !sys.IsBypassed(target))
                    {
                        Uri u = sys.GetProxy(target);
                        if ((u != null) && (u.Scheme == "http") && !string.Equals(u.Host, target.Host, StringComparison.OrdinalIgnoreCase)) { return u; }
                    }
                }
                catch (Exception) { }
            }
            return null;
        }

        static TcpClient ConnectTcp(string host, int port, string what)
        {
            IPAddress[] addrs;
            IPAddress ip;
            if (IPAddress.TryParse(host, out ip)) { addrs = new IPAddress[] { ip }; }
            else
            {
                try { addrs = Dns.GetHostAddresses(host); }
                catch (Exception ex) { throw new MtException("cannot connect to " + what + ": " + Inner(ex), Exit.NOTFOUND); }
            }
            string last = "no address found";
            foreach (IPAddress a in addrs)
            {
                TcpClient c = new TcpClient(a.AddressFamily);
                try
                {
                    IAsyncResult r = c.BeginConnect(a, port, null, null);
                    if (!r.AsyncWaitHandle.WaitOne(20000)) { c.Close(); last = "timed out"; continue; }
                    c.EndConnect(r);
                    c.NoDelay = true;
                    return c;
                }
                catch (Exception ex) { c.Close(); last = Inner(ex); }
            }
            throw new MtException("cannot connect to " + what + ": " + last, Exit.NOTFOUND);
        }

        static void ProxyConnect(TcpClient tcp, Uri proxy, string host, int port)
        {
            string target = ((host.IndexOf(':') >= 0) ? ("[" + host + "]") : host) + ":" + port;
            string req = "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n";
            if (!string.IsNullOrEmpty(proxy.UserInfo))
            {
                string[] up = proxy.UserInfo.Split(new char[] { ':' }, 2);
                string cred = Uri.UnescapeDataString(up[0]) + ":" + ((up.Length > 1) ? Uri.UnescapeDataString(up[1]) : "");
                req += "Proxy-Authorization: Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(cred)) + "\r\n";
            }
            NetworkStream ns = tcp.GetStream();
            byte[] rb = Encoding.ASCII.GetBytes(req + "\r\n");
            tcp.ReceiveTimeout = 20000;
            ns.Write(rb, 0, rb.Length);
            // Byte by byte: nothing past the reply may be consumed, the TLS handshake follows.
            StringBuilder head = new StringBuilder();
            while (!head.ToString().EndsWith("\r\n\r\n"))
            {
                int b;
                try { b = ns.ReadByte(); } catch (IOException) { b = -1; }
                if ((b < 0) || (head.Length > 16384)) { tcp.Close(); throw new MtException("the proxy closed the connection or sent an oversized reply", Exit.NOTFOUND); }
                head.Append((char)b);
            }
            string status = head.ToString().Split(new string[] { "\r\n" }, StringSplitOptions.None)[0];
            if (!(status.StartsWith("HTTP/1.1 200") || status.StartsWith("HTTP/1.0 200")))
            {
                tcp.Close();
                throw new MtException("the proxy " + proxy.Authority + " refused the connection: " + status + (status.Contains(" 407") ? " (it wants a login: set HTTPS_PROXY=http://user:password@proxy:port)" : ""), Exit.NOTFOUND);
            }
        }

        static string Describe(SslPolicyErrors e)
        {
            List<string> parts = new List<string>();
            if ((e & SslPolicyErrors.RemoteCertificateNotAvailable) != 0) { parts.Add("no certificate"); }
            if ((e & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) { parts.Add("issued for another name"); }
            if ((e & SslPolicyErrors.RemoteCertificateChainErrors) != 0) { parts.Add("not signed by a trusted authority"); }
            return string.Join(", ", parts.ToArray());
        }

        // Open a TLS connection and decide trust BEFORE anything is written, so credentials never reach an unverified peer.
        // Trusted means: a valid CA chain for this host name, or the public key matches the pinned one.
        public static TlsConn Connect(string url, string pin, bool allowUntrusted)
        {
            if (string.IsNullOrEmpty(pin)) { pin = null; }
            Uri u = new Uri(url);
            string host = u.DnsSafeHost;
            int port = u.Port;
            Uri proxy = ProxyFor(host, port);
            TcpClient tcp;
            if (proxy == null) { tcp = ConnectTcp(host, port, u.Authority); }
            else { tcp = ConnectTcp(proxy.DnsSafeHost, proxy.Port, "proxy " + proxy.Authority); ProxyConnect(tcp, proxy, host, port); }
            TlsConn t = new TlsConn();
            t.Tcp = tcp;
            bool checkedCert = false;
            RemoteCertificateValidationCallback cb = delegate (object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
            {
                checkedCert = true;
                try { t.Fingerprint = CertPin(cert.GetRawCertData()); } catch (Exception) { t.Fingerprint = null; }
                t.Authorized = (errors == SslPolicyErrors.None);
                if (!t.Authorized) { t.Reason = Describe(errors); }
                return t.Authorized || ((pin != null) && (pin == t.Fingerprint)) || allowUntrusted;
            };
            SslStream ssl = new SslStream(tcp.GetStream(), false, cb);
            tcp.ReceiveTimeout = 20000;
            tcp.SendTimeout = 20000;
            try { ssl.AuthenticateAsClient(host, null, (SslProtocols)3072, false); } // TLS 1.2: .NET Framework may not offer it by default
            catch (Exception ex)
            {
                tcp.Close();
                if (checkedCert && !t.Authorized && !allowUntrusted && ((pin == null) || (pin != t.Fingerprint)))
                {
                    if (pin != null) { throw new MtException("the server certificate does NOT match the pinned key!\n  pinned: " + pin + "\n  server: " + t.Fingerprint + "\nIt was replaced, or someone is intercepting the connection. If the change is expected, run: meshtunnel login " + url, Exit.TLS); }
                    throw new MtException("the server certificate is not trusted (" + t.Reason + ") and no key is pinned, run: meshtunnel login " + url, Exit.TLS);
                }
                throw new MtException("cannot connect to " + u.Authority + ": " + Inner(ex), Exit.NOTFOUND);
            }
            tcp.ReceiveTimeout = 0;
            tcp.SendTimeout = 0;
            t.Ssl = ssl;
            return t;
        }

        static int IndexOf(byte[] b, int len, byte[] pat)
        {
            for (int i = 0; i + pat.Length <= len; i++)
            {
                int j = 0;
                while ((j < pat.Length) && (b[i + j] == pat[j])) { j++; }
                if (j == pat.Length) { return i; }
            }
            return -1;
        }

        // Read an HTTP response head; bytes that followed it are returned in rest.
        public static HttpResult ReadHead(Stream s, out byte[] rest)
        {
            byte[] buf = new byte[16384];
            int len = 0;
            byte[] crlf2 = new byte[] { 13, 10, 13, 10 };
            while (true)
            {
                if (len == buf.Length)
                {
                    if (len >= 65536) { throw new MtException("the server sent an oversized HTTP header", Exit.NOTFOUND); }
                    Array.Resize(ref buf, len * 2);
                }
                int n;
                try { n = s.Read(buf, len, buf.Length - len); }
                catch (Exception) { throw new MtException("the server did not answer", Exit.NOTFOUND); }
                if (n <= 0) { throw new MtException("the server closed the connection", Exit.NOTFOUND); }
                len += n;
                int end = IndexOf(buf, len, crlf2);
                if (end < 0) { continue; }
                rest = new byte[len - end - 4];
                Array.Copy(buf, end + 4, rest, 0, rest.Length);
                string[] lines = Encoding.GetEncoding("iso-8859-1").GetString(buf, 0, end).Split(new string[] { "\r\n" }, StringSplitOptions.None);
                HttpResult r = new HttpResult();
                r.StatusLine = lines[0];
                string[] sp = lines[0].Split(' ');
                int code = 0;
                if (sp.Length > 1) { int.TryParse(sp[1], out code); }
                r.Status = code;
                r.Headers = new Hashtable(StringComparer.OrdinalIgnoreCase);
                for (int i = 1; i < lines.Length; i++)
                {
                    int c = lines[i].IndexOf(':');
                    if (c > 0) { r.Headers[lines[i].Substring(0, c).Trim()] = lines[i].Substring(c + 1).Trim(); }
                }
                return r;
            }
        }

        // A small HTTPS request through the same trust rules (setup code, token revocation, update).
        public static HttpResult Request(string url, string pin, string method, string pathAndQuery, string form)
        {
            TlsConn t = Connect(url, pin, false);
            try
            {
                Uri u = new Uri(url);
                byte[] body = (form != null) ? Encoding.UTF8.GetBytes(form) : null;
                string req = method + " " + pathAndQuery + " HTTP/1.1\r\nHost: " + u.Authority + "\r\nUser-Agent: " + UserAgent + "\r\nAccept-Encoding: identity\r\nConnection: close\r\n";
                if (body != null) { req += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " + body.Length + "\r\n"; }
                byte[] rb = Encoding.UTF8.GetBytes(req + "\r\n");
                t.Ssl.Write(rb, 0, rb.Length);
                if (body != null) { t.Ssl.Write(body, 0, body.Length); }
                t.Ssl.Flush();
                t.Tcp.ReceiveTimeout = 30000;
                byte[] rest;
                HttpResult r = ReadHead(t.Ssl, out rest);
                MemoryStream ms = new MemoryStream();
                ms.Write(rest, 0, rest.Length);
                string cl = r.Headers["content-length"] as string;
                long want = -1;
                if (cl != null) { long.TryParse(cl, out want); }
                byte[] buf = new byte[65536];
                while ((want < 0) || (ms.Length < want))
                {
                    int n;
                    try { n = t.Ssl.Read(buf, 0, buf.Length); } catch (Exception) { break; }
                    if (n <= 0) { break; }
                    ms.Write(buf, 0, n);
                }
                byte[] data = ms.ToArray();
                string te = r.Headers["transfer-encoding"] as string;
                if ((te != null) && (te.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    MemoryStream o = new MemoryStream();
                    int i = 0;
                    while (i < data.Length)
                    {
                        int eol = i;
                        while ((eol + 1 < data.Length) && !((data[eol] == 13) && (data[eol + 1] == 10))) { eol++; }
                        if (eol + 1 >= data.Length) { break; }
                        string sz = Encoding.ASCII.GetString(data, i, eol - i).Split(';')[0].Trim();
                        int size;
                        if (!int.TryParse(sz, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out size) || (size <= 0)) { break; }
                        if (eol + 2 + size > data.Length) { throw new MtException("the download was cut short", Exit.NOTFOUND); }
                        o.Write(data, eol + 2, size);
                        i = eol + 2 + size + 2;
                    }
                    data = o.ToArray();
                }
                else if (want >= 0)
                {
                    if (data.Length < want) { throw new MtException("the download was cut short", Exit.NOTFOUND); }
                    if (data.Length > want) { Array.Resize(ref data, (int)want); }
                }
                r.Body = data;
                return r;
            }
            finally { t.Close(); }
        }
    }

    public class WsMessage
    {
        public string Kind; // "text", "binary" or "close"
        public string Text;
        public byte[] Data;
        public int Code;
    }

    // An RFC 6455 client connection. One thread reads frames: messages are queued (Read) until a sink takes them (SetSink),
    // which then runs on the reading thread, so a slow sink slows the reading: back pressure. Writes are serialized.
    public class WsConn
    {
        const int MaxMessage = 64 * 1024 * 1024;
        static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        readonly TlsConn conn;
        readonly Stream stream;
        readonly object writeLock = new object();
        readonly object qlock = new object();
        readonly object deliverLock = new object();
        readonly Queue<WsMessage> queue = new Queue<WsMessage>();
        Action<WsMessage> sink;
        WsMessage closeMessage;
        byte[] rbuf = new byte[65536];
        int rpos, rlen;
        long lastSeen = Clock.Now();
        volatile bool inSink;
        Timer keepalive;

        public volatile bool Closed;
        public volatile bool CloseSent;
        public int CloseCode;
        public string Error;

        WsConn(TlsConn t, byte[] initial)
        {
            conn = t;
            stream = t.Ssl;
            if (initial.Length > rbuf.Length) { rbuf = new byte[initial.Length]; }
            Array.Copy(initial, rbuf, initial.Length);
            rlen = initial.Length;
        }

        public static WsConn Connect(string url, string pin, string pathAndQuery, string meshAuth)
        {
            TlsConn t = Tls.Connect(url, pin, false);
            try
            {
                Uri u = new Uri(url);
                byte[] keyBytes = new byte[16];
                rng.GetBytes(keyBytes);
                string key = Convert.ToBase64String(keyBytes);
                string req = "GET " + pathAndQuery + " HTTP/1.1\r\nHost: " + u.Authority + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\nUser-Agent: " + Tls.UserAgent + "\r\n";
                if (!string.IsNullOrEmpty(meshAuth)) { req += "x-meshauth: " + meshAuth + "\r\n"; }
                byte[] rb = Encoding.UTF8.GetBytes(req + "\r\n");
                t.Tcp.ReceiveTimeout = 20000;
                t.Ssl.Write(rb, 0, rb.Length);
                t.Ssl.Flush();
                byte[] rest;
                HttpResult h = Tls.ReadHead(t.Ssl, out rest);
                if (h.Status != 101)
                {
                    if (h.Status == 404) { throw new MtException("the server answered \"404 Not Found\" for " + pathAndQuery.Split('?')[0] + ", check the server URL (and the domain path, if any)", Exit.NOTFOUND); }
                    throw new MtException("the server refused the WebSocket: " + h.StatusLine, ((h.Status == 401) || (h.Status == 403)) ? Exit.AUTH : Exit.NOTFOUND);
                }
                string expected;
                using (SHA1 sha = SHA1.Create()) { expected = Convert.ToBase64String(sha.ComputeHash(Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))); }
                if ((h.Headers["sec-websocket-accept"] as string) != expected) { throw new MtException("the server sent an invalid WebSocket handshake", Exit.NOTFOUND); }
                t.Tcp.ReceiveTimeout = 0;
                WsConn ws = new WsConn(t, rest);
                Thread th = new Thread(ws.ReadLoop);
                th.IsBackground = true;
                th.Start();
                return ws;
            }
            catch (Exception)
            {
                t.Close();
                throw;
            }
        }

        // ---- Reading ----

        int Fill()
        {
            if (rpos < rlen) { return rlen - rpos; }
            rpos = 0;
            rlen = stream.Read(rbuf, 0, rbuf.Length);
            if (rlen > 0) { lastSeen = Clock.Now(); }
            return rlen;
        }

        int ReadByte() { if (Fill() <= 0) { return -1; } return rbuf[rpos++]; }

        void ReadExact(byte[] dst, int off, int count)
        {
            while (count > 0)
            {
                if (Fill() <= 0) { throw new EndOfStreamException("the connection ended in the middle of a message"); }
                int n = Math.Min(count, rlen - rpos);
                Buffer.BlockCopy(rbuf, rpos, dst, off, n);
                rpos += n; off += n; count -= n;
            }
        }

        int Need() { int b = ReadByte(); if (b < 0) { throw new EndOfStreamException("the connection ended in the middle of a frame"); } return b; }

        void ReadLoop()
        {
            int code = 1006;
            List<byte[]> fragments = null;
            int fragOpcode = 0;
            long fragSize = 0;
            try
            {
                while (true)
                {
                    int b0 = ReadByte();
                    if (b0 < 0) { break; }
                    int b1 = Need();
                    int opcode = b0 & 0x0f;
                    bool fin = (b0 & 0x80) != 0, masked = (b1 & 0x80) != 0;
                    long len = b1 & 0x7f;
                    if ((b0 & 0x70) != 0) { throw new InvalidDataException("unexpected extension bits"); }
                    if (len == 126) { len = (Need() << 8) | Need(); }
                    else if (len == 127) { len = 0; for (int i = 0; i < 8; i++) { len = (len << 8) + Need(); } }
                    if ((len < 0) || (len > MaxMessage)) { throw new InvalidDataException("frame too large"); }
                    byte[] mask = null;
                    if (masked) { mask = new byte[4]; ReadExact(mask, 0, 4); }
                    byte[] payload = new byte[len];
                    ReadExact(payload, 0, (int)len);
                    if (masked) { for (int i = 0; i < payload.Length; i++) { payload[i] ^= mask[i & 3]; } }
                    if (opcode >= 8)
                    {
                        if (!fin || (len > 125)) { throw new InvalidDataException("bad control frame"); }
                        if (opcode == 8)
                        {
                            code = (payload.Length >= 2) ? ((payload[0] << 8) | payload[1]) : 1005;
                            if (!CloseSent) { CloseSent = true; TrySendControl(8, (payload.Length >= 2) ? new byte[] { payload[0], payload[1] } : new byte[0]); }
                            break;
                        }
                        if (opcode == 9) { TrySendControl(10, payload); }
                        continue;
                    }
                    if (opcode == 0)
                    {
                        if (fragments == null) { throw new InvalidDataException("unexpected continuation frame"); }
                        fragments.Add(payload);
                        fragSize += payload.Length;
                        if (fragSize > MaxMessage) { throw new InvalidDataException("message too large"); }
                        if (fin)
                        {
                            byte[] all = new byte[fragSize];
                            int o = 0;
                            foreach (byte[] f in fragments) { Buffer.BlockCopy(f, 0, all, o, f.Length); o += f.Length; }
                            fragments = null;
                            Deliver(Message(fragOpcode, all));
                        }
                        continue;
                    }
                    if ((opcode != 1) && (opcode != 2)) { throw new InvalidDataException("unknown opcode " + opcode); }
                    if (fragments != null) { throw new InvalidDataException("interleaved messages"); }
                    if (fin) { Deliver(Message(opcode, payload)); }
                    else { fragments = new List<byte[]>(); fragments.Add(payload); fragOpcode = opcode; fragSize = payload.Length; }
                }
            }
            catch (InvalidDataException ex) { if (Error == null) { Error = "WebSocket protocol error: " + ex.Message; } code = 1002; }
            catch (Exception ex) { if (!Closed && (Error == null)) { Error = ex.Message; } }
            Closed = true;
            CloseCode = code;
            if (keepalive != null) { keepalive.Dispose(); }
            conn.Close();
            WsMessage cm = new WsMessage();
            cm.Kind = "close";
            cm.Code = code;
            Deliver(cm);
        }

        static WsMessage Message(int opcode, byte[] payload)
        {
            WsMessage m = new WsMessage();
            if (opcode == 1) { m.Kind = "text"; m.Text = Encoding.UTF8.GetString(payload); } else { m.Kind = "binary"; m.Data = payload; }
            return m;
        }

        void Deliver(WsMessage m)
        {
            lock (deliverLock)
            {
                Action<WsMessage> s;
                lock (qlock)
                {
                    if (m.Kind == "close") { closeMessage = m; }
                    if (sink == null)
                    {
                        queue.Enqueue(m);
                        while (queue.Count > 1000) { queue.Dequeue(); } // Nobody reads the control channel's event stream: keep the recent part
                        Monitor.PulseAll(qlock);
                        return;
                    }
                    s = sink;
                }
                inSink = true;
                try { s(m); } catch (Exception) { }
                finally { inSink = false; }
            }
        }

        // The next message within timeoutMs, or null. After the connection ended, always its "close" message.
        public WsMessage Read(int timeoutMs)
        {
            long deadline = Clock.Now() + Math.Max(0, timeoutMs);
            lock (qlock)
            {
                while (queue.Count == 0)
                {
                    if (closeMessage != null) { return closeMessage; }
                    long left = deadline - Clock.Now();
                    if (left <= 0) { return null; }
                    Monitor.Wait(qlock, (int)Math.Min(left, int.MaxValue));
                }
                return queue.Dequeue();
            }
        }

        // From now on messages go to sink, on the reading thread, starting with the ones already queued, in order.
        public void SetSink(Action<WsMessage> s)
        {
            lock (deliverLock)
            {
                List<WsMessage> pending;
                lock (qlock)
                {
                    pending = new List<WsMessage>(queue);
                    queue.Clear();
                    sink = s;
                }
                foreach (WsMessage m in pending)
                {
                    inSink = true;
                    try { s(m); } catch (Exception) { }
                    finally { inSink = false; }
                }
            }
        }

        // Returns once the server says both sides of a relay are joined ("c", or "cr" when recorded). What came after it stays
        // queued for SetSink. ctl, when given, is the control channel where a refusal to route the request shows up.
        public void WaitRelayStart(int timeoutMs, WsConn ctl)
        {
            long deadline = Clock.Now() + timeoutMs;
            Hashtable closeInfo = null;
            while (true)
            {
                if (ctl != null)
                {
                    WsMessage cm;
                    while (((cm = ctl.Read(0)) != null) && (cm.Kind != "close"))
                    {
                        if (cm.Kind != "text") { continue; }
                        Hashtable o = null;
                        try { o = Json.Parse(cm.Text) as Hashtable; } catch (Exception) { }
                        if ((o != null) && ("msg".Equals(o["action"])) && ("meshtunnel".Equals(o["responseid"])) && !("OK".Equals(o["result"])))
                        {
                            Destroy();
                            MtException re = new MtException("the server would not route the terminal request", Exit.NOTFOUND);
                            re.RelayEarly = true;
                            throw re;
                        }
                    }
                }
                long left = deadline - Clock.Now();
                if (left <= 0)
                {
                    Destroy();
                    MtException te = new MtException("timed out waiting for the device", Exit.NOTFOUND);
                    te.RelayEarly = true;
                    te.TimedOut = true;
                    throw te;
                }
                WsMessage m = Read((ctl != null) ? (int)Math.Min(left, 250) : (int)left);
                if (m == null) { continue; }
                if ((m.Kind == "text") && ((m.Text == "c") || (m.Text == "cr"))) { return; }
                if ((m.Kind == "text") && m.Text.StartsWith("{"))
                {
                    try { Hashtable o = Json.Parse(m.Text) as Hashtable; if ((o != null) && "close".Equals(o["action"])) { closeInfo = o; } } catch (Exception) { }
                }
                if (m.Kind == "close")
                {
                    MtException ce = new MtException("the relay closed before the device answered", Exit.NOTFOUND);
                    ce.RelayEarly = true;
                    ce.CloseInfo = closeInfo;
                    throw ce;
                }
            }
        }

        // ---- Writing ----

        byte[] Frame(int opcode, byte[] p, int off, int len)
        {
            int hl = (len < 126) ? 2 : ((len < 65536) ? 4 : 10);
            byte[] f = new byte[hl + 4 + len];
            f[0] = (byte)(0x80 | opcode);
            if (len < 126) { f[1] = (byte)(0x80 | len); }
            else if (len < 65536) { f[1] = 0x80 | 126; f[2] = (byte)(len >> 8); f[3] = (byte)len; }
            else { f[1] = 0x80 | 127; for (int i = 0; i < 8; i++) { f[2 + i] = (byte)((i < 4) ? 0 : (len >> (8 * (7 - i)))); } }
            byte[] key = new byte[4];
            rng.GetBytes(key);
            Buffer.BlockCopy(key, 0, f, hl, 4);
            int o = hl + 4;
            for (int i = 0; i < len; i++) { f[o + i] = (byte)(p[off + i] ^ key[i & 3]); }
            return f;
        }

        bool Write(byte[] frame)
        {
            try
            {
                stream.Write(frame, 0, frame.Length);
                lastSeen = Clock.Now(); // The server takes data: it is alive even when it has nothing to say
                return true;
            }
            catch (Exception ex)
            {
                if (!Closed && (Error == null)) { Error = ex.Message; }
                Destroy();
                return false;
            }
        }

        public bool SendBinary(byte[] data, int off, int len)
        {
            byte[] f = Frame(2, data, off, len);
            lock (writeLock) { if (Closed) { return false; } return Write(f); }
        }

        public bool SendText(string text)
        {
            byte[] b = Encoding.UTF8.GetBytes(text);
            byte[] f = Frame(1, b, 0, b.Length);
            lock (writeLock) { if (Closed) { return false; } return Write(f); }
        }

        // Control frames from the reading thread must never wait behind a blocked data write: skip them then (best effort).
        void TrySendControl(int opcode, byte[] payload)
        {
            byte[] f = Frame(opcode, payload, 0, payload.Length);
            if (!Monitor.TryEnter(writeLock)) { return; }
            try { if (!Closed) { Write(f); } } finally { Monitor.Exit(writeLock); }
        }

        public void Close(int code)
        {
            if (Closed || CloseSent) { return; }
            CloseSent = true;
            byte[] f = Frame(8, new byte[] { (byte)(code >> 8), (byte)code }, 0, 2);
            lock (writeLock) { if (!Closed) { Write(f); } }
        }

        public void Destroy()
        {
            Closed = true;
            conn.Close(); // The reading thread fails and delivers "close"
        }

        // Ping every 30 seconds; a server silent for 90 seconds is gone. Not while a sink is busy: that is our own back pressure.
        public void StartKeepalive()
        {
            if (keepalive != null) { return; }
            keepalive = new Timer(delegate (object state)
            {
                if (Closed) { return; }
                if (inSink) { lastSeen = Clock.Now(); return; }
                if (Clock.Now() - lastSeen > 90000) { if (Error == null) { Error = "the server stopped responding"; } Destroy(); return; }
                TrySendControl(9, new byte[0]);
            }, null, 30000, 30000);
        }
    }

    // Console access for the agent shell: raw VT mode on Windows, plain streams when redirected.
    class ConsoleIO
    {
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr GetStdHandle(int n);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetConsoleMode(IntPtr h, out uint mode);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetConsoleMode(IntPtr h, uint mode);
        [DllImport("kernel32.dll")] static extern uint GetConsoleCP();
        [DllImport("kernel32.dll")] static extern uint GetConsoleOutputCP();
        [DllImport("kernel32.dll")] static extern bool SetConsoleCP(uint cp);
        [DllImport("kernel32.dll")] static extern bool SetConsoleOutputCP(uint cp);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool ReadConsoleW(IntPtr h, [Out] char[] buffer, uint toRead, out uint read, IntPtr control);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool WriteConsoleW(IntPtr h, string s, uint count, out uint written, IntPtr reserved);

        const uint ENABLE_PROCESSED_INPUT = 0x1, ENABLE_LINE_INPUT = 0x2, ENABLE_ECHO_INPUT = 0x4, ENABLE_VIRTUAL_TERMINAL_INPUT = 0x200;
        const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x4, DISABLE_NEWLINE_AUTO_RETURN = 0x8;

        public readonly bool Tty;
        readonly bool win;
        IntPtr hIn, hOut;
        uint inMode, outMode, inCP, outCP;
        bool raw;
        readonly Stream stdin, stdout;
        readonly Decoder decoder = new UTF8Encoding(false).GetDecoder();
        readonly Encoder encoder = new UTF8Encoding(false).GetEncoder();
        readonly object outLock = new object();
        readonly char[] inChars = new char[4096];
        readonly byte[] inBytes = new byte[65536];

        public ConsoleIO(bool tty)
        {
            Tty = tty;
            win = Environment.OSVersion.Platform == PlatformID.Win32NT;
            stdin = Console.OpenStandardInput();
            stdout = Console.OpenStandardOutput();
            if (Tty && !win) { throw new MtException("an interactive agent shell needs Windows with the PowerShell client, use the Python or Node.js client here (piped input works)", Exit.USAGE); }
        }

        public void EnterRaw()
        {
            if (!Tty) { return; }
            hIn = GetStdHandle(-10);
            hOut = GetStdHandle(-11);
            if (!GetConsoleMode(hIn, out inMode) || !GetConsoleMode(hOut, out outMode)) { throw new MtException("cannot read the console mode", Exit.USAGE); }
            inCP = GetConsoleCP();
            outCP = GetConsoleOutputCP();
            // No line editing, echo or Ctrl+C handling here (the device gets them), keys as terminal sequences.
            if (!SetConsoleMode(hOut, outMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN) ||
                !SetConsoleMode(hIn, (inMode & ~(ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)) | ENABLE_VIRTUAL_TERMINAL_INPUT))
            {
                Restore();
                throw new MtException("this console does not support terminal sequences: use Windows Terminal, or Windows 10 version 1809 or newer", Exit.USAGE);
            }
            SetConsoleCP(65001);
            SetConsoleOutputCP(65001);
            raw = true;
        }

        public void Restore()
        {
            if (!win || (hIn == IntPtr.Zero)) { return; }
            SetConsoleMode(hIn, inMode);
            SetConsoleMode(hOut, outMode);
            if (raw) { SetConsoleCP(inCP); SetConsoleOutputCP(outCP); }
            raw = false;
        }

        // The next input bytes, or null at the end of the input.
        public byte[] ReadInput()
        {
            if (raw)
            {
                while (true)
                {
                    uint n;
                    if (!ReadConsoleW(hIn, inChars, (uint)inChars.Length, out n, IntPtr.Zero)) { return null; }
                    if (n == 0) { continue; }
                    int count = encoder.GetByteCount(inChars, 0, (int)n, false);
                    byte[] b = new byte[count];
                    encoder.GetBytes(inChars, 0, (int)n, b, 0, false);
                    if (count > 0) { return b; }
                }
            }
            int r = stdin.Read(inBytes, 0, inBytes.Length);
            if (r <= 0) { return null; }
            byte[] o = new byte[r];
            Buffer.BlockCopy(inBytes, 0, o, 0, r);
            return o;
        }

        public void Write(byte[] data)
        {
            lock (outLock)
            {
                if (raw)
                {
                    char[] chars = new char[data.Length + 8];
                    int nc = decoder.GetChars(data, 0, data.Length, chars, 0, false);
                    int off = 0;
                    while (off < nc)
                    {
                        uint w;
                        string s = new string(chars, off, nc - off);
                        if (!WriteConsoleW(hOut, s, (uint)s.Length, out w, IntPtr.Zero) || (w == 0)) { break; }
                        off += (int)w;
                    }
                    return;
                }
                stdout.Write(data, 0, data.Length);
                stdout.Flush();
            }
        }

        public int[] Size()
        {
            try { return new int[] { Console.WindowWidth, Console.WindowHeight }; } catch (Exception) { return new int[] { 80, 24 }; }
        }
    }

    class PumpState
    {
        public long Received;
        public volatile bool InputEnded;
        public readonly ManualResetEvent Done = new ManualResetEvent(false);
    }

    public static class Relay
    {
        const string CTRL = "102938";

        static bool Ctrl(Hashtable o) { return (o != null) && (Convert.ToString(o["ctrlChannel"], CultureInfo.InvariantCulture) == CTRL); }

        // A relay to a TCP port of the device (or of another host of its network), in its data phase.
        public static WsConn OpenPortTunnel(string url, string pin, string meshAuth, string nodeId, int port, string toHost)
        {
            string q = "nodeid=" + Uri.EscapeDataString(nodeId) + "&tcpport=" + port.ToString(CultureInfo.InvariantCulture);
            if (!string.IsNullOrEmpty(toHost)) { q += "&tcpaddr=" + Uri.EscapeDataString(toHost); }
            WsConn ws = WsConn.Connect(url, pin, new Uri(url).AbsolutePath + "meshrelay.ashx?" + q, meshAuth);
            ws.WaitRelayStart(20000, null);
            return ws;
        }

        // stdin/stdout <-> relay: the ssh ProxyCommand. Returns { bytes received, 1 if the input ended first }.
        public static long[] Proxy(WsConn ws)
        {
            Stream stdin = Console.OpenStandardInput(), stdout = Console.OpenStandardOutput();
            PumpState st = new PumpState();
            ws.SetSink(delegate (WsMessage m)
            {
                if (m.Kind == "binary")
                {
                    Interlocked.Add(ref st.Received, m.Data.Length);
                    try { stdout.Write(m.Data, 0, m.Data.Length); stdout.Flush(); } catch (Exception) { ws.Destroy(); } // The ssh client went away
                }
                else if (m.Kind == "close") { st.Done.Set(); }
            });
            Thread t = new Thread(delegate ()
            {
                byte[] buf = new byte[65536];
                try { int n; while ((n = stdin.Read(buf, 0, buf.Length)) > 0) { if (!ws.SendBinary(buf, 0, n)) { return; } } } catch (Exception) { }
                st.InputEnded = true;
                ws.Close(1000);
                if (!st.Done.WaitOne(1500)) { ws.Destroy(); } // MeshCentral may hold a relay socket open
            });
            t.IsBackground = true;
            t.Start();
            ws.StartKeepalive();
            st.Done.WaitOne();
            return new long[] { Interlocked.Read(ref st.Received), st.InputEnded ? 1 : 0 };
        }

        // A local TCP connection <-> relay. Returns the bytes received from the device.
        public static long PumpSocket(WsConn ws, TcpClient client)
        {
            NetworkStream ns = client.GetStream();
            PumpState st = new PumpState();
            ws.SetSink(delegate (WsMessage m)
            {
                if (m.Kind == "binary")
                {
                    Interlocked.Add(ref st.Received, m.Data.Length);
                    try { ns.Write(m.Data, 0, m.Data.Length); } catch (Exception) { ws.Destroy(); }
                }
                else if (m.Kind == "close") { st.Done.Set(); }
            });
            Thread t = new Thread(delegate ()
            {
                byte[] buf = new byte[65536];
                try { int n; while ((n = ns.Read(buf, 0, buf.Length)) > 0) { if (!ws.SendBinary(buf, 0, n)) { return; } } } catch (Exception) { }
                ws.Close(1000);
                if (!st.Done.WaitOne(1500)) { ws.Destroy(); }
            });
            t.IsBackground = true;
            t.Start();
            ws.StartKeepalive();
            st.Done.WaitOne();
            try { client.Client.Shutdown(SocketShutdown.Send); } catch (Exception) { }
            client.Close();
            return Interlocked.Read(ref st.Received);
        }

        // The agent's shell in this console. ctl (the control channel) is kept drained. Returns the exit code.
        public static int Terminal(WsConn ws, WsConn ctl, int protocol, bool requireLogin, string devName)
        {
            bool tty = !Console.IsInputRedirected && !Console.IsOutputRedirected;
            ConsoleIO io;
            try { io = new ConsoleIO(tty); } catch (Exception) { ws.Destroy(); throw; }
            int[] size = tty ? io.Size() : new int[] { 80, 24 };
            ws.SendText("{\"ctrlChannel\":\"" + CTRL + "\",\"type\":\"options\",\"cols\":" + size[0] + ",\"rows\":" + size[1] + (requireLogin ? ",\"requireLogin\":true" : "") + "}");
            ws.SendText(protocol.ToString(CultureInfo.InvariantCulture)); // Options first, then the protocol number: the web UI's order
            if (ctl != null) { ctl.SetSink(delegate (WsMessage m) { }); }
            long lastOutput = Clock.Now();
            ManualResetEvent done = new ManualResetEvent(false);
            ws.SetSink(delegate (WsMessage m)
            {
                if (m.Kind == "close") { done.Set(); return; }
                if (m.Kind == "binary") { Interlocked.Exchange(ref lastOutput, Clock.Now()); io.Write(m.Data); return; }
                if ((m.Text == "c") || (m.Text == "cr")) { return; }
                Interlocked.Exchange(ref lastOutput, Clock.Now());
                if (m.Text.StartsWith("{"))
                {
                    Hashtable o = null;
                    try { o = Json.Parse(m.Text) as Hashtable; } catch (Exception) { }
                    if (Ctrl(o))
                    {
                        if ("ping".Equals(o["type"])) { ws.SendText("{\"ctrlChannel\":\"" + CTRL + "\",\"type\":\"pong\"}"); }
                        else if ("console".Equals(o["type"]) && (o["msg"] != null)) { Console.Error.Write((tty ? "\r\n" : "") + "[" + o["msg"] + "]" + (tty ? "\r\n" : "\n")); }
                        return;
                    }
                }
                io.Write(Encoding.UTF8.GetBytes(m.Text));
            });
            try { io.EnterRaw(); } catch (Exception) { ws.Destroy(); throw; }
            long closingAt = 0;
            bool inputEnded = false;
            object closeLock = new object();
            Action disconnect = delegate ()
            {
                lock (closeLock)
                {
                    if (closingAt != 0) { return; }
                    closingAt = Clock.Now();
                }
                ws.SendText("{\"ctrlChannel\":\"" + CTRL + "\",\"type\":\"close\"}");
                ws.Close(1000);
            };
            Thread input = new Thread(delegate ()
            {
                bool atLineStart = true, tilde = false;
                try
                {
                    byte[] data;
                    while ((data = io.ReadInput()) != null)
                    {
                        if (!tty) { ws.SendBinary(data, 0, data.Length); continue; }
                        // ssh-style escapes, only right after a newline: "~." disconnects, "~~" sends one "~", "~?" lists them.
                        MemoryStream o = new MemoryStream();
                        bool quit = false;
                        foreach (byte b in data)
                        {
                            if (tilde)
                            {
                                tilde = false;
                                if (b == 0x2e) { quit = true; break; }
                                if (b == 0x3f) { Console.Error.Write("\r\nSupported escape sequences:\r\n ~.  - disconnect\r\n ~~  - send the escape character\r\n ~?  - this message\r\n(They are only recognized right after a newline.)\r\n"); continue; }
                                if (b == 0x7e) { o.WriteByte(0x7e); atLineStart = false; continue; }
                                o.WriteByte(0x7e);
                            }
                            else if (atLineStart && (b == 0x7e)) { tilde = true; continue; }
                            o.WriteByte(b);
                            atLineStart = (b == 0x0d) || (b == 0x0a);
                        }
                        if (o.Length > 0) { ws.SendBinary(o.ToArray(), 0, (int)o.Length); }
                        if (quit) { disconnect(); return; }
                    }
                }
                catch (Exception) { }
                inputEnded = true;
            });
            input.IsBackground = true;
            input.Start();
            ws.StartKeepalive();
            int eotTries = 0;
            long lastEot = 0;
            try
            {
                while (!done.WaitOne(250))
                {
                    long now = Clock.Now();
                    long closing;
                    lock (closeLock) { closing = closingAt; }
                    if ((closing != 0) && (now - closing > 1500)) { ws.Destroy(); break; } // MeshCentral may never answer the close
                    if (tty)
                    {
                        int[] s = io.Size();
                        if ((s[0] != size[0]) || (s[1] != size[1])) { size = s; ws.SendText("{\"ctrlChannel\":\"" + CTRL + "\",\"type\":\"termsize\",\"cols\":" + s[0] + ",\"rows\":" + s[1] + "}"); }
                    }
                    else if (inputEnded && (eotTries < 50) && (closing == 0))
                    {
                        // End of piped input: send ^D so the remote shell ends, like over ssh. Bash drops typeahead while it starts and
                        // when it redraws its prompt, so send it again whenever output appeared since the last one and then went quiet.
                        long lo = Interlocked.Read(ref lastOutput);
                        if ((now - lo >= 500) && !((lo <= lastEot) && (now - lastEot < 5000))) { eotTries++; lastEot = now; ws.SendBinary(new byte[] { 4 }, 0, 1); }
                    }
                }
            }
            finally { io.Restore(); }
            done.WaitOne(1000);
            bool lost = (ws.Error != null) && (closingAt == 0);
            Console.Error.Write((tty ? "\r\n" : "") + (lost ? ("meshtunnel: connection lost: " + ws.Error) : ("Connection to " + devName + " closed.")) + "\n");
            return lost ? Exit.NOTFOUND : Exit.OK;
        }
    }

    // "forward": a local listener; each connection gets its own relay, served on background threads. What happens is
    // reported through TakeNote() for the PowerShell side to print (it can explain failures from the device list).
    public class Forwarder
    {
        readonly TcpListener listener;
        readonly string url, pin, meshAuth, nodeId, toHost;
        readonly int rport;
        readonly Queue<string[]> notes = new Queue<string[]>();
        readonly List<WsConn> tunnels = new List<WsConn>();
        public volatile bool Stopped;
        public int StopCode;
        public int Port;

        public Forwarder(string url, string pin, string meshAuth, string nodeId, int rport, string toHost, string bind, int lport)
        {
            this.url = url; this.pin = pin; this.meshAuth = meshAuth; this.nodeId = nodeId; this.rport = rport;
            this.toHost = string.IsNullOrEmpty(toHost) ? null : toHost;
            IPAddress a;
            if (!IPAddress.TryParse(bind, out a)) { a = Dns.GetHostAddresses(bind)[0]; }
            listener = new TcpListener(a, lport);
        }

        public void Start()
        {
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            Thread t = new Thread(AcceptLoop);
            t.IsBackground = true;
            t.Start();
        }

        void AcceptLoop()
        {
            while (!Stopped)
            {
                TcpClient c;
                try { c = listener.AcceptTcpClient(); }
                catch (Exception) { if (Stopped) { return; } Thread.Sleep(100); continue; }
                Thread t = new Thread(delegate () { Serve(c); });
                t.IsBackground = true;
                t.Start();
            }
        }

        void Serve(TcpClient client)
        {
            string label = "?";
            try { label = client.Client.RemoteEndPoint.ToString(); client.NoDelay = true; } catch (Exception) { }
            WsConn ws;
            try { ws = Relay.OpenPortTunnel(url, pin, meshAuth, nodeId, rport, toHost); }
            catch (MtException e)
            {
                client.Close();
                Post(e.RelayEarly ? "early" : "error", label, e.Message, e.Code, e.TimedOut);
                return;
            }
            catch (Exception e) { client.Close(); Post("error", label, e.Message, Exit.NOTFOUND, false); return; }
            lock (tunnels) { tunnels.Add(ws); }
            long received = Relay.PumpSocket(ws, client);
            lock (tunnels) { tunnels.Remove(ws); }
            if ((ws.Error != null) && !Stopped) { Post("error", label, "connection lost: " + ws.Error, Exit.NOTFOUND, false); }
            else if ((received == 0) && !Stopped) { Post("refused", label, "", Exit.REFUSED, false); }
        }

        void Post(string kind, string label, string text, int code, bool timedOut)
        {
            lock (notes) { notes.Enqueue(new string[] { kind, label, text, code.ToString(CultureInfo.InvariantCulture), timedOut ? "1" : "0" }); }
        }

        // { kind (early, error, refused), client address, message, exit code, timed out (1/0) }, or null.
        public string[] TakeNote() { lock (notes) { return (notes.Count > 0) ? notes.Dequeue() : null; } }

        public void Stop(int code)
        {
            if (Stopped) { return; }
            StopCode = code;
            Stopped = true;
            try { listener.Stop(); } catch (Exception) { }
            lock (tunnels) { foreach (WsConn w in tunnels) { w.Close(1000); } }
        }
    }
}
'@

if ($MyInvocation.InvocationName -eq '.') { return } # Dot-sourced (the tests): define everything, run nothing

try { $null = Invoke-Main $args }
catch {
    $e = Get-MtError $_
    if ($null -ne $e) { Write-Note $e.message; $script:ExitCode = $e.code }
    else { Write-Note ('unexpected error: ' + ($_ | Out-String).Trim()); $script:ExitCode = $EXIT_USAGE }
}
exit $script:ExitCode
