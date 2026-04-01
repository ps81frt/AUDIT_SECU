$script = @'
# ============================================================
# AUDIT SECURITE WINDOWS - NIVEAU SOC/DFIR
# Version : Complète - Aucune interaction requise
# ============================================================

function Section($title) {
    Write-Host "`n" -NoNewline
    Write-Host "================================================================" -ForegroundColor DarkCyan
    Write-Host "  $title" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor DarkCyan
}

function SubSection($title) {
    Write-Host "`n  >> $title" -ForegroundColor Magenta
}

# ============================================================
Section "1 - SYSTEME & IDENTITE"
# ============================================================
SubSection "Informations systeme"
Get-ComputerInfo | Select-Object CsName, WindowsProductName, WindowsVersion, OsArchitecture,
    CsProcessors, CsTotalPhysicalMemory, OsLastBootUpTime, OsInstallDate | Format-List

SubSection "Utilisateur courant & groupes"
whoami /all

SubSection "Utilisateurs locaux"
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet,
    AccountExpires, Description | Format-Table -AutoSize

SubSection "Groupes locaux & membres"
Get-LocalGroup | ForEach-Object {
    $grp = $_
    $members = Get-LocalGroupMember -Group $grp.Name -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Name
    [PSCustomObject]@{ Groupe = $grp.Name; Membres = ($members -join ", ") }
} | Format-Table -AutoSize

SubSection "Sessions actives"
query session 2>$null

SubSection "Derniers logons (Eventlog)"
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 20 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Format-List

# ============================================================
Section "2 - RESEAU : PROFIL & INTERFACES"
# ============================================================
SubSection "Profil reseau"
Get-NetConnectionProfile | Select-Object Name, NetworkCategory, IPv4Connectivity, IPv6Connectivity | Format-Table -AutoSize

SubSection "Interfaces reseau"
Get-NetIPAddress | Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength, SuffixOrigin | Format-Table -AutoSize

SubSection "Routes actives"
Get-NetRoute | Where-Object { $_.RouteMetric -lt 9999 } |
    Select-Object InterfaceAlias, DestinationPrefix, NextHop, RouteMetric | Format-Table -AutoSize

SubSection "Table ARP"
arp -a

SubSection "DNS Cache"
Get-DnsClientCache | Select-Object Entry, RecordType, Data, TimeToLive | Format-Table -AutoSize

SubSection "Configuration DNS"
Get-DnsClientServerAddress | Select-Object InterfaceAlias, AddressFamily, ServerAddresses | Format-Table -AutoSize

SubSection "Adaptateurs reseau binding (IPv6, LLDP, etc)"
Get-NetAdapterBinding | Select-Object Name, ComponentID, DisplayName, Enabled | Format-Table -AutoSize

# ============================================================
Section "3 - PORTS & CONNEXIONS RESEAU"
# ============================================================
SubSection "Ports en ecoute (LISTENING) avec PID"
netstat -ano | findstr "LISTENING"

SubSection "Connexions etablies (ESTABLISHED)"
netstat -ano | findstr "ESTABLISHED"

SubSection "Correspondance PID -> Processus"
$listening = netstat -ano | Select-String "LISTENING|ESTABLISHED"
$pids = $listening | ForEach-Object { ($_ -split "\s+")[-1] } | Sort-Object -Unique
foreach ($p in $pids) {
    $proc = Get-Process -Id $p -ErrorAction SilentlyContinue
    if ($proc) {
        [PSCustomObject]@{
            PID = $p
            Nom = $proc.Name
            Chemin = $proc.Path
            Utilisateur = (Get-WmiObject Win32_Process -Filter "ProcessId=$p" -ErrorAction SilentlyContinue).GetOwner().User
        }
    }
} | Format-Table -AutoSize

# ============================================================
Section "4 - FIREWALL"
# ============================================================
SubSection "Etat global du firewall"
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction,
    LogAllowed, LogBlocked, LogFileName | Format-Table -AutoSize

SubSection "Regles INBOUND actives"
Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" } |
    Select-Object DisplayName, Profile, Action, Direction, Description |
    Sort-Object DisplayName | Format-Table -AutoSize

SubSection "Regles OUTBOUND actives (Block uniquement)"
Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Outbound" -and $_.Action -eq "Block" } |
    Select-Object DisplayName, Profile, Action | Format-Table -AutoSize

SubSection "Regles critiques : SMB / RDP / WinRM / SSH / UPnP / Print / NetBIOS / LLMNR / mDNS / VPN / Docker / WSL / Hyper-V / VMware"
Get-NetFirewallRule | Where-Object {
    $_.DisplayName -match "SMB|Partage|File and Printer|UPnP|Remote Desktop|Bureau a distance|SSH|WinRM|Teredo|IPHTTPS|Hyper-V|Docker|WSL|VPN|PPTP|L2TP|IKE|mDNS|LLMNR|NetBIOS|Spooler|Print|VMware|SSDP|1900|445|139|137|138|3389|5985|5986|22"
} | Select-Object DisplayName, Enabled, Profile, Action, Direction | Format-Table -AutoSize

# ============================================================
Section "5 - SERVICES WINDOWS"
# ============================================================
SubSection "Tous les services en cours d execution"
Get-Service | Where-Object { $_.Status -eq "Running" } |
    Select-Object Name, DisplayName, Status, StartType | Sort-Object Name | Format-Table -AutoSize

SubSection "Services critiques - etat detaille"
$critiques = @(
    # Reseau & Partage
    "LanmanServer", "LanmanWorkstation", "MrxSmb10", "MrxSmb20",
    # Acces distant
    "SSHD", "ssh-agent", "WinRM", "TermService", "SessionEnv", "UmRdpService",
    "RemoteRegistry", "RemoteAccess",
    # VMware
    "VMware NAT Service", "VMwareHostd", "VMAuthdService", "VMnetDHCP",
    "VMUSBArbService", "VMwareHostd",
    # Hyper-V
    "vmms", "HvHost", "vmicheartbeat", "vmicvss",
    # Docker / WSL
    "com.docker.service", "WslService", "LxssManager",
    # Impression
    "Spooler",
    # UPnP / Discovery
    "SSDPSRV", "upnphost", "FDResPub", "fdPHost",
    "lltdsvc", "NlaSvc", "DNSCache",
    # Securite
    "MpsSvc", "SecurityHealthService", "wscsvc", "WdNisSvc", "WinDefend",
    # Misc
    "W32Time", "Netlogon", "wuauserv", "BITS", "EventLog", "Schedule"
)
$results = foreach ($svc in $critiques) {
    Get-Service -Name $svc -ErrorAction SilentlyContinue |
        Select-Object Name, DisplayName, Status, StartType
}
$results | Format-Table -AutoSize

SubSection "Services VMware (detection auto)"
Get-Service | Where-Object { $_.Name -match "VMware|vmware|vmnat|vmnetdhcp|vmx" } |
    Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize

SubSection "Services SSH (detection auto)"
Get-Service | Where-Object { $_.Name -match "ssh|sshd|openssh" } |
    Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize

SubSection "Services Docker/WSL/Hyper-V (detection auto)"
Get-Service | Where-Object { $_.Name -match "docker|wsl|lxss|vmms|HvHost" } |
    Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize

SubSection "Services VPN (detection auto)"
Get-Service | Where-Object { $_.Name -match "vpn|cisco|pulse|globalprotect|ivpn|nordvpn|expressvpn|openvpn|wireguard" } |
    Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize

# ============================================================
Section "6 - PROTOCOLES SMB"
# ============================================================
SubSection "SMB via registre"
$smb1 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -ErrorAction SilentlyContinue
$smb2 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB2 -ErrorAction SilentlyContinue
if ($smb1) { "SMB1 (registre) : $($smb1.SMB1)  [0=desactive, 1=actif]" }
else { "SMB1 : cle absente => desactive par defaut (W10/W11)" }
if ($smb2) { "SMB2 (registre) : $($smb2.SMB2)  [0=desactive, 1=actif]" }
else { "SMB2 : cle absente => actif par defaut" }

SubSection "SMB via Get-SmbServerConfiguration"
try {
    $smb = Get-SmbServerConfiguration -ErrorAction Stop
    [PSCustomObject]@{
        SMB1_Actif              = $smb.EnableSMB1Protocol
        SMB2_Actif              = $smb.EnableSMB2Protocol
        SignatureRequise        = $smb.RequireSecuritySignature
        SignatureActivee        = $smb.EnableSecuritySignature
        Chiffrement             = $smb.EncryptData
        NullSessionPipes        = $smb.NullSessionPipes
        NullSessionShares       = $smb.NullSessionShares
        AutoDeconnexion_min     = $smb.AutoDisconnectTimeout
        MaxWorkItems            = $smb.MaxWorkItems
    } | Format-List
} catch { "Get-SmbServerConfiguration indisponible : $_" }

SubSection "Partages SMB actifs"
Get-SmbShare -ErrorAction SilentlyContinue |
    Select-Object Name, Path, Description, CurrentUsers, ShareState, FolderEnumerationMode | Format-Table -AutoSize

SubSection "Sessions SMB ouvertes"
Get-SmbSession -ErrorAction SilentlyContinue |
    Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists | Format-Table -AutoSize

SubSection "Connexions SMB ouvertes"
Get-SmbConnection -ErrorAction SilentlyContinue |
    Select-Object ServerName, ShareName, UserName, Dialect, NumOpens | Format-Table -AutoSize

# ============================================================
Section "7 - RDP / ACCES DISTANT"
# ============================================================
SubSection "Etat RDP"
$rdp = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue
if ($rdp) {
    if ($rdp.fDenyTSConnections -eq 0) { "RDP : ACTIF (fDenyTSConnections=0)" }
    else { "RDP : DESACTIVE (fDenyTSConnections=$($rdp.fDenyTSConnections))" }
}

SubSection "NLA (Network Level Authentication)"
$nla = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction SilentlyContinue
if ($nla) { "NLA : $($nla.UserAuthentication)  [1=requis (securise), 0=desactive]" }

SubSection "Port RDP"
$port = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name PortNumber -ErrorAction SilentlyContinue
if ($port) { "Port RDP : $($port.PortNumber)" }

SubSection "WinRM - Etat"
$winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
"WinRM Status : $($winrm.Status) | StartType : $($winrm.StartType)"
winrm enumerate winrm/config/listener 2>$null

SubSection "RemoteRegistry"
$rr = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
"RemoteRegistry : $($rr.Status) | StartType : $($rr.StartType)"

# ============================================================
Section "8 - IPv6 / TEREDO / IPHTTPS / NetBIOS / LLMNR"
# ============================================================
SubSection "IPv6 par interface"
Get-NetAdapterBinding | Where-Object { $_.ComponentID -eq "ms_tcpip6" } |
    Select-Object Name, Enabled | Format-Table -AutoSize

SubSection "Teredo"
netsh interface teredo show state

SubSection "IPHTTPS"
netsh interface httpstunnel show interfaces

SubSection "NetBIOS sur TCP/IP"
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue
foreach ($a in $adapters | Where-Object { $_.IPEnabled }) {
    [PSCustomObject]@{
        Description = $a.Description
        NetBIOS     = switch ($a.TcpipNetbiosOptions) {
            0 { "Via DHCP" }
            1 { "ACTIF" }
            2 { "DESACTIVE" }
            default { "Inconnu ($($a.TcpipNetbiosOptions))" }
        }
    }
} | Format-Table -AutoSize

SubSection "LLMNR (registre)"
$llmnr = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue
if ($llmnr) { "LLMNR EnableMulticast : $($llmnr.EnableMulticast)  [0=desactive]" }
else { "LLMNR : aucune GPO trouvee => probablement ACTIF par defaut" }

SubSection "mDNS"
$mdns = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableMDNS -ErrorAction SilentlyContinue
if ($mdns) { "mDNS : $($mdns.EnableMDNS)  [0=desactive]" }
else { "mDNS : cle absente => actif par defaut" }

# ============================================================
Section "9 - ICMP / PING"
# ============================================================
Get-NetFirewallRule | Where-Object { $_.DisplayName -match "ICMP|Ping|Echo" } |
    Select-Object DisplayName, Enabled, Direction, Action, Profile | Format-Table -AutoSize

# ============================================================
Section "10 - PROCESSUS SUSPECTS"
# ============================================================
SubSection "Processus avec connexions reseau actives"
$netProcs = netstat -ano | Select-String "ESTABLISHED|LISTENING" |
    ForEach-Object { ($_ -split "\s+")[-1] } | Sort-Object -Unique
foreach ($p in $netProcs) {
    $proc = Get-Process -Id $p -ErrorAction SilentlyContinue
    if ($proc) {
        [PSCustomObject]@{
            PID     = $p
            Nom     = $proc.Name
            Chemin  = $proc.Path
            CPU     = $proc.CPU
            Memoire = "$([math]::Round($proc.WorkingSet64/1MB,1)) MB"
        }
    }
} | Format-Table -AutoSize

SubSection "Processus sans chemin connu (suspects)"
Get-Process | Where-Object { $_.Path -eq $null -and $_.Name -notmatch "Idle|System|Registry|smss|csrss|wininit|services|lsass|svchost|fontdrvhost|dwm" } |
    Select-Object Id, Name, CPU, Handles | Format-Table -AutoSize

SubSection "Taches planifiees actives (non-Microsoft)"
Get-ScheduledTask | Where-Object {
    $_.State -eq "Ready" -and $_.TaskPath -notmatch "\\Microsoft\\"
} | Select-Object TaskName, TaskPath, State |
    Sort-Object TaskPath | Format-Table -AutoSize

# ============================================================
Section "11 - REGISTRE : PERSISTANCE & SECURITE"
# ============================================================
SubSection "Run Keys (demarrage auto utilisateur)"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue

SubSection "LSA Protection"
$lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
"LmCompatibilityLevel : $($lsa.LmCompatibilityLevel)  [5=NTLMv2 uniquement, recommande]"
"NoLMHash             : $($lsa.NoLMHash)  [1=pas de hash LM, recommande]"
"RunAsPPL             : $($lsa.RunAsPPL)  [1=LSA protege, recommande]"
"RestrictAnonymous    : $($lsa.RestrictAnonymous)"
"RestrictAnonymousSAM : $($lsa.RestrictAnonymousSAM)"

SubSection "UAC"
$uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
"EnableLUA                   : $($uac.EnableLUA)  [1=UAC actif]"
"ConsentPromptBehaviorAdmin  : $($uac.ConsentPromptBehaviorAdmin)  [2=invite credentials, 5=invite confirmation]"
"LocalAccountTokenFilterPolicy : $($uac.LocalAccountTokenFilterPolicy)  [0=recommande]"

SubSection "PowerShell ScriptBlock Logging"
$pslogs = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
if ($pslogs) { "ScriptBlock Logging : $($pslogs.EnableScriptBlockLogging)" }
else { "ScriptBlock Logging : NON CONFIGURE (desactive)" }

# ============================================================
Section "12 - WINDOWS DEFENDER / ANTIVIRUS"
# ============================================================
SubSection "Etat Windows Defender"
Get-MpComputerStatus -ErrorAction SilentlyContinue |
    Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled,
    RealTimeProtectionEnabled, IoavProtectionEnabled, NISEnabled,
    AntivirusSignatureLastUpdated, QuickScanAge | Format-List

SubSection "Exclusions Defender (risque potentiel)"
$excl = Get-MpPreference -ErrorAction SilentlyContinue
"Exclusions Paths    : $($excl.ExclusionPath -join ', ')"
"Exclusions Process  : $($excl.ExclusionProcess -join ', ')"
"Exclusions Ext      : $($excl.ExclusionExtension -join ', ')"

# ============================================================
Section "13 - EVENEMENTS SECURITE RECENTS"
# ============================================================
SubSection "Echecs de connexion (4625) - 10 derniers"
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4625]]" -MaxEvents 10 -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Heure   = $_.TimeCreated
            Message = ($_.Message -split "`n")[0..3] -join " | "
        }
    } | Format-Table -AutoSize -Wrap

SubSection "Connexions reussies (4624) - 10 derniers"
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 10 -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Heure   = $_.TimeCreated
            Message = ($_.Message -split "`n")[0..2] -join " | "
        }
    } | Format-Table -AutoSize -Wrap

SubSection "Services installes recemment (7045)"
Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7045]]" -MaxEvents 10 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Format-List

# ============================================================
Section "14 - MISES A JOUR WINDOWS"
# ============================================================
SubSection "Derniers hotfix installes"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 |
    Select-Object HotFixID, Description, InstalledOn, InstalledBy | Format-Table -AutoSize

SubSection "Windows Update - derniere verification"
$wu = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" -ErrorAction SilentlyContinue
if ($wu) { "Derniere detection WU : $($wu.LastSuccessTime)" }

# ============================================================
Section "15 - CHIFFREMENT & CERTIFICATS"
# ============================================================
SubSection "BitLocker"
manage-bde -status 2>$null

SubSection "Certificats Machine (expiration < 90 jours)"
Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.NotAfter -lt (Get-Date).AddDays(90) } |
    Select-Object Subject, NotAfter, Thumbprint | Format-Table -AutoSize

# ============================================================
Write-Host "`n================================================================" -ForegroundColor Green
Write-Host "  FIN DE L AUDIT SOC/DFIR - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
Write-Host "================================================================`n" -ForegroundColor Green
'@

$script | Out-File "$env:TEMP\audit_soc.ps1" -Encoding UTF8
Write-Host "Script sauvegarde : $env:TEMP\audit_soc.ps1" -ForegroundColor Yellow
Write-Host "Lancement de l audit..." -ForegroundColor Cyan
powershell -ExecutionPolicy Bypass -File "$env:TEMP\audit_soc.ps1" | Tee-Object "$env:TEMP\audit_soc_result.txt"
Write-Host "`nRapport sauvegarde : $env:TEMP\audit_soc_result.txt" -ForegroundColor Green
notepad "$env:TEMP\audit_soc_result.txt"
