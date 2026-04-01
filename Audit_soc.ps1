$script = @'
# ============================================================
# AUDIT SECURITE WINDOWS - NIVEAU SOC/DFIR
# Version : v2 - Corrigee & Durcie
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

# Helper : collecte propre dans un foreach pour eviter EmptyPipeElement
function Invoke-CollectLoop {
    param([scriptblock]$Block)
    $results = & $Block
    if ($results) { $results | Format-Table -AutoSize }
    else { Write-Host "  (aucun resultat)" -ForegroundColor DarkGray }
}

# ============================================================
Section "1 - SYSTEME & IDENTITE"
# ============================================================
SubSection "Informations systeme"
try {
    Get-ComputerInfo -ErrorAction Stop |
        Select-Object CsName, WindowsProductName, WindowsVersion, OsArchitecture,
            CsProcessors, CsTotalPhysicalMemory, OsLastBootUpTime, OsInstallDate |
        Format-List
} catch { "Get-ComputerInfo indisponible : $_" }

SubSection "Utilisateur courant et groupes"
whoami /all

SubSection "Utilisateurs locaux"
Get-LocalUser -ErrorAction SilentlyContinue |
    Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet,
        AccountExpires, Description | Format-Table -AutoSize

SubSection "Groupes locaux et membres"
# CORRECTION BUG #1 : foreach -> pipeline direct via collect, evite EmptyPipeElement
$grpResults = foreach ($grp in (Get-LocalGroup -ErrorAction SilentlyContinue)) {
    $members = Get-LocalGroupMember -Group $grp.Name -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Name
    [PSCustomObject]@{ Groupe = $grp.Name; Membres = ($members -join ", ") }
}
if ($grpResults) { $grpResults | Format-Table -AutoSize }

SubSection "Sessions actives"
query session 2>$null

SubSection "Derniers logons (Eventlog 4624) - 20 derniers"
# CORRECTION : Message brut trop verbeux -> parsing XML pour donnees exploitables
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 20 -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $xml = [xml]$_.ToXml()
            $data = $xml.Event.EventData.Data
            $logonType = ($data | Where-Object { $_.Name -eq "LogonType" }).'#text'
            $user      = ($data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
            $domain    = ($data | Where-Object { $_.Name -eq "TargetDomainName" }).'#text'
            $ip        = ($data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
            [PSCustomObject]@{
                Heure      = $_.TimeCreated
                Utilisateur = "$domain\$user"
                LogonType  = $logonType
                IP         = $ip
            }
        } catch { $null }
    } | Where-Object { $_ } | Format-Table -AutoSize

# ============================================================
Section "2 - RESEAU : PROFIL & INTERFACES"
# ============================================================
SubSection "Profil reseau"
Get-NetConnectionProfile -ErrorAction SilentlyContinue |
    Select-Object Name, NetworkCategory, IPv4Connectivity, IPv6Connectivity | Format-Table -AutoSize

SubSection "Interfaces reseau"
Get-NetIPAddress -ErrorAction SilentlyContinue |
    Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength, SuffixOrigin | Format-Table -AutoSize

SubSection "Routes actives"
Get-NetRoute -ErrorAction SilentlyContinue |
    Where-Object { $_.RouteMetric -lt 9999 } |
    Select-Object InterfaceAlias, DestinationPrefix, NextHop, RouteMetric | Format-Table -AutoSize

SubSection "Table ARP"
arp -a

SubSection "DNS Cache"
Get-DnsClientCache -ErrorAction SilentlyContinue |
    Select-Object Entry, RecordType, Data, TimeToLive | Format-Table -AutoSize

SubSection "Configuration DNS"
Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
    Select-Object InterfaceAlias, AddressFamily, ServerAddresses | Format-Table -AutoSize

SubSection "Adaptateurs reseau binding (IPv6, LLDP, etc)"
Get-NetAdapterBinding -ErrorAction SilentlyContinue |
    Select-Object Name, ComponentID, DisplayName, Enabled | Format-Table -AutoSize

# ============================================================
Section "3 - PORTS & CONNEXIONS RESEAU"
# ============================================================
SubSection "Ports en ecoute (LISTENING) avec PID"
netstat -ano | findstr "LISTENING"

SubSection "Connexions etablies (ESTABLISHED)"
netstat -ano | findstr "ESTABLISHED"

SubSection "Correspondance PID -> Processus"
# CORRECTION BUG #2 : foreach + PSCustomObject ne peut pas etre pipe directement
# -> collecte dans variable puis Format-Table
# CORRECTION SUPPLEMENTAIRE : GetOwner() via CIM (WMI deprecie sous PS7+)
$listening2 = netstat -ano | Select-String "LISTENING|ESTABLISHED"
$pids2 = $listening2 | ForEach-Object { ($_ -split "\s+")[-1] } |
    Where-Object { $_ -match '^\d+$' } | Sort-Object -Unique

$pidResults = foreach ($p in $pids2) {
    $proc = Get-Process -Id $p -ErrorAction SilentlyContinue
    if ($proc) {
        $owner = try {
            (Get-CimInstance Win32_Process -Filter "ProcessId=$p" -ErrorAction SilentlyContinue).GetOwner().User
        } catch { "N/A" }
        [PSCustomObject]@{
            PID         = $p
            Nom         = $proc.Name
            Chemin      = $proc.Path
            Utilisateur = $owner
        }
    }
}
if ($pidResults) { $pidResults | Format-Table -AutoSize }

# ============================================================
Section "4 - FIREWALL"
# ============================================================
SubSection "Etat global du firewall"
Get-NetFirewallProfile -ErrorAction SilentlyContinue |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction,
        LogAllowed, LogBlocked, LogFileName | Format-Table -AutoSize

SubSection "Regles INBOUND actives"
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" } |
    Select-Object DisplayName, Profile, Action, Direction, Description |
    Sort-Object DisplayName | Format-Table -AutoSize

SubSection "Regles OUTBOUND actives (Block uniquement)"
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Outbound" -and $_.Action -eq "Block" } |
    Select-Object DisplayName, Profile, Action | Format-Table -AutoSize

SubSection "Regles critiques : SMB / RDP / WinRM / SSH / UPnP / NetBIOS / LLMNR / mDNS / VPN / Docker / WSL / Hyper-V / VMware"
Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -match "SMB|Partage|File and Printer|UPnP|Remote Desktop|Bureau a distance|SSH|WinRM|Teredo|IPHTTPS|Hyper-V|Docker|WSL|VPN|PPTP|L2TP|IKE|mDNS|LLMNR|NetBIOS|Spooler|Print|VMware|SSDP|1900|445|139|137|138|3389|5985|5986|22"
} | Select-Object DisplayName, Enabled, Profile, Action, Direction | Format-Table -AutoSize

# ============================================================
Section "5 - SERVICES WINDOWS"
# ============================================================
SubSection "Tous les services en cours d execution"
Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq "Running" } |
    Select-Object Name, DisplayName, Status, StartType | Sort-Object Name | Format-Table -AutoSize

SubSection "Services critiques - etat detaille"
$critiques = @(
    "LanmanServer","LanmanWorkstation","MrxSmb10","MrxSmb20",
    "SSHD","ssh-agent","WinRM","TermService","SessionEnv","UmRdpService",
    "RemoteRegistry","RemoteAccess",
    "VMware NAT Service","VMwareHostd","VMAuthdService","VMnetDHCP",
    "VMUSBArbService",
    "vmms","HvHost","vmicheartbeat","vmicvss",
    "com.docker.service","WslService","LxssManager",
    "Spooler",
    "SSDPSRV","upnphost","FDResPub","fdPHost",
    "lltdsvc","NlaSvc","DNSCache",
    "MpsSvc","SecurityHealthService","wscsvc","WdNisSvc","WinDefend",
    "W32Time","Netlogon","wuauserv","BITS","EventLog","Schedule"
)
$svcResults = foreach ($svc in $critiques) {
    Get-Service -Name $svc -ErrorAction SilentlyContinue |
        Select-Object Name, DisplayName, Status, StartType
}
if ($svcResults) { $svcResults | Format-Table -AutoSize }

SubSection "Services VMware (detection auto)"
Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "VMware|vmware|vmnat|vmnetdhcp|vmx" } |
    Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize

SubSection "Services SSH (detection auto)"
Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "ssh|sshd|openssh" } |
    Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize

SubSection "Services Docker/WSL/Hyper-V (detection auto)"
Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "docker|wsl|lxss|vmms|HvHost" } |
    Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize

SubSection "Services VPN (detection auto)"
Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "vpn|cisco|pulse|globalprotect|ivpn|nordvpn|expressvpn|openvpn|wireguard" } |
    Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize

SubSection "Services avec chemin non quote (PrivEsc local)"
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -notmatch '^"' -and $_.PathName -match ' '} | 
    Select-Object Name, PathName, StartMode

# ============================================================
Section "6 - PROTOCOLES SMB"
# ============================================================
SubSection "SMB via registre"
$smb1 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -ErrorAction SilentlyContinue
$smb2 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB2 -ErrorAction SilentlyContinue
if ($smb1) { "SMB1 (registre) : $($smb1.SMB1)  [0=desactive, 1=actif]" }
else        { "SMB1 : cle absente => desactive par defaut (W10/W11)" }
if ($smb2) { "SMB2 (registre) : $($smb2.SMB2)  [0=desactive, 1=actif]" }
else        { "SMB2 : cle absente => actif par defaut" }

SubSection "SMB via Get-SmbServerConfiguration"
try {
    $smb = Get-SmbServerConfiguration -ErrorAction Stop
    [PSCustomObject]@{
        SMB1_Actif          = $smb.EnableSMB1Protocol
        SMB2_Actif          = $smb.EnableSMB2Protocol
        SignatureRequise     = $smb.RequireSecuritySignature
        SignatureActivee     = $smb.EnableSecuritySignature
        Chiffrement          = $smb.EncryptData
        NullSessionPipes     = $smb.NullSessionPipes
        NullSessionShares    = $smb.NullSessionShares
        AutoDeconnexion_min  = $smb.AutoDisconnectTimeout
        MaxWorkItems         = $smb.MaxWorkItems
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
} else { "RDP : cle registre introuvable" }

SubSection "NLA (Network Level Authentication)"
$nla = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction SilentlyContinue
if ($nla) { "NLA : $($nla.UserAuthentication)  [1=requis (securise), 0=desactive]" }
else       { "NLA : cle introuvable (RDP probablement desactive)" }

SubSection "Port RDP"
$rdpPort = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name PortNumber -ErrorAction SilentlyContinue
if ($rdpPort) { "Port RDP : $($rdpPort.PortNumber)  [defaut=3389]" }

SubSection "WinRM - Etat"
$winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($winrm) { "WinRM Status : $($winrm.Status) | StartType : $($winrm.StartType)" }
else        { "WinRM : service introuvable" }
winrm enumerate winrm/config/listener 2>$null

SubSection "RemoteRegistry"
$rr = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
if ($rr) { "RemoteRegistry : $($rr.Status) | StartType : $($rr.StartType)" }
else     { "RemoteRegistry : service introuvable" }

# ============================================================
Section "8 - IPv6 / TEREDO / IPHTTPS / NetBIOS / LLMNR"
# ============================================================
SubSection "IPv6 par interface"
Get-NetAdapterBinding -ErrorAction SilentlyContinue |
    Where-Object { $_.ComponentID -eq "ms_tcpip6" } |
    Select-Object Name, Enabled | Format-Table -AutoSize

SubSection "Teredo"
netsh interface teredo show state

SubSection "IPHTTPS"
netsh interface httpstunnel show interfaces

SubSection "NetBIOS sur TCP/IP"
# CORRECTION BUG #3 : foreach + PSCustomObject ne peut pas etre pipe directement
$netbiosResults = foreach ($a in (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPEnabled })) {
    [PSCustomObject]@{
        Description = $a.Description
        NetBIOS     = switch ($a.TcpipNetbiosOptions) {
            0 { "Via DHCP" }
            1 { "ACTIF" }
            2 { "DESACTIVE" }
            default { "Inconnu ($($a.TcpipNetbiosOptions))" }
        }
    }
}
if ($netbiosResults) { $netbiosResults | Format-Table -AutoSize }

SubSection "LLMNR (registre)"
$llmnr = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue
if ($llmnr) { "LLMNR EnableMulticast : $($llmnr.EnableMulticast)  [0=desactive]" }
else        { "LLMNR : aucune GPO trouvee => probablement ACTIF par defaut" }

SubSection "mDNS"
$mdns = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableMDNS -ErrorAction SilentlyContinue
if ($mdns) { "mDNS : $($mdns.EnableMDNS)  [0=desactive]" }
else       { "mDNS : cle absente => actif par defaut" }

# ============================================================
Section "9 - ICMP / PING"
# ============================================================
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match "ICMP|Ping|Echo" } |
    Select-Object DisplayName, Enabled, Direction, Action, Profile | Format-Table -AutoSize

# ============================================================
Section "10 - PROCESSUS SUSPECTS"
# ============================================================
SubSection "Processus avec connexions reseau actives"
# CORRECTION : meme pattern que section 3 - collecte dans variable
$netProcs = netstat -ano | Select-String "ESTABLISHED|LISTENING" |
    ForEach-Object { ($_ -split "\s+")[-1] } |
    Where-Object { $_ -match '^\d+$' } | Sort-Object -Unique

$procResults = foreach ($p in $netProcs) {
    $proc = Get-Process -Id $p -ErrorAction SilentlyContinue
    if ($proc) {
        [PSCustomObject]@{
            PID     = $p
            Nom     = $proc.Name
            Chemin  = $proc.Path
            CPU     = [math]::Round($proc.CPU, 2)
            Memoire = "$([math]::Round($proc.WorkingSet64/1MB,1)) MB"
        }
    }
}
if ($procResults) { $procResults | Format-Table -AutoSize }

SubSection "Processus sans chemin connu (suspects)"
Get-Process -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Path -eq $null -and
        $_.Name -notmatch "^(Idle|System|Registry|smss|csrss|wininit|services|lsass|fontdrvhost|dwm|svchost|conhost|WerFault|WUDFHost|NisSrv|MsMpEng)$"
    } |
    Select-Object Id, Name, CPU, Handles | Format-Table -AutoSize

SubSection "Taches planifiees actives (non-Microsoft)"
Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq "Ready" -and $_.TaskPath -notmatch "\\Microsoft\\" } |
    Select-Object TaskName, TaskPath, State |
    Sort-Object TaskPath | Format-Table -AutoSize

# BONUS : detail des actions des taches suspectes
SubSection "Actions des taches planifiees non-Microsoft"
Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.State -ne "Disabled" -and $_.TaskPath -notmatch "\\Microsoft\\" } |
    ForEach-Object {
        $t = $_
        foreach ($a in $t.Actions) {
            [PSCustomObject]@{
                Tache    = $t.TaskName
                Execute  = $a.Execute
                Args     = $a.Arguments
            }
        }
    } | Format-Table -AutoSize

# ============================================================
Section "11 - REGISTRE : PERSISTANCE & SECURITE"
# ============================================================
SubSection "Run Keys (demarrage auto)"
$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($key in $runKeys) {
    $val = Get-ItemProperty $key -ErrorAction SilentlyContinue
    if ($val) {
        Write-Host "  $key" -ForegroundColor Cyan
        $val.PSObject.Properties |
            Where-Object { $_.Name -notmatch "^PS" } |
            ForEach-Object { "    $($_.Name) = $($_.Value)" }
    }
}

SubSection "LSA Protection"
$lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
if ($lsa) {
    "LmCompatibilityLevel : $($lsa.LmCompatibilityLevel)  [5=NTLMv2 uniquement, recommande]"
    "NoLMHash             : $($lsa.NoLMHash)  [1=pas de hash LM, recommande]"
    "RunAsPPL             : $($lsa.RunAsPPL)  [1=LSA protege, recommande]"
    "RestrictAnonymous    : $($lsa.RestrictAnonymous)"
    "RestrictAnonymousSAM : $($lsa.RestrictAnonymousSAM)"
} else { "Cle LSA introuvable" }

SubSection "UAC"
$uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
if ($uac) {
    "EnableLUA                   : $($uac.EnableLUA)  [1=UAC actif]"
    "ConsentPromptBehaviorAdmin  : $($uac.ConsentPromptBehaviorAdmin)  [2=credentials, 5=confirmation]"
    "LocalAccountTokenFilterPolicy : $($uac.LocalAccountTokenFilterPolicy)  [0=recommande]"
} else { "Cle UAC introuvable" }

SubSection "PowerShell ScriptBlock Logging"
$pslogs = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
if ($pslogs) { "ScriptBlock Logging : $($pslogs.EnableScriptBlockLogging)  [1=actif, recommande]" }
else         { "ScriptBlock Logging : NON CONFIGURE (desactive)" }

# BONUS : Module Logging PS
$psmod = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
if ($psmod) { "Module Logging : $($psmod.EnableModuleLogging)" }
else        { "Module Logging : NON CONFIGURE (desactive)" }

# BONUS : Transcription PS
$pstrans = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
if ($pstrans) { "Transcription PS : $($pstrans.EnableTranscripting)" }
else          { "Transcription PS : NON CONFIGURE (desactive)" }

# BONUS : Verif AMSI bypass connu (registre)
SubSection "AMSI (Antimalware Scan Interface)"
$amsi = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\AMSI" -ErrorAction SilentlyContinue
if ($amsi) { $amsi | Format-List }
else       { "Cle AMSI non trouvee (normal si non modifiee)" }

# ============================================================
Section "12 - WINDOWS DEFENDER / ANTIVIRUS"
# ============================================================
SubSection "Etat Windows Defender"
try {
    Get-MpComputerStatus -ErrorAction Stop |
        Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled,
            RealTimeProtectionEnabled, IoavProtectionEnabled, NISEnabled,
            AntivirusSignatureLastUpdated, QuickScanAge | Format-List
} catch { "Windows Defender indisponible ou remplace par un AV tiers : $_" }

SubSection "Exclusions Defender (risque potentiel)"
try {
    $excl = Get-MpPreference -ErrorAction Stop
    "Exclusions Paths    : $(($excl.ExclusionPath    -join ', ') | Where-Object {$_} | Select-Object -First 1; if (-not $excl.ExclusionPath) {'(aucune)'})"
    "Exclusions Process  : $(if ($excl.ExclusionProcess) { $excl.ExclusionProcess -join ', ' } else { '(aucune)' })"
    "Exclusions Ext      : $(if ($excl.ExclusionExtension) { $excl.ExclusionExtension -join ', ' } else { '(aucune)' })"
} catch { "Impossible de lire les preferences Defender : $_" }

# ============================================================
Section "13 - EVENEMENTS SECURITE RECENTS"
# ============================================================
SubSection "Echecs de connexion (4625) - 10 derniers"
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4625]]" -MaxEvents 10 -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $xml  = [xml]$_.ToXml()
            $data = $xml.Event.EventData.Data
            [PSCustomObject]@{
                Heure       = $_.TimeCreated
                Utilisateur = ($data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                IP          = ($data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
                LogonType   = ($data | Where-Object { $_.Name -eq "LogonType" }).'#text'
            }
        } catch { $null }
    } | Where-Object { $_ } | Format-Table -AutoSize

SubSection "Connexions reussies (4624) - 10 derniers"
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 10 -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $xml  = [xml]$_.ToXml()
            $data = $xml.Event.EventData.Data
            [PSCustomObject]@{
                Heure       = $_.TimeCreated
                Utilisateur = ($data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                LogonType   = ($data | Where-Object { $_.Name -eq "LogonType" }).'#text'
                IP          = ($data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
            }
        } catch { $null }
    } | Where-Object { $_ } | Format-Table -AutoSize

SubSection "Services installes recemment (7045)"
Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7045]]" -MaxEvents 10 -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $xml  = [xml]$_.ToXml()
            $data = $xml.Event.EventData.Data
            [PSCustomObject]@{
                Heure   = $_.TimeCreated
                Service = ($data | Where-Object { $_.Name -eq "ServiceName" }).'#text'
                Chemin  = ($data | Where-Object { $_.Name -eq "ImagePath" }).'#text'
                Type    = ($data | Where-Object { $_.Name -eq "ServiceType" }).'#text'
            }
        } catch { $null }
    } | Where-Object { $_ } | Format-Table -AutoSize

# BONUS : Audit policy clearing (1102)
SubSection "Effacement des logs (1102) - 5 derniers"
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=1102]]" -MaxEvents 5 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Format-List

# BONUS : Ajout membre groupe privilegie (4732/4728)
SubSection "Ajout dans groupes privilegies (4732/4728) - 10 derniers"
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4732 or EventID=4728]]" -MaxEvents 10 -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $xml  = [xml]$_.ToXml()
            $data = $xml.Event.EventData.Data
            [PSCustomObject]@{
                Heure   = $_.TimeCreated
                EID     = $_.Id
                Compte  = ($data | Where-Object { $_.Name -eq "MemberName" }).'#text'
                Groupe  = ($data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                Par     = ($data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
            }
        } catch { $null }
    } | Where-Object { $_ } | Format-Table -AutoSize

# ============================================================
Section "14 - MISES A JOUR WINDOWS"
# ============================================================
SubSection "Derniers hotfix installes"
Get-HotFix -ErrorAction SilentlyContinue |
    Sort-Object InstalledOn -Descending | Select-Object -First 15 |
    Select-Object HotFixID, Description, InstalledOn, InstalledBy | Format-Table -AutoSize

SubSection "Windows Update - derniere verification"
$wu = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" -ErrorAction SilentlyContinue
if ($wu) { "Derniere detection WU : $($wu.LastSuccessTime)" }
else     { "Cle WU introuvable" }

# ============================================================
Section "15 - CHIFFREMENT & CERTIFICATS"
# ============================================================
SubSection "BitLocker"
try {
    manage-bde -status 2>$null
} catch { "manage-bde indisponible : $_" }

SubSection "Certificats Machine expirant dans < 90 jours"
Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.NotAfter -lt (Get-Date).AddDays(90) } |
    Select-Object Subject, NotAfter, Thumbprint | Format-Table -AutoSize

SubSection "Certificats racine non-Microsoft (verification manuelle recommandee)"
Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
    Where-Object { $_.Issuer -notmatch "Microsoft|Thawte|DigiCert|Comodo|Sectigo|GlobalSign|VeriSign|Let.s Encrypt|ISRG|Baltimore|Symantec|GeoTrust|AddTrust" } |
    Select-Object Subject, Issuer, NotAfter, Thumbprint | Format-Table -AutoSize

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
