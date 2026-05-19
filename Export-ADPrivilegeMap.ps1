<#
.SYNOPSIS
    AD Privilege Map - voll aufgeloeste Beziehungsmap aller privilegierten AD-Objekte.

.DESCRIPTION
    Build 3: A2 wird kontrolliert, damit die Konvergenz nicht explodiert.

      1. A2 (User-Membership-Walk) laeuft per Default nur fuer User mit
         AdminCount=1. Normale User werden nicht lateral expandiert.
      2. Gruppen, die ausschliesslich ueber A2 entdeckt wurden ("LateralOnly"),
         werden in der Konvergenz NICHT weiter expandiert. Es gibt eine Edge
         vom priv. User zur lateralen Gruppe, aber die Members der lateralen
         Gruppe kommen nicht in den Graph.

    Datenebene:
      A1: Auto-Discovery aller Gruppen mit AdminCount=1 als Tier-0-Roots
      A2: User-Membership-Walk (Default nur AdminCount=1-User, lateral begrenzt)
      A3: SDProp-Waisen (User mit AdminCount=1 ohne Membership in Tier-0)
      A4: PrimaryGroupID-Reverse-Lookup (nur fuer AdminCount=1-Gruppen)
      A5: Iterative Konvergenz bis keine neuen Nodes mehr dazukommen

    Darstellung:
      B6: Layout-Umschalter Physics / Hierarchisch (Tier-0 oben)
      B7: Filter-Toolbar (Tier-0, aktive User, Computer/FSP, laterale Gruppen,
          Min-Memberships, Suche)

    Bedienung:
      C10: Write-Progress fuer alle Schleifen

.PARAMETER OutputPath
    Zielordner.

.PARAMETER MaxDepth
    Maximale Rekursionstiefe pro Richtung. Default: 12.

.PARAMETER MaxRounds
    Maximale Konvergenzrunden. Default: 8.

.PARAMETER Pick
    Oeffnet Out-GridView fuer manuelle Root-Auswahl.

.PARAMETER SkipUserMembershipWalk
    Deaktiviert A2 komplett.

.PARAMETER FullUserMembershipWalk
    A2 fuer ALLE User. Achtung: kann den Graph deutlich aufblaehen.

.PARAMETER ExtraRootGroups
    Zusaetzliche Root-Gruppen (SAMAccountName).

.EXAMPLE
    .\Export-ADPrivilegeMap.ps1 -OutputPath C:\Temp
    .\Export-ADPrivilegeMap.ps1 -OutputPath C:\Temp -SkipUserMembershipWalk
    .\Export-ADPrivilegeMap.ps1 -OutputPath C:\Temp -FullUserMembershipWalk
#>

[CmdletBinding()]
param(
    [string]   $OutputPath = (Join-Path $env:TEMP "AD-PrivMap-$(Get-Date -Format 'yyyyMMdd-HHmmss')"),
    [int]      $MaxDepth   = 12,
    [int]      $MaxRounds  = 8,
    [switch]   $Pick,
    [switch]   $SkipUserMembershipWalk,
    [switch]   $FullUserMembershipWalk,
    [switch]   $Minimal,
    [switch]   $IncludeDelegation,
    [switch]   $FromCache,
    [string]   $CachePath,
    [string[]] $ExtraRootGroups = @()
)

if (-not $FromCache) {
    Import-Module ActiveDirectory -ErrorAction Stop
}
if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}
if (-not $FromCache) {
    $Domain = Get-ADDomain
}

# ----------------------------- Datenstrukturen -----------------------------
$Nodes                 = @{}
$Edges                 = New-Object System.Collections.Generic.List[PSCustomObject]
$EdgeKeys              = New-Object System.Collections.Generic.HashSet[string]
$VisitedDown           = New-Object System.Collections.Generic.HashSet[string]
$VisitedUp             = New-Object System.Collections.Generic.HashSet[string]
$VisitedUserMembership = New-Object System.Collections.Generic.HashSet[string]
$VisitedPrimary        = New-Object System.Collections.Generic.HashSet[string]
$DirectTier0Users      = New-Object System.Collections.Generic.HashSet[string]

# ----------------------------- Helper -----------------------------
function Add-Node {
    param($ADObject, [string]$Type)
    $g = $ADObject.ObjectGUID.ToString()
    if ($Nodes.ContainsKey($g)) {
        if ($ADObject.PSObject.Properties['AdminCount'] -and $ADObject.AdminCount -eq 1) {
            $Nodes[$g].AdminCount = $true
        }
        return
    }
    $admin = $false
    if ($ADObject.PSObject.Properties['AdminCount']) { $admin = ($ADObject.AdminCount -eq 1) }
    $enabled = $null
    if ($ADObject.PSObject.Properties['Enabled']) { $enabled = $ADObject.Enabled }
    $Nodes[$g] = [PSCustomObject]@{
        Id                = $g
        SamAccountName    = if ($ADObject.PSObject.Properties['SamAccountName']) { $ADObject.SamAccountName } else { $null }
        DisplayName       = $ADObject.Name
        DistinguishedName = $ADObject.DistinguishedName
        Type              = $Type
        Enabled           = $enabled
        AdminCount        = $admin
        IsRoot            = $false
        IsSDPropOrphan    = $false
        LateralOnly       = $false
        LateralMemberOnly = $false
        LateralParentOnly = $false
        HasDelegation     = $false
        DelegationType    = $null
    }
}

function Add-Edge {
    param([string]$From, [string]$To, [string]$EdgeType = 'member', [string]$Label = '')
    $k = "$From->$To-$EdgeType"
    if (-not $EdgeKeys.Add($k)) { return }
    $Edges.Add([PSCustomObject]@{ From = $From; To = $To; EdgeType = $EdgeType; Label = $Label })
}

# ----------------------------- Members nach unten -----------------------------
function Expand-Members {
    param([string]$GroupDN, [int]$Depth = 0)
    if ($Depth -ge $MaxDepth) { return }
    try {
        $group = Get-ADGroup -Identity $GroupDN -Properties Members, ObjectGUID, AdminCount -ErrorAction Stop
    } catch { return }
    if (-not $VisitedDown.Add($group.ObjectGUID.ToString())) { return }
    Add-Node -ADObject $group -Type 'Group'
    # Ueber Members erreicht = nicht (mehr) lateral
    $Nodes[$group.ObjectGUID.ToString()].LateralOnly = $false

    foreach ($memberDN in $group.Members) {
        try { $m = Get-ADObject -Identity $memberDN -Properties ObjectClass, ObjectGUID -ErrorAction Stop }
        catch { continue }

        switch ($m.ObjectClass) {
            'user' {
                try {
                    $u = Get-ADUser -Identity $m.DistinguishedName -Properties Enabled, AdminCount
                    Add-Node -ADObject $u -Type 'User'
                    Add-Edge -From $u.ObjectGUID.ToString() -To $group.ObjectGUID.ToString()
                    # Fuer LooseA2: User die direkt Member einer Tier-0-Gruppe sind
                    if ($group.AdminCount -eq 1) {
                        [void]$DirectTier0Users.Add($u.ObjectGUID.ToString())
                    }
                } catch { continue }
            }
            'group' {
                try {
                    $s = Get-ADGroup -Identity $m.DistinguishedName -Properties AdminCount
                    Add-Node -ADObject $s -Type 'Group'
                    $Nodes[$s.ObjectGUID.ToString()].LateralOnly = $false
                    Add-Edge -From $s.ObjectGUID.ToString() -To $group.ObjectGUID.ToString()
                    Expand-Members -GroupDN $s.DistinguishedName -Depth ($Depth + 1)
                } catch { continue }
            }
            'computer' {
                try {
                    $c = Get-ADComputer -Identity $m.DistinguishedName -Properties Enabled
                    Add-Node -ADObject $c -Type 'Computer'
                    Add-Edge -From $c.ObjectGUID.ToString() -To $group.ObjectGUID.ToString()
                } catch { continue }
            }
            'foreignSecurityPrincipal' {
                Add-Node -ADObject $m -Type 'ForeignSecurityPrincipal'
                Add-Edge -From $m.ObjectGUID.ToString() -To $group.ObjectGUID.ToString()
            }
            default {
                Add-Node -ADObject $m -Type $m.ObjectClass
                Add-Edge -From $m.ObjectGUID.ToString() -To $group.ObjectGUID.ToString()
            }
        }
    }
}

# ----------------------------- MemberOf nach oben -----------------------------
function Expand-MemberOf {
    param([string]$GroupDN, [int]$Depth = 0)
    if ($Depth -ge $MaxDepth) { return }
    try {
        $group = Get-ADGroup -Identity $GroupDN -Properties MemberOf, ObjectGUID, AdminCount -ErrorAction Stop
    } catch { return }
    if (-not $VisitedUp.Add($group.ObjectGUID.ToString())) { return }
    Add-Node -ADObject $group -Type 'Group'
    $Nodes[$group.ObjectGUID.ToString()].LateralOnly = $false

    foreach ($parentDN in $group.MemberOf) {
        try {
            $p = Get-ADGroup -Identity $parentDN -Properties AdminCount -ErrorAction Stop
            Add-Node -ADObject $p -Type 'Group'
            $Nodes[$p.ObjectGUID.ToString()].LateralOnly = $false
            Add-Edge -From $group.ObjectGUID.ToString() -To $p.ObjectGUID.ToString()
            Expand-MemberOf -GroupDN $parentDN -Depth ($Depth + 1)
        } catch { continue }
    }
}

# ----------------------------- A2: User-Membership-Walk -----------------------------
function Expand-UserMemberships {
    param([string]$UserDN, [bool]$OnlyPrivileged = $true, [bool]$LooseA2 = $false)
    try {
        $u = Get-ADUser -Identity $UserDN -Properties MemberOf, ObjectGUID, Enabled, AdminCount -ErrorAction Stop
    } catch { return }
    if (-not $VisitedUserMembership.Add($u.ObjectGUID.ToString())) { return }
    Add-Node -ADObject $u -Type 'User'

    # Standard: nur AdminCount=1-User werden weiter expandiert.
    # Mit LooseA2: zusaetzlich User, die direkt Member einer Tier-0-Gruppe sind
    # (z.B. neue Konten, bei denen SDProp noch nicht gelaufen ist).
    if ($OnlyPrivileged -and $u.AdminCount -ne 1) {
        if (-not ($LooseA2 -and $DirectTier0Users.Contains($u.ObjectGUID.ToString()))) {
            return
        }
    }

    foreach ($groupDN in $u.MemberOf) {
        try {
            $g = Get-ADGroup -Identity $groupDN -Properties AdminCount -ErrorAction Stop
            $isNew = -not $Nodes.ContainsKey($g.ObjectGUID.ToString())
            Add-Node -ADObject $g -Type 'Group'
            # Neue, nicht-priv. Gruppe: als lateral markieren.
            # Diese Gruppe wird in der Konvergenz NICHT weiter expandiert,
            # d.h. ihre Members landen nicht im Graph.
            if ($isNew -and $g.AdminCount -ne 1) {
                $Nodes[$g.ObjectGUID.ToString()].LateralOnly = $true
            }
            Add-Edge -From $u.ObjectGUID.ToString() -To $g.ObjectGUID.ToString()
        } catch { continue }
    }
}

# ----------------------------- A4: PrimaryGroupID-Reverse-Lookup -----------------------------
function Add-PrimaryGroupMembers {
    param([string]$GroupDN)
    try {
        $g = Get-ADGroup -Identity $GroupDN -Properties ObjectSID, AdminCount, ObjectGUID -ErrorAction Stop
    } catch { return }
    if (-not $VisitedPrimary.Add($g.ObjectGUID.ToString())) { return }
    if ($g.AdminCount -ne 1) { return }

    $rid = $g.ObjectSID.Value.Split('-')[-1]
    try {
        $primMembers = @(Get-ADUser -LDAPFilter "(primaryGroupID=$rid)" -Properties Enabled, AdminCount -ErrorAction Stop)
    } catch { return }

    foreach ($u in $primMembers) {
        Add-Node -ADObject $u -Type 'User'
        Add-Edge -From $u.ObjectGUID.ToString() -To $g.ObjectGUID.ToString()
    }
}

# ----------------------------- Cache-Load oder AD-Walk ----------------------
# Cache-Dateipfad bestimmen
$cacheFile = if ($CachePath) { $CachePath } else { Join-Path $OutputPath 'ad-priv-map-cache.json' }

if ($FromCache) {
    # Auto-Discovery des Cache wenn kein expliziter Pfad
    if (-not $CachePath) {
        $candidate = Join-Path $OutputPath 'ad-priv-map-cache.json'
        if (Test-Path -LiteralPath $candidate) {
            $cacheFile = $candidate
        } else {
            $searchBase = Split-Path $OutputPath -Parent
            if (-not $searchBase -or -not (Test-Path -LiteralPath $searchBase)) {
                Write-Error "Kein Cache und kein gueltiges Basis-Verzeichnis. Bitte -CachePath setzen."
                return
            }
            $candidates = Get-ChildItem -Path $searchBase -Filter 'ad-priv-map-cache.json' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
            if (-not $candidates -or $candidates.Count -eq 0) {
                Write-Error "Kein Cache gefunden in '$searchBase'. Bitte erst einen normalen Lauf machen (ohne -FromCache)."
                return
            }
            $cacheFile = $candidates[0].FullName
            Write-Host "Cache automatisch gefunden: $cacheFile" -ForegroundColor Gray
        }
    }

    Write-Host ""
    Write-Host "Cache-Modus: lade $cacheFile" -ForegroundColor Cyan
    try {
        $cache = Get-Content -Path $cacheFile -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        Write-Error "Cache konnte nicht geladen werden: $_"
        return
    }

    # Domain rekonstruieren (nur DNSRoot wird im HTML-Export benoetigt)
    $Domain = [PSCustomObject]@{ DNSRoot = $cache.Meta.Domain }

    # Nodes und Edges aus Cache uebernehmen
    foreach ($n in $cache.Nodes) { $Nodes[$n.Id] = $n }
    foreach ($e in $cache.Edges) {
        $Edges.Add([PSCustomObject]@{
            From     = $e.From
            To       = $e.To
            EdgeType = $e.EdgeType
            Label    = $e.Label
        })
    }

    # Counts aus Meta
    $round         = $cache.Meta.Rounds
    $lateralCount  = $cache.Meta.LateralCount
    $latMemCount   = $cache.Meta.LatMemCount
    $latParCount   = $cache.Meta.LatParCount
    $delegCount    = $cache.Meta.DelegCount
    $kerbEdges     = $cache.Meta.KerbEdges
    $aclEdges      = $cache.Meta.AclEdges

    Write-Host "  $($Nodes.Count) Nodes, $($Edges.Count) Edges aus Cache (Original generiert: $($cache.Meta.Generated))." -ForegroundColor Green
} else {

# ----------------------------- A1: Auto-Discovery -----------------------------
Write-Host ""
Write-Host "AD Privilege Map - $($Domain.DNSRoot)" -ForegroundColor Cyan
Write-Host ""
Write-Host "A1: Auto-Discovery privilegierter Gruppen (AdminCount=1)..." -ForegroundColor Gray
$autoRoots = @(Get-ADGroup -LDAPFilter "(adminCount=1)" -Properties AdminCount, Description -ErrorAction Stop)
Write-Host "  $($autoRoots.Count) Gruppen mit AdminCount=1." -ForegroundColor Gray

$defaultPrivNames = @(
    'Domain Admins','Enterprise Admins','Schema Admins','Administrators',
    'Account Operators','Backup Operators','Server Operators','Print Operators',
    'Cert Publishers','Domain Controllers','Read-only Domain Controllers',
    'Group Policy Creator Owners','Cryptographic Operators',
    'Pre-Windows 2000 Compatible Access','Distributed COM Users','Replicator',
    'Key Admins','Enterprise Key Admins',
    'Domaenen-Admins','Organisations-Admins','Schema-Admins','Administratoren',
    'Konten-Operatoren','Sicherungs-Operatoren','Server-Operatoren','Druck-Operatoren',
    'Zertifikatherausgeber','Domaenencontroller'
)
foreach ($name in $defaultPrivNames) {
    try {
        $g = Get-ADGroup -Identity $name -Properties AdminCount -ErrorAction Stop
        if (-not ($autoRoots | Where-Object { $_.DistinguishedName -eq $g.DistinguishedName })) {
            $autoRoots = @($autoRoots) + $g
        }
    } catch { continue }
}

foreach ($name in $ExtraRootGroups) {
    try {
        $g = Get-ADGroup -Identity $name -Properties AdminCount -ErrorAction Stop
        if (-not ($autoRoots | Where-Object { $_.DistinguishedName -eq $g.DistinguishedName })) {
            $autoRoots = @($autoRoots) + $g
        }
    } catch { Write-Warning "ExtraRootGroup nicht gefunden: $name" }
}

if ($Pick) {
    if (-not (Get-Command Out-GridView -ErrorAction SilentlyContinue)) {
        Write-Warning "Out-GridView nicht verfuegbar - Pick-Modus uebersprungen."
    } else {
        Write-Host ""
        Write-Host "Pick-Modus: weitere Gruppen optional ergaenzen..." -ForegroundColor Yellow
        $allGroups = Get-ADGroup -Filter * -Properties Description, AdminCount |
            Sort-Object Name |
            ForEach-Object {
                [PSCustomObject]@{
                    Name           = $_.Name
                    SamAccountName = $_.SamAccountName
                    GroupScope     = $_.GroupScope
                    GroupCategory  = $_.GroupCategory
                    AdminCount     = $_.AdminCount
                    Description    = $_.Description
                }
            }
        $picked = @($allGroups | Out-GridView -Title "Zusaetzliche Root-Gruppen waehlen (optional)" -OutputMode Multiple)
        foreach ($p in $picked) {
            try {
                $g = Get-ADGroup -Identity $p.SamAccountName -Properties AdminCount -ErrorAction Stop
                if (-not ($autoRoots | Where-Object { $_.DistinguishedName -eq $g.DistinguishedName })) {
                    $autoRoots = @($autoRoots) + $g
                }
            } catch { continue }
        }
    }
}

if ($autoRoots.Count -eq 0) {
    Write-Warning "Keine Root-Gruppen ermittelt - Ende."
    return
}
Write-Host ""
Write-Host "Verwende $($autoRoots.Count) Root-Gruppe(n)." -ForegroundColor Cyan

# A2-Strategie ausgeben
$onlyPrivilegedUsers = -not $FullUserMembershipWalk
$looseA2 = (-not $Minimal) -and (-not $FullUserMembershipWalk) -and (-not $SkipUserMembershipWalk)

if ($SkipUserMembershipWalk) {
    Write-Host "A2-Strategie: deaktiviert (-SkipUserMembershipWalk)" -ForegroundColor Yellow
} elseif ($FullUserMembershipWalk) {
    Write-Host "A2-Strategie: voll (alle User, kann gross werden)" -ForegroundColor Yellow
} elseif ($Minimal) {
    Write-Host "A2-Strategie: minimal (nur AdminCount=1-User, laterale Gruppen geschlossen)" -ForegroundColor Gray
} else {
    Write-Host "A2-Strategie: erweitert (AdminCount=1 + direkte Tier-0-Member, laterale Gruppen geschlossen)" -ForegroundColor Gray
}

# ----------------------------- Initiale Expansion der Roots -----------------------------
$i = 0
foreach ($r in $autoRoots) {
    $i++
    Write-Progress -Activity "Initiale Root-Expansion" -Status $r.Name -PercentComplete (($i / $autoRoots.Count) * 100)
    Expand-Members  -GroupDN $r.DistinguishedName
    Expand-MemberOf -GroupDN $r.DistinguishedName
    if ($Nodes.ContainsKey($r.ObjectGUID.ToString())) {
        $Nodes[$r.ObjectGUID.ToString()].IsRoot = $true
    }
}
Write-Progress -Activity "Initiale Root-Expansion" -Completed

# ----------------------------- A3: SDProp-Waisen -----------------------------
Write-Host "A3: SDProp-Waisen (User mit AdminCount=1)..." -ForegroundColor Gray
try {
    $adminUsers = @(Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(adminCount=1))" -Properties AdminCount, Enabled -ErrorAction Stop)
    $orphanCount = 0
    foreach ($u in $adminUsers) {
        $existed = $Nodes.ContainsKey($u.ObjectGUID.ToString())
        Add-Node -ADObject $u -Type 'User'
        if (-not $existed) {
            $Nodes[$u.ObjectGUID.ToString()].IsSDPropOrphan = $true
            $orphanCount++
        }
    }
    Write-Host "  $($adminUsers.Count) AdminCount-User, davon $orphanCount echte Waisen." -ForegroundColor Gray
} catch {
    Write-Warning "A3 fehlgeschlagen: $_"
}

# ----------------------------- A5: Iterative Konvergenz -----------------------------
Write-Host ""
Write-Host "A5: Iterative Konvergenz..." -ForegroundColor Cyan

$round = 0
$prevTotal = -1
$currTotal = $Nodes.Count

while ($currTotal -ne $prevTotal -and $round -lt $MaxRounds) {
    $round++
    $prevTotal = $currTotal

    $currentGroups = @($Nodes.Values | Where-Object { $_.Type -eq 'Group' } | Select-Object -ExpandProperty Id)
    $currentUsers  = @($Nodes.Values | Where-Object { $_.Type -eq 'User'  } | Select-Object -ExpandProperty Id)

    Write-Host ("  Runde {0}: Start mit {1} Gruppen, {2} User, {3} Nodes gesamt" -f $round, $currentGroups.Count, $currentUsers.Count, $Nodes.Count) -ForegroundColor Gray

    # Phase 1: Gruppen expandieren - laterale Gruppen werden NICHT weiter ausgerollt
    $j = 0
    foreach ($gid in $currentGroups) {
        $j++
        if ($j % 5 -eq 0 -or $j -eq $currentGroups.Count) {
            Write-Progress -Activity "Konvergenz Runde $round - Gruppen" -Status $Nodes[$gid].DisplayName -PercentComplete (($j / $currentGroups.Count) * 100)
        }
        if ($Nodes[$gid].LateralOnly) { continue }
        $dn = $Nodes[$gid].DistinguishedName
        Expand-Members          -GroupDN $dn
        Expand-MemberOf         -GroupDN $dn
        Add-PrimaryGroupMembers -GroupDN $dn
    }
    Write-Progress -Activity "Konvergenz Runde $round - Gruppen" -Completed

    # Phase 2: A2 (User-Membership-Walk)
    if (-not $SkipUserMembershipWalk) {
        $k = 0
        foreach ($uid in $currentUsers) {
            $k++
            if ($k % 10 -eq 0 -or $k -eq $currentUsers.Count) {
                Write-Progress -Activity "Konvergenz Runde $round - User-Memberships" -Status $Nodes[$uid].SamAccountName -PercentComplete (($k / $currentUsers.Count) * 100)
            }
            Expand-UserMemberships -UserDN $Nodes[$uid].DistinguishedName -OnlyPrivileged $onlyPrivilegedUsers -LooseA2 $looseA2
        }
        Write-Progress -Activity "Konvergenz Runde $round - User-Memberships" -Completed
    }

    $currTotal = $Nodes.Count
}

$lateralCount = @($Nodes.Values | Where-Object { $_.LateralOnly }).Count
Write-Host ("  Konvergenz nach {0} Runde(n). Endstand: {1} Nodes (davon {2} laterale Gruppen), {3} Edges." -f $round, $Nodes.Count, $lateralCount, $Edges.Count) -ForegroundColor Green

# ----------------------------- Phase 3: Laterale Members ---------------------
if (-not $Minimal) {
    Write-Host ""
    Write-Host "Phase 3: Members der lateralen Gruppen einmal laden..." -ForegroundColor Cyan

    $lateralGroupIds = @($Nodes.Values | Where-Object { $_.LateralOnly } | ForEach-Object { $_.Id })
    $beforeCount = $Nodes.Count

    $j = 0
    foreach ($gid in $lateralGroupIds) {
        $j++
        if ($j % 5 -eq 0 -or $j -eq $lateralGroupIds.Count) {
            Write-Progress -Activity "Phase 3 - Laterale Members" -Status $Nodes[$gid].DisplayName -PercentComplete (($j / $lateralGroupIds.Count) * 100)
        }
        $dn = $Nodes[$gid].DistinguishedName
        try {
            $lg = Get-ADGroup -Identity $dn -Properties Members, ObjectGUID -ErrorAction Stop
        } catch { continue }

        foreach ($memberDN in $lg.Members) {
            try { $m = Get-ADObject -Identity $memberDN -Properties ObjectClass, ObjectGUID -ErrorAction Stop }
            catch { continue }

            $mGuid  = $m.ObjectGUID.ToString()
            $isNew  = -not $Nodes.ContainsKey($mGuid)

            switch ($m.ObjectClass) {
                'user' {
                    try {
                        $u = Get-ADUser -Identity $m.DistinguishedName -Properties Enabled, AdminCount
                        Add-Node -ADObject $u -Type 'User'
                        if ($isNew) { $Nodes[$u.ObjectGUID.ToString()].LateralMemberOnly = $true }
                        Add-Edge -From $u.ObjectGUID.ToString() -To $lg.ObjectGUID.ToString()
                    } catch { continue }
                }
                'group' {
                    try {
                        $s = Get-ADGroup -Identity $m.DistinguishedName -Properties AdminCount
                        Add-Node -ADObject $s -Type 'Group'
                        if ($isNew) { $Nodes[$s.ObjectGUID.ToString()].LateralMemberOnly = $true }
                        Add-Edge -From $s.ObjectGUID.ToString() -To $lg.ObjectGUID.ToString()
                    } catch { continue }
                }
                'computer' {
                    try {
                        $c = Get-ADComputer -Identity $m.DistinguishedName -Properties Enabled
                        Add-Node -ADObject $c -Type 'Computer'
                        if ($isNew) { $Nodes[$c.ObjectGUID.ToString()].LateralMemberOnly = $true }
                        Add-Edge -From $c.ObjectGUID.ToString() -To $lg.ObjectGUID.ToString()
                    } catch { continue }
                }
                'foreignSecurityPrincipal' {
                    Add-Node -ADObject $m -Type 'ForeignSecurityPrincipal'
                    if ($isNew) { $Nodes[$mGuid].LateralMemberOnly = $true }
                    Add-Edge -From $mGuid -To $lg.ObjectGUID.ToString()
                }
                default {
                    Add-Node -ADObject $m -Type $m.ObjectClass
                    if ($isNew) { $Nodes[$mGuid].LateralMemberOnly = $true }
                    Add-Edge -From $mGuid -To $lg.ObjectGUID.ToString()
                }
            }
        }
    }
    Write-Progress -Activity "Phase 3 - Laterale Members" -Completed
    Write-Host "  $($Nodes.Count - $beforeCount) neue Nodes via laterale Member-Expansion." -ForegroundColor Gray
}

# ----------------------------- Phase 4: Laterale Parents ---------------------
if (-not $Minimal) {
    Write-Host ""
    Write-Host "Phase 4: MemberOf der lateralen Gruppen einmal laden..." -ForegroundColor Cyan

    $lateralGroupIds = @($Nodes.Values | Where-Object { $_.LateralOnly } | ForEach-Object { $_.Id })
    $beforeCount = $Nodes.Count

    $j = 0
    foreach ($gid in $lateralGroupIds) {
        $j++
        if ($j % 5 -eq 0 -or $j -eq $lateralGroupIds.Count) {
            Write-Progress -Activity "Phase 4 - Laterale Parents" -Status $Nodes[$gid].DisplayName -PercentComplete (($j / $lateralGroupIds.Count) * 100)
        }
        $dn = $Nodes[$gid].DistinguishedName
        try {
            $lg = Get-ADGroup -Identity $dn -Properties MemberOf, ObjectGUID -ErrorAction Stop
        } catch { continue }

        foreach ($parentDN in $lg.MemberOf) {
            try {
                $p = Get-ADGroup -Identity $parentDN -Properties AdminCount -ErrorAction Stop
                $pGuid = $p.ObjectGUID.ToString()
                $isNew = -not $Nodes.ContainsKey($pGuid)
                Add-Node -ADObject $p -Type 'Group'
                if ($isNew) { $Nodes[$pGuid].LateralParentOnly = $true }
                Add-Edge -From $lg.ObjectGUID.ToString() -To $pGuid
            } catch { continue }
        }
    }
    Write-Progress -Activity "Phase 4 - Laterale Parents" -Completed
    Write-Host "  $($Nodes.Count - $beforeCount) neue Nodes via laterale Parent-Walk." -ForegroundColor Gray
}

$latMemCount = @($Nodes.Values | Where-Object { $_.LateralMemberOnly }).Count
$latParCount = @($Nodes.Values | Where-Object { $_.LateralParentOnly }).Count

# ----------------------------- Phase 5: Kerberos-Delegation ------------------
if ($IncludeDelegation) {
    Write-Host ""
    Write-Host "Phase 5: Kerberos-Delegation..." -ForegroundColor Cyan

    $beforeNodes = $Nodes.Count
    $beforeEdges = $Edges.Count

    $TRUSTED_FOR_DELEGATION   = 0x80000       # Unconstrained
    $TRUSTED_TO_AUTH_FOR_DEL  = 0x1000000     # Protocol Transition (Constrained-PT)

    $delegFilter = "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"

    try {
        $delegObjects = @(Get-ADObject -LDAPFilter $delegFilter -Properties userAccountControl, 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', servicePrincipalName, ObjectClass, ObjectGUID -ErrorAction Stop)
    } catch {
        Write-Warning "Phase 5 fehlgeschlagen: $_"
        $delegObjects = @()
    }

    Write-Host "  $($delegObjects.Count) Konten mit Delegations-Attributen gefunden." -ForegroundColor Gray

    foreach ($obj in $delegObjects) {
        # Source-Node anlegen (typabhaengig nachladen, damit Enabled / AdminCount stimmen)
        $srcType = switch ($obj.ObjectClass) {
            'computer' { 'Computer' }
            'user'     { 'User' }
            'group'    { 'Group' }
            default    { $obj.ObjectClass }
        }
        try {
            switch ($obj.ObjectClass) {
                'computer' { $srcAd = Get-ADComputer -Identity $obj.DistinguishedName -Properties Enabled -ErrorAction Stop }
                'user'     { $srcAd = Get-ADUser     -Identity $obj.DistinguishedName -Properties Enabled, AdminCount -ErrorAction Stop }
                'group'    { $srcAd = Get-ADGroup    -Identity $obj.DistinguishedName -Properties AdminCount -ErrorAction Stop }
                default    { $srcAd = $obj }
            }
        } catch { continue }
        Add-Node -ADObject $srcAd -Type $srcType
        $srcId = $srcAd.ObjectGUID.ToString()
        $Nodes[$srcId].HasDelegation = $true

        $uac = [int]$obj.userAccountControl

        # 1. Unconstrained: nur Node-Markierung, keine spezifische Edge
        if (($uac -band $TRUSTED_FOR_DELEGATION) -eq $TRUSTED_FOR_DELEGATION) {
            $Nodes[$srcId].DelegationType = 'Unconstrained'
        }

        # 2. Constrained: msDS-AllowedToDelegateTo (Liste von SPNs)
        $cdList = $obj.'msDS-AllowedToDelegateTo'
        if ($cdList -and $cdList.Count -gt 0) {
            if (-not $Nodes[$srcId].DelegationType) {
                $Nodes[$srcId].DelegationType =
                    if (($uac -band $TRUSTED_TO_AUTH_FOR_DEL) -eq $TRUSTED_TO_AUTH_FOR_DEL) { 'Constrained-PT' }
                    else { 'Constrained' }
            }
            foreach ($spn in $cdList) {
                # SPN -> Account aufloesen
                try {
                    $svcObj = Get-ADObject -LDAPFilter "(servicePrincipalName=$spn)" -Properties ObjectClass, ObjectGUID, Enabled, AdminCount -ErrorAction Stop | Select-Object -First 1
                } catch { continue }
                if (-not $svcObj) { continue }
                $tgtType = switch ($svcObj.ObjectClass) {
                    'computer' { 'Computer' }
                    'user'     { 'User' }
                    'group'    { 'Group' }
                    default    { $svcObj.ObjectClass }
                }
                Add-Node -ADObject $svcObj -Type $tgtType
                Add-Edge -From $srcId -To $svcObj.ObjectGUID.ToString() -EdgeType 'kerberos-constrained' -Label "Constrained: $spn"
            }
        }

        # 3. RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity (Security Descriptor)
        $rbcdSdBytes = $obj.'msDS-AllowedToActOnBehalfOfOtherIdentity'
        if ($rbcdSdBytes) {
            try {
                $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $rbcdSdBytes, 0
                foreach ($ace in $sd.DiscretionaryAcl) {
                    $sid = $ace.SecurityIdentifier
                    try {
                        $rbcdObj = Get-ADObject -Identity $sid.Value -Properties ObjectClass, ObjectGUID, Enabled, AdminCount -ErrorAction Stop
                    } catch { continue }
                    $rbcdType = switch ($rbcdObj.ObjectClass) {
                        'computer' { 'Computer' }
                        'user'     { 'User' }
                        'group'    { 'Group' }
                        default    { $rbcdObj.ObjectClass }
                    }
                    Add-Node -ADObject $rbcdObj -Type $rbcdType
                    $rbcdId = $rbcdObj.ObjectGUID.ToString()
                    $Nodes[$rbcdId].HasDelegation = $true
                    if (-not $Nodes[$rbcdId].DelegationType) {
                        $Nodes[$rbcdId].DelegationType = 'RBCD-Source'
                    }
                    # RBCD-Pfeil: Source -> Target (Source darf sich fuer Target ausgeben)
                    Add-Edge -From $rbcdId -To $srcId -EdgeType 'kerberos-rbcd' -Label 'RBCD'
                }
            } catch {
                # SD-Parse-Fehler ignorieren
            }
        }
    }

    Write-Host "  Phase 5 fertig: $($Nodes.Count - $beforeNodes) neue Nodes, $($Edges.Count - $beforeEdges) Kerberos-Edges." -ForegroundColor Green
}

# ----------------------------- Phase 6: ACL-Delegation -----------------------
if ($IncludeDelegation) {
    Write-Host ""
    Write-Host "Phase 6: ACL-Delegation (kann mehrere Minuten dauern)..." -ForegroundColor Cyan

    $beforeNodes = $Nodes.Count
    $beforeEdges = $Edges.Count

    # Well-known ExtendedRight GUIDs
    $userForceChangePwd            = '00299570-246d-11d0-a768-00aa006e0529'
    $dsReplicationGetChanges       = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    $dsReplicationGetChangesAll    = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

    # SIDs, die wir ueberspringen (Standard-System-Accounts)
    $skipSids = @{
        'S-1-5-18'     = $true   # SYSTEM
        'S-1-5-19'     = $true   # LOCAL SERVICE
        'S-1-5-20'     = $true   # NETWORK SERVICE
        'S-1-5-32-544' = $true   # BUILTIN\Administrators (zu generisch)
        'S-1-5-10'     = $true   # SELF
        'S-1-3-0'      = $true   # CREATOR OWNER
        'S-1-3-1'      = $true   # CREATOR GROUP
    }

    # Scope: alle OUs + alle Knoten, die bereits im Graph sind
    $aclTargets = @()
    try {
        $ous = @(Get-ADOrganizationalUnit -Filter * -Properties ObjectGUID -ErrorAction Stop)
        foreach ($ou in $ous) {
            Add-Node -ADObject $ou -Type 'OU'
            $aclTargets += [PSCustomObject]@{ DN = $ou.DistinguishedName; Id = $ou.ObjectGUID.ToString() }
        }
        Write-Host "  $($ous.Count) OUs in Scope." -ForegroundColor Gray
    } catch {
        Write-Warning "OUs konnten nicht geladen werden: $_"
    }

    foreach ($n in @($Nodes.Values | Where-Object { $_.Type -in @('Group','User','Computer') -and $_.DistinguishedName })) {
        $aclTargets += [PSCustomObject]@{ DN = $n.DistinguishedName; Id = $n.Id }
    }

    Write-Host "  Scope total: $($aclTargets.Count) Objekte fuer ACL-Read." -ForegroundColor Gray

    $sidCache = @{}

    $j = 0
    foreach ($t in $aclTargets) {
        $j++
        if ($j % 25 -eq 0 -or $j -eq $aclTargets.Count) {
            Write-Progress -Activity "Phase 6 - ACLs lesen" -Status $t.DN -PercentComplete (($j / $aclTargets.Count) * 100)
        }

        try {
            $acl = Get-Acl -Path "AD:$($t.DN)" -ErrorAction Stop
        } catch { continue }

        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.IsInherited) { continue }   # vererbte ACEs separat, zu viel Rauschen

            $rights    = $ace.ActiveDirectoryRights.ToString()
            $objType   = $ace.ObjectType.ToString()
            $rightLabel = $null

            if     ($rights -match 'GenericAll')                            { $rightLabel = 'GenericAll' }
            elseif ($rights -match 'WriteDacl')                             { $rightLabel = 'WriteDACL' }
            elseif ($rights -match 'WriteOwner')                            { $rightLabel = 'WriteOwner' }
            elseif ($rights -match 'GenericWrite')                          { $rightLabel = 'GenericWrite' }
            elseif ($rights -match 'ExtendedRight' -and $objType -eq $userForceChangePwd)         { $rightLabel = 'ForcePwdChange' }
            elseif ($rights -match 'ExtendedRight' -and $objType -eq $dsReplicationGetChanges)    { $rightLabel = 'DCSync-GetChanges' }
            elseif ($rights -match 'ExtendedRight' -and $objType -eq $dsReplicationGetChangesAll) { $rightLabel = 'DCSync-All' }
            else { continue }

            # SID der Identity ermitteln
            $sid = $null
            try {
                $idRef = $ace.IdentityReference
                if ($idRef -is [System.Security.Principal.SecurityIdentifier]) {
                    $sid = $idRef
                } else {
                    $sid = $idRef.Translate([System.Security.Principal.SecurityIdentifier])
                }
            } catch { continue }
            if ($skipSids.ContainsKey($sid.Value)) { continue }

            # Source-Account via SID, mit Cache
            $srcObj = $null
            if ($sidCache.ContainsKey($sid.Value)) {
                $srcObj = $sidCache[$sid.Value]
            } else {
                try {
                    $srcObj = Get-ADObject -Identity $sid.Value -Properties ObjectClass, ObjectGUID, Enabled, AdminCount, SamAccountName -ErrorAction Stop
                    $sidCache[$sid.Value] = $srcObj
                } catch {
                    $sidCache[$sid.Value] = $null
                    continue
                }
            }
            if (-not $srcObj) { continue }

            $srcType = switch ($srcObj.ObjectClass) {
                'user'     { 'User' }
                'group'    { 'Group' }
                'computer' { 'Computer' }
                default    { $srcObj.ObjectClass }
            }
            Add-Node -ADObject $srcObj -Type $srcType
            Add-Edge -From $srcObj.ObjectGUID.ToString() -To $t.Id -EdgeType 'acl-right' -Label $rightLabel
        }
    }
    Write-Progress -Activity "Phase 6 - ACLs lesen" -Completed
    Write-Host "  Phase 6 fertig: $($Nodes.Count - $beforeNodes) neue Nodes, $($Edges.Count - $beforeEdges) ACL-Edges." -ForegroundColor Green
}

$delegCount  = @($Nodes.Values | Where-Object { $_.HasDelegation }).Count
$kerbEdges   = @($Edges | Where-Object { $_.EdgeType -like 'kerberos-*' }).Count
$aclEdges    = @($Edges | Where-Object { $_.EdgeType -eq 'acl-right' }).Count

# Cache schreiben fuer spaeteren -FromCache-Lauf
$cacheData = [ordered]@{
    Meta = [ordered]@{
        Generated    = (Get-Date).ToString('o')
        Domain       = $Domain.DNSRoot
        Rounds       = $round
        LateralCount = $lateralCount
        LatMemCount  = $latMemCount
        LatParCount  = $latParCount
        DelegCount   = $delegCount
        KerbEdges    = $kerbEdges
        AclEdges     = $aclEdges
    }
    Nodes = @($Nodes.Values)
    Edges = @($Edges)
}
try {
    $cacheData | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $cacheFile -Encoding UTF8
    Write-Host "  Cache geschrieben: $cacheFile" -ForegroundColor Gray
} catch {
    Write-Warning "Cache konnte nicht geschrieben werden: $_"
}

}  # Ende if (-not $FromCache)

# ----------------------------- HTML-Export -----------------------------
$visNodes = $Nodes.Values | ForEach-Object {
    $color = switch ($_.Type) {
        'User' {
            if ($_.IsSDPropOrphan)         { '#7c2d12' }
            elseif ($_.AdminCount)         { '#b91c1c' }
            elseif ($_.LateralMemberOnly)  { '#bfdbfe' }
            elseif ($_.Enabled -eq $false) { '#9ca3af' }
            else                           { '#3b82f6' }
        }
        'Group' {
            if ($_.IsRoot)                 { '#dc2626' }
            elseif ($_.AdminCount)         { '#ea580c' }
            elseif ($_.LateralParentOnly)  { '#d9f99d' }
            elseif ($_.LateralMemberOnly)  { '#fef3c7' }
            elseif ($_.LateralOnly)        { '#fcd34d' }
            else                           { '#f59e0b' }
        }
        'Computer' {
            if ($_.LateralMemberOnly)      { '#bbf7d0' }
            else                           { '#10b981' }
        }
        'ForeignSecurityPrincipal' {
            if ($_.LateralMemberOnly)      { '#e9d5ff' }
            else                           { '#a855f7' }
        }
        'OU'                               { '#64748b' }
        default                            { '#6b7280' }
    }
    $delegLine = if ($_.HasDelegation) { "`nDelegation: $($_.DelegationType)" } else { '' }
    $tooltip = "Type: $($_.Type)`nSAM: $($_.SamAccountName)`nEnabled: $($_.Enabled)`nAdminCount: $($_.AdminCount)`nIsRoot: $($_.IsRoot)`nIsSDPropOrphan: $($_.IsSDPropOrphan)`nLateralOnly: $($_.LateralOnly)`nLateralMemberOnly: $($_.LateralMemberOnly)`nLateralParentOnly: $($_.LateralParentOnly)${delegLine}`nDN: $($_.DistinguishedName)"
    [PSCustomObject]@{
        id                = $_.Id
        label             = $_.DisplayName
        title             = $tooltip
        color             = $color
        shape             = if ($_.Type -eq 'Group' -or $_.Type -eq 'OU') { 'box' } else { 'dot' }
        nodeType          = $_.Type
        nodeEnabled       = $_.Enabled
        nodeAdminCount    = $_.AdminCount
        nodeIsRoot        = $_.IsRoot
        nodeIsOrphan      = $_.IsSDPropOrphan
        nodeLateral       = $_.LateralOnly
        nodeLatMember     = $_.LateralMemberOnly
        nodeLatParent     = $_.LateralParentOnly
        nodeHasDelegation = $_.HasDelegation
        nodeDelegationType = $_.DelegationType
    }
}
$nJson = ($visNodes | ConvertTo-Json -Depth 4 -Compress)
$eJson = ($Edges | ForEach-Object { [PSCustomObject]@{ from = $_.From; to = $_.To; edgeType = $_.EdgeType; label = $_.Label } } | ConvertTo-Json -Depth 4 -Compress)
if (-not $nJson)               { $nJson = '[]' }
if (-not $eJson)               { $eJson = '[]' }
if ($nJson -notmatch '^\s*\[') { $nJson = "[$nJson]" }
if ($eJson -notmatch '^\s*\[') { $eJson = "[$eJson]" }

$htmlPath = Join-Path $OutputPath 'ad-priv-map.html'

$htmlTemplate = @'
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>AD Privilege Map - __DOMAIN__</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
  html, body { margin:0; padding:0; height:100%; font-family:'Segoe UI',Tahoma,sans-serif; }
  #header { padding:10px 20px; background:#1f2937; color:#fff; display:flex; align-items:center; justify-content:space-between; }
  #header h1 { font-size:16px; margin:0; }
  #header .meta { font-size:12px; opacity:0.7; }
  #toolbar { padding:8px 20px; background:#f3f4f6; border-bottom:1px solid #d1d5db; display:flex; flex-wrap:wrap; gap:16px; align-items:center; font-size:13px; }
  #toolbar label { display:flex; align-items:center; gap:4px; cursor:pointer; user-select:none; }
  #toolbar select, #toolbar input[type='text'], #toolbar input[type='number'] { padding:4px 6px; font-size:13px; }
  #toolbar .grp { display:flex; gap:12px; align-items:center; }
  #toolbar .grp + .grp { border-left:1px solid #d1d5db; padding-left:16px; }
  #network { width:100%; height:calc(100vh - 130px); background:#fafafa; }
  .legend { position:absolute; top:140px; right:20px; background:#fff; padding:10px 14px; border:1px solid #ddd; border-radius:6px; font-size:12px; box-shadow:0 2px 8px rgba(0,0,0,0.08); z-index:10; max-width:300px; }
  .legend div { margin:4px 0; }
  .legend .hint { margin-top:8px; padding-top:8px; border-top:1px solid #eee; color:#555; font-size:11px; line-height:1.4; }
  .swatch { display:inline-block; width:14px; height:14px; margin-right:8px; border-radius:3px; vertical-align:middle; }
  #stats { position:absolute; bottom:10px; left:20px; background:#fff; padding:6px 10px; border:1px solid #ddd; border-radius:4px; font-size:11px; box-shadow:0 1px 4px rgba(0,0,0,0.08); z-index:10; }
  #loading { position:fixed; top:130px; left:0; right:0; bottom:0; background:rgba(255,255,255,0.95); display:flex; align-items:center; justify-content:center; flex-direction:column; z-index:100; font-size:14px; color:#1f2937; }
  #loading progress { width:300px; height:14px; margin:10px 0; }
  #loading-text { font-size:12px; color:#6b7280; margin-top:4px; }
</style>
</head>
<body>
<div id="header">
  <div><h1>AD Privilege Map - __DOMAIN__</h1></div>
  <div class="meta">__TIMESTAMP__ &middot; __NODECOUNT__ Nodes &middot; __EDGECOUNT__ Edges &middot; __ROUNDS__ Runden</div>
</div>

<div id="toolbar">
  <div class="grp">
    <label>Anzeige:
      <select id="display-mode">
        <option value="depth" selected>Auswahl + Nachbarn</option>
        <option value="all">Alle Nodes</option>
      </select>
    </label>
    <label>Tiefe:
      <select id="depth-select">
        <option value="1">1</option>
        <option value="2" selected>2</option>
        <option value="3">3</option>
        <option value="4">4</option>
        <option value="6">6</option>
        <option value="999">Alle</option>
      </select>
    </label>
  </div>
  <div class="grp">
    <label>Layout:
      <select id="layout-select">
        <option value="physics">Physics</option>
        <option value="hierarchical">Hierarchisch (Tier-0 oben)</option>
      </select>
    </label>
  </div>
  <div class="grp">
    <label><input type="checkbox" id="f-tier0"> Nur Tier-0</label>
    <label><input type="checkbox" id="f-active"> Nur aktive User</label>
    <label><input type="checkbox" id="f-hidecomp"> Computer aus</label>
    <label><input type="checkbox" id="f-hidefsp"> Foreign SPs aus</label>
    <label><input type="checkbox" id="f-hidelateral"> Laterale Gruppen aus</label>
    <label><input type="checkbox" id="f-hidelatmem"> Lat. Members aus</label>
    <label><input type="checkbox" id="f-hidelatpar"> Lat. Parents aus</label>
    <label><input type="checkbox" id="f-hidekerb"> Kerberos-Edges aus</label>
    <label><input type="checkbox" id="f-hideacl"> ACL-Edges aus</label>
    <label>Min. Memberships pro User: <input type="number" id="f-minmem" value="0" min="0" max="50" style="width:50px;"></label>
  </div>
  <div class="grp">
    <label>Suche: <input type="text" id="search" placeholder="Name..." style="width:200px;"></label>
  </div>
</div>

<div id="network"></div>

<div class="legend">
  <div><span class="swatch" style="background:#dc2626"></span>Tier-0 Root-Gruppe</div>
  <div><span class="swatch" style="background:#ea580c"></span>Gruppe (AdminCount=1)</div>
  <div><span class="swatch" style="background:#f59e0b"></span>Gruppe (normal)</div>
  <div><span class="swatch" style="background:#fcd34d"></span>Gruppe (lateral, nur via A2)</div>
  <div><span class="swatch" style="background:#fef3c7"></span>Gruppe (Member einer lat. Gruppe)</div>
  <div><span class="swatch" style="background:#d9f99d"></span>Gruppe (Parent einer lat. Gruppe)</div>
  <div><span class="swatch" style="background:#b91c1c"></span>User (AdminCount=1)</div>
  <div><span class="swatch" style="background:#7c2d12"></span>SDProp-Waise</div>
  <div><span class="swatch" style="background:#3b82f6"></span>User (aktiv)</div>
  <div><span class="swatch" style="background:#bfdbfe"></span>User (Member einer lat. Gruppe)</div>
  <div><span class="swatch" style="background:#9ca3af"></span>User (deaktiviert)</div>
  <div><span class="swatch" style="background:#10b981"></span>Computer</div>
  <div><span class="swatch" style="background:#bbf7d0"></span>Computer (lat. Member)</div>
  <div><span class="swatch" style="background:#a855f7"></span>Foreign SP</div>
  <div><span class="swatch" style="background:#64748b"></span>OU</div>
  <div class="hint">Pfeilrichtung A -&gt; B = "A ist Mitglied von B"<br>Klick auf Node oder Eingabe im Suchfeld = Pfad markieren<br><br>Edge-Farben:<br><span style="color:#555;font-weight:bold">grau</span> = Mitgliedschaft<br><span style="color:#7c3aed;font-weight:bold">lila</span> = Kerberos-Delegation<br><span style="color:#f97316;font-weight:bold">orange</span> = ACL-Recht</div>
</div>

<div id="stats"></div>

<div id="loading">
  <div>Map wird berechnet...</div>
  <progress id="loading-progress" value="0" max="100"></progress>
  <div id="loading-text">Initialisierung...</div>
</div>

<script>
  const allNodesData = __NODESJSON__;
  const allEdgesData = __EDGESJSON__;
  // Edges mit IDs versehen (Voraussetzung fuer DataSet.update)
  allEdgesData.forEach((e, idx) => { e.id = 'e' + idx; });

  // Adjacency-Listen einmalig vorberechnen (fuer BFS in beide Richtungen)
  const adjOut = {};
  const adjIn  = {};
  allEdgesData.forEach(e => {
    if (!adjOut[e.from]) adjOut[e.from] = [];
    if (!adjIn[e.to])    adjIn[e.to]    = [];
    adjOut[e.from].push(e.to);
    adjIn[e.to].push(e.from);
  });

  // Anzahl ausgehender Edges pro User-Node (= Group-Memberships)
  const userMembershipCount = {};
  allEdgesData.forEach(e => {
    userMembershipCount[e.from] = (userMembershipCount[e.from] || 0) + 1;
  });

  // Original-Farbe pro Node fuer Reset cachen
  allNodesData.forEach(n => {
    n._origColor = (typeof n.color === 'string') ? n.color : ((n.color && n.color.background) || '#888');
  });

  const state = {
    displayMode: 'depth',
    depth:       2,
    tier0Only:   false,
    activeOnly:  false,
    hideComps:   false,
    hideFsp:     false,
    hideLateral: false,
    hideLatMem:  false,
    hideLatPar:  false,
    hideKerb:    false,
    hideAcl:     false,
    minMembers:  0
  };

  let highlightId = null;  // ID des aktuell markierten Nodes fuer Pfad-Hervorhebung

  const HIGHLIGHT_COLOR = '#dc2626';   // rot fuer Pfad
  const DIMMED_BG       = '#e5e7eb';   // hellgrau fuer ausgeblendete Nodes
  const DIMMED_FONT     = '#9ca3af';

  function isTier0(node) {
    if (node.nodeType === 'Group') return node.nodeIsRoot || node.nodeAdminCount;
    if (node.nodeType === 'User')  return node.nodeAdminCount || node.nodeIsOrphan;
    return false;
  }

  function nodeVisible(node) {
    if (state.tier0Only && !isTier0(node)) return false;
    if (state.activeOnly && node.nodeType === 'User' && node.nodeEnabled === false) return false;
    if (state.hideComps && node.nodeType === 'Computer') return false;
    if (state.hideFsp && node.nodeType === 'ForeignSecurityPrincipal') return false;
    if (state.hideLateral && node.nodeLateral) return false;
    if (state.hideLatMem && node.nodeLatMember) return false;
    if (state.hideLatPar && node.nodeLatParent) return false;
    if (state.minMembers > 0 && node.nodeType === 'User') {
      const c = userMembershipCount[node.id] || 0;
      if (c < state.minMembers) return false;
    }
    return true;
  }

  // BFS in beide Richtungen ab startId. Liefert Set aller erreichbaren, sichtbaren Node-IDs.
  function findReachable(startId, visibleSet) {
    const set = new Set([startId]);
    let queue = [startId];
    while (queue.length) {
      const cur = queue.shift();
      (adjOut[cur] || []).forEach(n => {
        if (!set.has(n) && visibleSet.has(n)) { set.add(n); queue.push(n); }
      });
    }
    queue = [startId];
    while (queue.length) {
      const cur = queue.shift();
      (adjIn[cur] || []).forEach(n => {
        if (!set.has(n) && visibleSet.has(n)) { set.add(n); queue.push(n); }
      });
    }
    return set;
  }

  // BFS mit Tiefen-Limit (beide Richtungen). Fuer Display-Mode "Auswahl + Nachbarn".
  function findReachableWithDepth(startId, maxDepth) {
    const result = new Set([startId]);
    if (maxDepth <= 0) return result;
    let queue = [startId];
    for (let d = 0; d < maxDepth; d++) {
      const nextQueue = [];
      queue.forEach(cur => {
        (adjOut[cur] || []).forEach(n => {
          if (!result.has(n)) { result.add(n); nextQueue.push(n); }
        });
        (adjIn[cur] || []).forEach(n => {
          if (!result.has(n)) { result.add(n); nextQueue.push(n); }
        });
      });
      queue = nextQueue;
      if (queue.length === 0) break;
    }
    return result;
  }

  const NORMAL_EDGE = '#555';

  const physicsOptions = {
    layout: { hierarchical: { enabled: false } },
    physics: {
      enabled: true,
      solver: 'barnesHut',
      barnesHut: {
        gravitationalConstant: -150000,
        centralGravity: 0.005,
        springLength: 500,
        springConstant: 0.02,
        damping: 0.4,
        avoidOverlap: 1
      },
      stabilization: {
        enabled: true,
        iterations: 5000,
        updateInterval: 50,
        onlyDynamicEdges: false,
        fit: true
      },
      minVelocity: 0.75
    },
    edges: { arrows: { to: { enabled: true, scaleFactor: 1.2 } }, color: NORMAL_EDGE, smooth: { type: 'continuous' } },
    nodes: { font: { size: 12, face: 'Segoe UI' }, borderWidth: 1, size: 14 },
    interaction: { hover: true, tooltipDelay: 150, navigationButtons: true, keyboard: true }
  };

  const hierarchicalOptions = {
    layout: { hierarchical: { enabled: true, direction: 'DU', sortMethod: 'directed', nodeSpacing: 200, levelSeparation: 220, treeSpacing: 300, blockShifting: true, edgeMinimization: true } },
    physics: { enabled: false },
    edges: { arrows: { to: { enabled: true, scaleFactor: 1.2 } }, color: NORMAL_EDGE, smooth: { type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.4 } },
    nodes: { font: { size: 12, face: 'Segoe UI' }, borderWidth: 1, size: 14 },
    interaction: { hover: true, tooltipDelay: 150, navigationButtons: true, keyboard: true }
  };

  // Persistente DataSets: Filter/Highlight nutzen update() statt setData(),
  // damit Knotenpositionen erhalten bleiben und nichts mehr wackelt.
  const nodesDS = new vis.DataSet(allNodesData);
  const edgesDS = new vis.DataSet(allEdgesData);

  const container = document.getElementById('network');
  const net = new vis.Network(container, { nodes: nodesDS, edges: edgesDS }, physicsOptions);

  // Loading-Overlay-Steuerung
  const loadingDiv  = document.getElementById('loading');
  const loadingProg = document.getElementById('loading-progress');
  const loadingTxt  = document.getElementById('loading-text');
  function showLoading(text) {
    loadingDiv.style.display = 'flex';
    loadingTxt.textContent = text || 'Map wird berechnet...';
    loadingProg.value = 0;
  }
  function hideLoading() { loadingDiv.style.display = 'none'; }

  net.on('stabilizationProgress', params => {
    const percent = Math.round((params.iterations / params.total) * 100);
    loadingProg.value = percent;
    loadingTxt.textContent = 'Stabilisierung: ' + percent + '% (' + params.iterations + ' / ' + params.total + ')';
  });
  net.on('stabilizationIterationsDone', () => {
    // Nach erster Stabilisierung Physics ausschalten -> Filter und Highlight
    // veraendern nur noch Properties, nicht die Positionen.
    net.setOptions({ physics: { enabled: false } });
    hideLoading();
  });

  function render() {
    // Schritt 1: Basis-Sichtbarkeit nach Display-Modus
    let baseSet;
    if (state.displayMode === 'depth') {
      if (highlightId !== null) {
        baseSet = findReachableWithDepth(highlightId, state.depth);
      } else {
        // Default-Einstieg: Tier-0-Kern (Roots + AdminCount=1 + Waisen)
        baseSet = new Set();
        allNodesData.forEach(n => {
          if (isTier0(n)) baseSet.add(n.id);
        });
      }
    } else {
      baseSet = new Set(allNodesData.map(n => n.id));
    }

    // Schritt 2: Zusaetzliche Filter anwenden
    const visibleSet = new Set();
    allNodesData.forEach(n => {
      if (baseSet.has(n.id) && nodeVisible(n)) visibleSet.add(n.id);
    });

    // Schritt 3: pathSet (rote Hervorhebung) nur im "all"-Modus, sonst kein Sinn
    const pathSet = (state.displayMode === 'all' && highlightId !== null && visibleSet.has(highlightId))
      ? findReachable(highlightId, visibleSet)
      : null;

    const nodeUpdates = allNodesData.map(n => {
      const isVis = visibleSet.has(n.id);
      const u = { id: n.id, hidden: !isVis };
      if (isVis) {
        if (pathSet) {
          if (pathSet.has(n.id)) {
            u.color = { background: n._origColor, border: HIGHLIGHT_COLOR };
            u.borderWidth = (n.id === highlightId) ? 6 : 3;
            u.font = { color: '#000', size: 12, face: 'Segoe UI' };
          } else {
            u.color = { background: DIMMED_BG, border: DIMMED_BG };
            u.borderWidth = 1;
            u.font = { color: DIMMED_FONT, size: 12, face: 'Segoe UI' };
          }
        } else if (state.displayMode === 'depth' && n.id === highlightId) {
          // Im depth-Mode: das ausgewaehlte Zentrum rot markieren
          u.color = { background: n._origColor, border: HIGHLIGHT_COLOR };
          u.borderWidth = 6;
          u.font = { color: '#000', size: 12, face: 'Segoe UI' };
        } else {
          u.color = n._origColor;
          u.borderWidth = 1;
          u.font = { color: '#000', size: 12, face: 'Segoe UI' };
        }
      }
      return u;
    });

    const edgeUpdates = allEdgesData.map(e => {
      // Edge-Typ-Filter
      const isKerb = (e.edgeType === 'kerberos-constrained' || e.edgeType === 'kerberos-rbcd');
      const isAcl  = (e.edgeType === 'acl-right');
      let typeAllowed = true;
      if (state.hideKerb && isKerb) typeAllowed = false;
      if (state.hideAcl  && isAcl)  typeAllowed = false;

      const isVis = typeAllowed && visibleSet.has(e.from) && visibleSet.has(e.to);
      const u = { id: e.id, hidden: !isVis };
      if (isVis) {
        // Basis-Farbe nach Edge-Typ
        let baseColor = NORMAL_EDGE;
        let baseWidth = 1;
        if (isKerb)     { baseColor = '#7c3aed'; baseWidth = 2; }
        else if (isAcl) { baseColor = '#f97316'; baseWidth = 2; }

        if (pathSet) {
          if (pathSet.has(e.from) && pathSet.has(e.to)) {
            u.color = { color: HIGHLIGHT_COLOR, highlight: HIGHLIGHT_COLOR };
            u.width = 3;
          } else {
            u.color = { color: DIMMED_BG, opacity: 0.2 };
            u.width = 1;
          }
        } else {
          u.color = { color: baseColor };
          u.width = baseWidth;
          if (e.label) u.label = e.label;
        }
      }
      return u;
    });

    nodesDS.update(nodeUpdates);
    edgesDS.update(edgeUpdates);

    let statsText = 'Sichtbar: ' + visibleSet.size + ' Nodes';
    if (state.displayMode === 'depth') {
      if (highlightId !== null) {
        const hl = allNodesData.find(x => x.id === highlightId);
        const dLabel = (state.depth >= 999) ? 'alle' : state.depth;
        statsText += ' | Zentrum: ' + (hl ? hl.label : '?') + ' (Tiefe ' + dLabel + ')';
      } else {
        statsText += ' | Tier-0-Uebersicht - Knoten anklicken oder suchen, um zu erkunden';
      }
    } else if (pathSet) {
      const hl = allNodesData.find(x => x.id === highlightId);
      statsText += ' | Pfad: ' + (hl ? hl.label : '?') + ' (' + pathSet.size + ' erreichbar)';
    }
    document.getElementById('stats').textContent = statsText;
  }
  render();

  document.getElementById('display-mode').addEventListener('change', e => { state.displayMode = e.target.value; render(); });
  document.getElementById('depth-select').addEventListener('change', e => {
    const v = parseInt(e.target.value, 10);
    state.depth = isNaN(v) ? 2 : v;
    render();
  });

  document.getElementById('f-tier0').addEventListener('change', e => { state.tier0Only = e.target.checked; render(); });
  document.getElementById('f-active').addEventListener('change', e => { state.activeOnly = e.target.checked; render(); });
  document.getElementById('f-hidecomp').addEventListener('change', e => { state.hideComps = e.target.checked; render(); });
  document.getElementById('f-hidefsp').addEventListener('change', e => { state.hideFsp = e.target.checked; render(); });
  document.getElementById('f-hidelateral').addEventListener('change', e => { state.hideLateral = e.target.checked; render(); });
  document.getElementById('f-hidelatmem').addEventListener('change', e => { state.hideLatMem = e.target.checked; render(); });
  document.getElementById('f-hidelatpar').addEventListener('change', e => { state.hideLatPar = e.target.checked; render(); });
  document.getElementById('f-hidekerb').addEventListener('change', e => { state.hideKerb = e.target.checked; render(); });
  document.getElementById('f-hideacl').addEventListener('change', e => { state.hideAcl = e.target.checked; render(); });
  document.getElementById('f-minmem').addEventListener('change', e => {
    const v = parseInt(e.target.value, 10);
    state.minMembers = isNaN(v) || v < 0 ? 0 : v;
    render();
  });

  document.getElementById('layout-select').addEventListener('change', e => {
    showLoading('Layout-Wechsel...');
    if (e.target.value === 'hierarchical') {
      net.setOptions(hierarchicalOptions);
      // Hierarchisches Layout hat keine Physics-Stabilization -> manuell fitten
      setTimeout(() => {
        net.fit({ animation: { duration: 400 } });
        hideLoading();
      }, 200);
    } else {
      // Zurueck zu Physics: re-enabled Stabilization
      net.setOptions(physicsOptions);
      // hideLoading wird durch stabilizationIterationsDone ausgeloest
    }
  });

  // Suche: erster Match wird markiert, alle erreichbaren Pfade hervorgehoben
  document.getElementById('search').addEventListener('input', e => {
    const q = e.target.value.trim().toLowerCase();
    if (!q) {
      highlightId = null;
      render();
      return;
    }
    const match = allNodesData.find(x => (x.label || '').toLowerCase().includes(q));
    if (match) {
      highlightId = match.id;
      render();
      net.focus(match.id, { scale: 1.0, animation: { duration: 400 } });
    } else {
      highlightId = null;
      render();
    }
  });

  // Klick auf Node markiert ebenfalls den Pfad, Klick ins Leere setzt zurueck
  net.on('click', params => {
    if (params.nodes && params.nodes.length > 0) {
      highlightId = params.nodes[0];
      render();
    } else {
      highlightId = null;
      document.getElementById('search').value = '';
      render();
    }
  });
</script>
</body>
</html>
'@

$html = $htmlTemplate
$html = $html.Replace('__DOMAIN__',    [string]$Domain.DNSRoot)
$html = $html.Replace('__TIMESTAMP__', (Get-Date).ToString('yyyy-MM-dd HH:mm'))
$html = $html.Replace('__NODECOUNT__', [string]$Nodes.Count)
$html = $html.Replace('__EDGECOUNT__', [string]$Edges.Count)
$html = $html.Replace('__ROUNDS__',    [string]$round)
$html = $html.Replace('__NODESJSON__', $nJson)
$html = $html.Replace('__EDGESJSON__', $eJson)

$html | Out-File -FilePath $htmlPath -Encoding UTF8

Write-Host ""
Write-Host "Fertig:" -ForegroundColor Green
Write-Host "  HTML:  $htmlPath"
if (Test-Path -LiteralPath $cacheFile) {
    Write-Host "  Cache: $cacheFile"
}
Write-Host ("  Nodes: {0}, Edges: {1}, Konvergenz: {2} Runde(n)" -f $Nodes.Count, $Edges.Count, $round)
Write-Host ("  Laterale Gruppen: {0}, Lat. Members: {1}, Lat. Parents: {2}" -f $lateralCount, $latMemCount, $latParCount)
if ($delegCount -gt 0 -or $kerbEdges -gt 0 -or $aclEdges -gt 0) {
    Write-Host ("  Delegation: {0} Konten markiert, {1} Kerberos-Edges, {2} ACL-Edges" -f $delegCount, $kerbEdges, $aclEdges)
}
if (-not $FromCache) {
    Write-Host ""
    Write-Host "  Tipp: Naechster Lauf nur fuer HTML/Layout-Aenderungen aus Cache:" -ForegroundColor Gray
    Write-Host "  .\Export-ADPrivilegeMap.ps1 -OutputPath '$OutputPath' -FromCache" -ForegroundColor Gray
}
