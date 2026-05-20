# ==============================================================================
# Active Directory Privilege Map - DEFENSIVE AD AUDIT TOOL (READ-ONLY)
# ==============================================================================
# Purpose   Maps Tier-0 group membership + Kerberos/ACL privilege paths.
# Behavior  ActiveDirectory PowerShell module Get-* cmdlets ONLY.
#           No Set-* / New-* / Remove-* AD operations.
#           No SAM / lsass / registry / token access.
#           No outbound network calls.
#           Writes only to the user-specified -OutputPath.
# EDR note  This tool triggers behavioral detections similar to BloodHound /
#           SharpHound / PingCastle (LDAP (adminCount=1), msDS-AllowedTo*,
#           DCSync-ACL walk). That is expected for any AD-enumeration audit
#           tool. See README "EDR & SOC Integration" for whitelist guidance.
# Source    https://github.com/SilvioTormen/Active-Directory-Privilege-Map-
# ==============================================================================
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

# ----------------------------- Module laden -----------------------------
# EDR-Hinweis: Cache.ps1 + Export-Html.ps1 enthalten keine AD-Cmdlets und
# triggern AMSI nicht. Die anderen Module (Walks/Discovery/Convergence/
# Delegation/Graph) enthalten Get-ADUser/Get-ADGroup/Get-ADObject - AMSI
# scant beim Dot-Sourcing den Skript-Body und kann das (faelschlich) als
# BloodHound/SharpHound-Recon klassifizieren, OHNE dass die Funktionen
# je aufgerufen werden. Im -FromCache-Modus brauchen wir diese Module
# NICHT (es findet kein AD-Walk statt), also gar nicht erst laden.
$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) { $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }

. (Join-Path $ScriptRoot 'src/Cache.ps1')
. (Join-Path $ScriptRoot 'src/Export-Html.ps1')

if (-not $FromCache) {
    . (Join-Path $ScriptRoot 'src/Graph.ps1')
    . (Join-Path $ScriptRoot 'src/Walks.ps1')
    . (Join-Path $ScriptRoot 'src/Discovery.ps1')
    . (Join-Path $ScriptRoot 'src/Convergence.ps1')
    . (Join-Path $ScriptRoot 'src/Delegation.ps1')
}

$TemplatePath = Join-Path $ScriptRoot 'templates/ad-priv-map.html.tmpl'

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

# ----------------------------- Cache-Load oder AD-Walk ----------------------
$cacheFile = if ($CachePath) { $CachePath } else { Join-Path $OutputPath 'ad-priv-map-cache.json' }

if ($FromCache) {
    $cacheFile = Resolve-PrivMapCachePath -CachePath $CachePath -OutputPath $OutputPath
    $cache     = Read-PrivMapCache -Path $cacheFile

    # Domain rekonstruieren (nur DNSRoot wird im HTML-Export benoetigt)
    $Domain = [PSCustomObject]@{ DNSRoot = $cache.Meta.Domain }

    foreach ($n in $cache.Nodes) { $Nodes[$n.Id] = $n }
    foreach ($e in $cache.Edges) {
        $Edges.Add([PSCustomObject]@{
            From     = $e.From
            To       = $e.To
            EdgeType = $e.EdgeType
            Label    = $e.Label
        })
    }

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

$autoRoots = Get-PrivMapRootGroups -ExtraRootGroups $ExtraRootGroups -Pick:$Pick

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
Find-PrivMapSDPropOrphans

# ----------------------------- A5: Iterative Konvergenz -----------------------------
$round = Invoke-PrivMapConvergence `
    -MaxRounds $MaxRounds `
    -SkipUserMembershipWalk ([bool]$SkipUserMembershipWalk) `
    -OnlyPrivilegedUsers $onlyPrivilegedUsers `
    -LooseA2 $looseA2

$lateralCount = @($Nodes.Values | Where-Object { $_.LateralOnly }).Count
Write-Host ("  Konvergenz nach {0} Runde(n). Endstand: {1} Nodes (davon {2} laterale Gruppen), {3} Edges." -f $round, $Nodes.Count, $lateralCount, $Edges.Count) -ForegroundColor Green

# ----------------------------- Phase 3 + 4: Laterale Members / Parents ---------------
if (-not $Minimal) {
    Expand-PrivMapLateralMembers
    Expand-PrivMapLateralParents
}

$latMemCount = @($Nodes.Values | Where-Object { $_.LateralMemberOnly }).Count
$latParCount = @($Nodes.Values | Where-Object { $_.LateralParentOnly }).Count

# ----------------------------- Phase 5 + 6: Delegation -------------------------------
if ($IncludeDelegation) {
    Invoke-PrivMapKerberosDelegation
    Invoke-PrivMapAclDelegation
}

$delegCount  = @($Nodes.Values | Where-Object { $_.HasDelegation }).Count
$kerbEdges   = @($Edges | Where-Object { $_.EdgeType -like 'kerberos-*' }).Count
$aclEdges    = @($Edges | Where-Object { $_.EdgeType -eq 'acl-right' }).Count

# ----------------------------- Cache schreiben ---------------------------------------
$meta = @{
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
Write-PrivMapCache -Path $cacheFile -Nodes $Nodes.Values -Edges $Edges -Meta $meta

}  # Ende if (-not $FromCache)

# ----------------------------- HTML-Export -----------------------------
$htmlPath = Join-Path $OutputPath 'ad-priv-map.html'
$exportResult = Export-PrivMapHtml `
    -Path          $htmlPath `
    -TemplatePath  $TemplatePath `
    -Nodes         $Nodes.Values `
    -Edges         $Edges `
    -DomainDnsRoot $Domain.DNSRoot `
    -Rounds        $round

Write-Host ""
Write-Host "Fertig:" -ForegroundColor Green
Write-Host "  HTML:  $($exportResult.HtmlPath)"
Write-Host "  Data:  $($exportResult.DataPath)  <- muss neben der HTML liegen"
if (Test-Path -LiteralPath $cacheFile) {
    Write-Host "  Cache: $cacheFile"
}
Write-Host ("  Nodes: {0}, Edges: {1}, Konvergenz: {2} Runde(n)" -f $Nodes.Count, $Edges.Count, $round)
Write-Host ("  Laterale Gruppen: {0}, Lat. Members: {1}, Lat. Parents: {2}" -f $lateralCount, $latMemCount, $latParCount)
if ($delegCount -gt 0 -or $kerbEdges -gt 0 -or $aclEdges -gt 0) {
    Write-Host ("  Delegation: {0} Konten markiert, {1} Kerberos-Edges, {2} ACL-Edges" -f $delegCount, $kerbEdges, $aclEdges)
}
Write-Host ""
Write-Host "  Wichtig: ad-priv-map.html und ad-priv-map-data.js IMMER zusammen kopieren/verschicken." -ForegroundColor Yellow
if (-not $FromCache) {
    Write-Host "  Tipp: Naechster Lauf nur fuer HTML/Layout-Aenderungen aus Cache:" -ForegroundColor Gray
    Write-Host "  .\Export-ADPrivilegeMap.ps1 -OutputPath '$OutputPath' -FromCache" -ForegroundColor Gray
}
