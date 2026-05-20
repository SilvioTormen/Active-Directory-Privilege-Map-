# Read-only helper for Export-ADPrivilegeMap.ps1 (defensive AD audit tool).
# Only Get-AD* cmdlets - no AD modifications.
# A1: Root-Discovery
# A3: SDProp-Waisen

function Get-PrivMapRootGroups {
    param(
        [string[]]$ExtraRootGroups = @(),
        [switch]$Pick
    )

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

    return ,$autoRoots
}

function Find-PrivMapSDPropOrphans {
    # Greift via Dot-Source-Scope auf $Nodes zu (Add-Node mutiert in place).
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
}
