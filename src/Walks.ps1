# AD-Walk-Helper.
# Greifen ueber Skript-Scope auf $MaxDepth, $VisitedDown, $VisitedUp,
# $VisitedUserMembership, $VisitedPrimary, $DirectTier0Users, $Nodes zu.

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
