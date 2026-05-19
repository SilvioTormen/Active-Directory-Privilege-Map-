# A5: Iterative Konvergenz + Phase 3 (laterale Members) + Phase 4 (laterale Parents).
# Greifen via Dot-Source auf $Nodes, $Edges und die Walk-Helper zu.

function Invoke-PrivMapConvergence {
    param(
        [Parameter(Mandatory)][int]$MaxRounds,
        [Parameter(Mandatory)][bool]$SkipUserMembershipWalk,
        [Parameter(Mandatory)][bool]$OnlyPrivilegedUsers,
        [Parameter(Mandatory)][bool]$LooseA2
    )

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
                Expand-UserMemberships -UserDN $Nodes[$uid].DistinguishedName -OnlyPrivileged $OnlyPrivilegedUsers -LooseA2 $LooseA2
            }
            Write-Progress -Activity "Konvergenz Runde $round - User-Memberships" -Completed
        }

        $currTotal = $Nodes.Count
    }

    return $round
}

function Expand-PrivMapLateralMembers {
    # Phase 3: einmaliger Lade-Pass der Members aller LateralOnly-Gruppen.
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

function Expand-PrivMapLateralParents {
    # Phase 4: einmaliger Lade-Pass der MemberOf aller LateralOnly-Gruppen.
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
