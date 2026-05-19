# Phase 5: Kerberos-Delegation (Unconstrained / Constrained / RBCD)
# Phase 6: ACL-Delegation (GenericAll, WriteDACL, WriteOwner, GenericWrite,
#          ForceChangePassword, DCSync)
# Greifen via Dot-Source auf $Nodes / $Edges zu.

function Invoke-PrivMapKerberosDelegation {
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

function Invoke-PrivMapAclDelegation {
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
