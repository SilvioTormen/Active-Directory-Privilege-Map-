# Read-only helper for Export-ADPrivilegeMap.ps1 (defensive AD audit tool).
# In-memory node/edge bookkeeping - no I/O at all.
# Graph-Helper.
# Diese Funktionen sind absichtlich scope-lose Closures: sie greifen auf
# $Nodes, $Edges und $EdgeKeys im aufrufenden Skript-Scope zu (dot-source).

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
