# Active Directory Privilege Map

`Export-ADPrivilegeMap.ps1` erzeugt eine voll aufgeloeste Beziehungsmap aller
privilegierten AD-Objekte und exportiert sie als interaktive HTML-Visualisierung.

## Funktionsumfang

- **A1** Auto-Discovery aller Gruppen mit `AdminCount=1` als Tier-0-Roots
- **A2** User-Membership-Walk (per Default nur fuer `AdminCount=1`-User,
  lateral begrenzt, damit der Graph nicht explodiert)
- **A3** SDProp-Waisen (User mit `AdminCount=1` ohne Membership in Tier-0)
- **A4** PrimaryGroupID-Reverse-Lookup (nur fuer `AdminCount=1`-Gruppen)
- **A5** Iterative Konvergenz bis keine neuen Nodes mehr dazukommen
- **B6** Layout-Umschalter Physics / Hierarchisch (Tier-0 oben)
- **B7** Filter-Toolbar (Tier-0, aktive User, Computer/FSP, laterale Gruppen,
  Min-Memberships, Suche)
- **C10** `Write-Progress` fuer alle Schleifen

### Attack-Path-Computation (im HTML)

Die HTML-Visualisierung berechnet im Browser zusaetzlich:

- **Distanz zu Tier-0 pro Node** via Multi-Source-BFS von allen Tier-0-Nodes
  in Inbound-Richtung. Damit weiss jeder Node, wieviele Hops er von
  Domain-Admin-Aequivalent entfernt ist.
- **Display-Modus "Tier-0-Risiko (Distanz)"**: zeigt nur Nodes innerhalb
  einer Max-Distanz und faerbt deren Outline nach Distanz (1 rot, 2
  orange, 3 gelb, 4+ gruen). Mit Selektion wird der kuerzeste Pfad zu
  Tier-0 hervorgehoben (alle gleichlangen Pfade als Layer).
- **Display-Modus "Owned-Cone (Selektion)"**: zeigt die outbound
  transitive Huelle ab einem ausgewaehlten Node - also alle Objekte, die
  dieser Node direkt oder indirekt uebernehmen koennte.
- **Top-Pfade-Panel**: Liste der Nicht-Tier-0-Nodes mit der kuerzesten
  Distanz zu Tier-0, Klick fokussiert den Node + schaltet in den
  Risiko-Modus.

### Darstellungs-Adaptivitaet

- **Programmatische Layouts pro Modus**: Im Tier-0-Risiko-Modus werden
  alle sichtbaren Nodes nach ihrer Distanz zu Tier-0 horizontal in
  Layern angeordnet (Tier-0 oben, Angreifer unten). Im
  Owned-Cone-Modus radial um den selektierten Node, in Ringen pro
  BFS-Hop. Frei verschiebbare Layouts bleiben in den anderen Modi.
- **Smart Auto-Fit**: Beim Wechsel des Modus oder der Selektion fittet
  sich die Kamera auf das aktuell sichtbare Set. Bei <= 3 sichtbaren
  Nodes wird der Zoom hart bei 1.5 begrenzt, damit Einzelknoten nicht
  den ganzen Viewport fuellen. Filter, die nur kleinere Aenderungen
  bewirken (<30% des Gesamtbestands), lassen die Kamera in Ruhe.
- **Adaptive Focus-Zoom**: Klick / Suchtreffer / Top-Pfad-Eintrag
  fokussiert den Node mit einem Scale, der von der Anzahl sichtbarer
  Nachbarn abhaengt - isolierte Nodes werden reingezoomt, Hubs eher
  rausgezoomt.
- **Importance-basierte Node-Groesse**: Dot-Nodes skalieren mit der
  Anzahl ein- bzw. ausgehender Kanten (mode-abhaengig). Tier-0 bekommt
  immer einen festen Groessen-Bonus.
- **Edge-Label-Zoom-Mask**: Edge-Labels (Kerberos-SPNs, ACL-Rechte)
  werden bei Zoom < 0.6 ausgeblendet, damit der Graph im
  Uebersichts-Zoom nicht zur Spaghetti wird.
- **Refit-Button** in der Toolbar zum manuellen Zuruecksetzen der
  Ansicht.

### Impact-/Konsolidierungs-Analyse

Rechtsklick auf einen Gruppen-Knoten oeffnet ein Side-Panel, das die
Folgen eines Loeschens / Umbaus zeigt:

- **Direkte und transitive Mitglieder**, die ihre Mitgliedschafts-Kette
  ueber diese Gruppe verlieren wuerden
- **Parent-Gruppen** (direkt + transitiv), in denen die Gruppe Mitglied
  ist - Tier-0-Treffer werden mit Badge markiert und ueber dem Panel als
  Warnung eingeblendet
- **Gewaehrte Rechte** (ACL-Edges + Kerberos-Delegationen), die mit dem
  Loeschen wegfallen
- **Konsolidierungs-Kandidaten**: andere Gruppen mit der groessten
  Capability-Ueberlappung (gemeinsame Parents + gemeinsame
  ACL/Kerberos-Targets), sortiert nach Overlap-Score - der erste
  Kandidat ist meist eine sinnvolle Ziel-Gruppe fuer einen Merge
- **CSV-Export** aller Sektionen als `impact-<gruppenname>.csv`,
  abarbeitbar fuer den Migrations-/Loesch-Plan
- **"Im Graph hervorheben"** schaltet in Tiefe-3-Ansicht um die Gruppe
  und fokussiert die Kamera

## EDR & SOC Integration

Dieses Tool ist ein **defensiver AD-Audit-Walker** und macht funktional
exakt das, was BloodHound, SharpHound, ADRecon und PingCastle auch tun -
nur fuer die andere Seite. Folge: **jede moderne EDR-Loesung
(CrowdStrike Falcon, Defender for Endpoint, SentinelOne, Cybereason ...)
loest beim Lauf einen Alarm aus**. Das ist erwuenschtes Verhalten und
kein Bug.

### Typische Detektionen

Klassifiziert wird meist als MITRE **T1069 (Permission Groups Discovery)**
oder **T1087 (Account Discovery)**, einige EDRs gruppieren es aggressiv
unter **T1003 (OS Credential Dumping)**. Die Trigger-Patterns:

| Skript-Aktion | Typischer EDR-Indikator |
|---------------|--------------------------|
| LDAP-Filter `(adminCount=1)` | Tier-0-Enumeration-Signature |
| LDAP-Filter `userAccountControl:...:=524288` | Unconstrained-Delegation-Hunting |
| LDAP-Filter `msDS-AllowedToActOnBehalfOfOtherIdentity=*` | RBCD-Hunting |
| `Get-Acl -Path "AD:..."` + Pruefung auf `DS-Replication-Get-Changes-All` | **DCSync-Detection** (der wahrscheinliche Critical-Trigger bei `-IncludeDelegation`) |
| Bulk `Get-ADObject`-Queries | "Bulk enumeration"-Heuristik |

### Was *nicht* passiert (fuer SOC-Validierung)

- Keine `Set-AD*` / `New-AD*` / `Add-AD*` / `Remove-AD*` Operationen
- Kein lsass / SAM / SECURITY-Hive-Zugriff
- Keine ausgehenden Netzverbindungen (Skript laedt nichts aus dem Web)
- Keine Registry-Aenderungen
- Keine Datei-Operationen ausserhalb des explizit angegebenen `-OutputPath`
- Keine `Invoke-Command` / `Invoke-Expression` / `Add-Type`
- Kein `ADSI` / `DirectorySearcher` / `System.DirectoryServices`-Bypass

Vollstaendige Verifikation: `grep -rEhn 'Set-AD|Remove-AD|Invoke-Expression|Add-Type|ADSI|DirectorySearcher' *.ps1 src/*.ps1` liefert null Treffer.

### SOC-Whitelist-Anfrage

Sprich vor dem ersten Produktionslauf mit deinem SOC. Ticket-Vorlage:

> Wir setzen ein internes AD-Privilege-Audit-Tool ein (read-only). Der
> Lauf triggert "OS Credential Dumping" / "Suspicious LDAP Enumeration",
> weil das Tool dieselben LDAP-Patterns nutzt wie BloodHound (das ist by
> design - es ist das defensive Gegenstueck). Es schreibt nichts in AD,
> nichts in die Registry, macht keinen Netzverkehr.
>
> Bitte folgendes whitelisten:
> - **Path**: `<euer-pfad>\Export-ADPrivilegeMap.ps1`
> - **SHA-256**: (per `Get-FileHash` ermitteln)
> - **User-Context**: Dedizierter AD-Audit-Account (siehe unten)
> - **Host-Context**: Audit-Jumpbox (siehe unten)
> - **Detection-Beispiel**: `<crowdstrike-detection-url>`
> - **Tool im Git**: `<repo-link>`

Hash-Liste fuer alle PowerShell-Files generieren:

```powershell
Get-ChildItem -Recurse -Include *.ps1 | Get-FileHash -Algorithm SHA256
```

### Best Practices fuer Produktionslaeufe

1. **Dedizierter Audit-Account** statt persoenlichem Admin-Account.
   Macht das SOC-Whitelisting praezise und sauber attributable.
2. **Dedizierter Audit-Host** (Jumpbox oder Management-VM), den das SOC
   mit angepassten Policies versieht. Sauber gegenueber jedes-Mal-
   Whitelisten von ad-hoc Laeufen.
3. **Change-Ticket vor dem Lauf**: SOC kann Detection-Window
   unterdruecken oder Alarm pre-acknowledged behandeln.
4. **Reduzierter Lauf bei akuter Eile** (falls Whitelist noch nicht
   durch): `.\Export-ADPrivilegeMap.ps1 -Minimal -SkipUserMembershipWalk`
   ohne `-IncludeDelegation`. Skippt die DCSync-ACL-Suche (der
   wahrscheinliche Critical-Trigger), reduziert Query-Volumen um ~70%.
   Du verlierst dafuer die ACL-/Kerberos-Edges im Graph.

### Was du **nicht** tun solltest

Den Code so umbauen, dass er an der EDR vorbeikommt. Das waere
defensiv falsch - wenn ein Tool dieser Bauart "stealthy" geht, hat
auch dein zukuenftiger Angreifer einen Vorteil daraus. Ziel ist
**transparenter, whitelisteter Lauf** durch koordiniertes Vorgehen
mit dem SOC.

## Output-Dateien

Nach einem erfolgreichen Lauf liegen im `-OutputPath`:

```
$OutputPath/
├── ad-priv-map.html         ~780 KB - HTML + vis-network-Lib inline (keine Daten)
├── ad-priv-map-data.js      ~variabel - window.__PRIVMAP_DATA mit Nodes/Edges/Meta
└── ad-priv-map-cache.json   ~variabel - Roh-Daten fuer -FromCache-Reruns
```

**Wichtig: `ad-priv-map.html` und `ad-priv-map-data.js` muessen
zusammen liegen.** Die HTML laedt die Daten ueber
`<script src="ad-priv-map-data.js">` aus dem gleichen Ordner. Beide
Files immer zusammen kopieren oder verschicken - sonst zeigt der Browser
eine rote Fehlermeldung statt der Map.

Vorteil dieser Trennung: HTML/CSS/JS lassen sich direkt editieren und im
Browser refresh anzeigen, ohne erneuten Skript-Lauf. Fuer
Template-Aenderungen reicht `.\Export-ADPrivilegeMap.ps1 -FromCache
-OutputPath <derselbe Ordner>` (Subsekunden-Re-Render aus Cache).

## Voraussetzungen

- Windows PowerShell 5.1 oder PowerShell 7+
- RSAT / Modul `ActiveDirectory`
- Leseberechtigung auf dem Ziel-Forest

## Verwendung

```powershell
# Standardlauf
.\Export-ADPrivilegeMap.ps1 -OutputPath C:\Temp

# A2 komplett deaktivieren
.\Export-ADPrivilegeMap.ps1 -OutputPath C:\Temp -SkipUserMembershipWalk

# A2 fuer ALLE User (Achtung: blaeht den Graph stark auf)
.\Export-ADPrivilegeMap.ps1 -OutputPath C:\Temp -FullUserMembershipWalk

# Manuelle Root-Auswahl per Out-GridView
.\Export-ADPrivilegeMap.ps1 -OutputPath C:\Temp -Pick
```

### Parameter

| Parameter | Beschreibung |
|-----------|--------------|
| `-OutputPath` | Zielordner fuer die Exporte. Default: `%TEMP%\AD-PrivMap-<Timestamp>` |
| `-MaxDepth` | Maximale Rekursionstiefe pro Richtung. Default: `12` |
| `-MaxRounds` | Maximale Konvergenzrunden. Default: `8` |
| `-Pick` | Oeffnet `Out-GridView` fuer manuelle Root-Auswahl |
| `-SkipUserMembershipWalk` | Deaktiviert A2 komplett |
| `-FullUserMembershipWalk` | A2 fuer ALLE User |
| `-Minimal` | Reduzierter Export |
| `-IncludeDelegation` | Delegations-Edges mit aufnehmen |
| `-FromCache` | Lauf aus zuvor exportiertem Cache wiederherstellen |
| `-CachePath` | Pfad zum Cache |
| `-ExtraRootGroups` | Zusaetzliche Root-Gruppen (`SAMAccountName`) |

## Repo-Struktur

```
Export-ADPrivilegeMap.ps1     # Einstiegspunkt (Orchestrierung, ~250 Zeilen)
src/
  Graph.ps1                   # Add-Node / Add-Edge
  Walks.ps1                   # Expand-Members / -MemberOf / -UserMemberships / Add-PrimaryGroupMembers
  Discovery.ps1               # A1 Root-Discovery + A3 SDProp-Waisen
  Convergence.ps1             # A5 Konvergenz + Phase 3/4 (laterale Members/Parents)
  Delegation.ps1              # Phase 5 Kerberos + Phase 6 ACL
  Cache.ps1                   # JSON-Cache lesen/schreiben
  Export-Html.ps1             # HTML-Render aus Template
templates/
  ad-priv-map.html.tmpl       # vis-network HTML-Template mit Platzhaltern
```

Die Helper unter `src/` werden vom Wrapper per Dot-Source geladen. Damit
sieht jede Funktion den State (`$Nodes`, `$Edges`, Visited-Sets,
`$MaxDepth`, ...) im aufrufenden Skript-Scope und kann ihn in-place
mutieren - das Verhalten ist identisch zum Original-Monolithen.
