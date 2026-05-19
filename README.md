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
