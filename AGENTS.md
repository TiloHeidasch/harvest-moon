# harvest-moon

Internet-Ping-Sweeper. Scannt IPv4-Adressräume mit nmap und erzeugt
pro `/24` einen Helligkeitswert (Host-Anzahl) — ausgeliefert als `.bin`
(1 Byte pro /24) und client-seitig als Heatmap-Canvas gerendert.

## Architektur (Überblick)

- **16 Workflows** (`.github/workflows/0.yml` … `15.yml`), jeder deckt **16 aufeinanderfolgende
  Class A** ab (Workflow `g` = Class A `g*16` … `g*16+15`, also `0.yml` → 0–15, `15.yml` → 240–255).
- Ein manueller Lauf wählt genau **eine Class A** aus dem 16er-Bereich seines Workflows
  und einen 64-Class-B-Block ab `0`, `64`, `128` oder `192`. Die 64 Zellen laufen in
  16 dependency-gated Scan-Waves mit je vier Class-B-Offsets (`0…3`); jede Wave
  wartet auf die vorige. Die laufende Parallelität ist per Dispatch auf 1 oder 2
  begrenzt (Standard 1), sodass keine Matrixzelle länger als 24 Stunden hinter
  `max-parallel` wartet.
- Jeder Job ruft `scan-classb.sh <classa> <classb> 1` auf. Der Executor bleibt intern
  hart begrenzt; der Workflow verwendet geprüft `SCAN_WORKERS=4`,
  `NMAP_MAX_RATE=25`, `NMAP_TIMEOUT_SECONDS=120`, `SCAN_ATTEMPTS=2` und
  `SCAN_RETRY_DELAY=1`.
- Ergebnis pro Job ist genau ein atomisches Archiv
  `artifacts/scan-<classa>-<classb>-1.tar` mit `results/`- und
  `coverage/`-Fragmenten.
- **Aggregate-Job** (im gleichen Workflow, `needs: scan_wave_0…scan_wave_15`) lädt die Archive ohne
  Überlappungs-Merge und ruft genau einmal `bin/publish-result.sh` auf. Der
  Publisher baut einen frischen `origin/result`-Snapshot, validiert alle Zellen,
  erzeugt kanonische Coverage/Binaries/Manifest-Dateien und pusht höchstens
  einen Commit.

## scan-classb.sh

```bash
./scan-classb.sh 8 0 1     # scans 8.0.0.0/24 (256 hosts)
./scan-classb.sh 8 248 1   # scans 8.248.0.0/24 (256 hosts)
```

Zerlegt das `/16` (65536 IPs) in 256 × `/24` (je 256 IPs) und feuert
sie innerhalb der gebundenen Worker-Anzahl parallel ab. Ein Workflow-Job deckt
genau eine Class B ab.

Reservierte Bereiche (10/8, 127/8, 172.16/12, 192.168/16, 224+/3) werden
übersprungen.

**nmap-Parameter** (konservativ, zuverlässig):
```
nmap -sn -n -T5 --max-rtt-timeout 200ms \
    --max-retries 1 --host-timeout 300ms \
    --min-hostgroup 256
```
- `--max-retries 1` — ein Retry fängt Packet-Loss ab (0 Retries verpasst alive-Hosts)
- `--host-timeout 300ms` — Host raus, wenn nicht innerhalb 300 ms geantwortet
- `--max-rtt-timeout 200ms` — einzelner Probe-Timeout

**Output** (im atomaren Archiv):
- `<classa>.<classb>.txt` — `/24-Counts` (`classa.classb.classc.0,anzahl`)
- `coverage/<classa>.<classb>.json` — ein 256-Zeichen-Fragment mit `S`, `Z`,
  oder `E`.

## bin/generate-workflows.sh

Generiert alle 16 Workflow-Dateien aus einem Template. Nach Änderungen am
Template einfach neu ausführen:

```bash
./bin/generate-workflows.sh
```

Jede `N.yml` (N = 0…15) enthält:
- eine Class-A-Auswahl aus `N*16…N*16+15`, eine Block-Auswahl (`0`, `64`, `128`,
  `192`) und 16 abhängige Scan-Waves mit je `classb_offset: [0,1,2,3]`
  (insgesamt 64 Jobs; die tatsächliche Class B ist Blockstart plus Wave-Basis
  plus Offset)
- je Wave einen Scan-Job: berechnet die kanonische Class B aus Blockstart und
  Offset in Bash und ruft `scan-classb.sh <classa> <classb> 1` auf
- einen `aggregate`-Job, der alle 16 Waves benötigt, die Tar-Envelope-Archive
  getrennt lädt und genau einmal
  `bin/publish-result.sh` für den `result`-Branch auf

## Bild-Hierarchie

Jedes Pixel repräsentiert ein /24-Subnetz. Die Helligkeit (0–255) ist die
Anzahl live-Hosts in diesem /24.

| Level | Dimension | Pixel | Beschreibung |
|---|---|---|---|
| Class C | 16×16 | 1 Pixel | Hosts pro /24 |
| Class B | 16×16 | 256 Pixel | 256 class C in 16×16-Raster |
| Block | 16 class B | 4096 Pixel (256×16) | 16 class B pro Block |
| Class A | 16 Blöcke | 65536 Pixel (256×256) | 16 Blöcke = 1 Class A |
| Gesamt | 256 Class A | 16,7M Pixel (4096×4096) | 256 Class-A-Bilder im 16×16-Quadranten |

## Pixel-Mapping

```
cx = classc % 16       (0–15)  Spalte innerhalb 16×16-Class-C-Raster
cy = classc / 16       (0–15)  Zeile  innerhalb 16×16-Class-C-Raster
bx = classb % 16      (0–15)  Spalte innerhalb Block (16 class B)
```

### Class-A-Grid im Gesamtbild (4096×4096)

Die 256 Class A sind in einem 16×16-Quadranten angeordnet:

```
  quad 0 (Zeilen 0-7)   |  quad 1 (Zeilen 0-7)
  classa  0-63           |  classa  64-127
  ax=classa%8, ay/=8    |  ax=classa%8+8, ay/=8
 ------------------------+------------------------
  quad 2 (Zeilen 8-15)  |  quad 3 (Zeilen 8-15)
  classa 128-191         |  classa 192-255
  ax=classa%8, ay/=8+8  |  ax=classa%8+8, ay/=8+8
```

Globale Pixelposition:
```
x_global = ax * 256 + x_in_classA
y_global = ay * 256 + y_in_classA
```

## CI (`.github/workflows/*.yml`)

Nur durch `workflow_dispatch` aus dem Default-Branch ausgelöst. Es gibt keinen
automatischen Zeitplan. Vor dem Start müssen die exakte Bestätigung
`I_HAVE_WRITTEN_AUTHORIZATION`, die geschriebene Provider-Erlaubnis und die
Freigaben des geschützten GitHub-Environments `internet-scan` vorliegen; diese
Environment-/Provider-Freigaben sind operative Voraussetzungen und werden
nicht vom Repository simuliert.

Nutzt `nmap -sn` (TCP-SYN, da ICMP auf GitHub blockiert ist). Die Seite rendert
die Binärdaten client-seitig; CI erzeugt keine PNG-Dateien.

### Scan-Modus
16 Workflows (0.yml – 15.yml), jeder mit einer Auswahl aus 16 Class A. Ein Lauf
wählt genau eine davon und einen 64-Class-B-Block (`0`, `64`, `128` oder `192`)
und erzeugt 16 dependency-gated Scan-Wave-Jobs mit je vier Matrix-Zellen
(`classa: [selected]` × `classb_offset: [0,1,2,3]`); jeder Job scannt genau eine
Class B. Jede Wave wartet auf die vorige. Die Matrix ist über die Dispatch-Auswahl
sicher auf 1 oder 2 parallele Jobs begrenzt (Standard 1), sodass keine Zelle
länger als 24 Stunden hinter `max-parallel` wartet.
Der Job läuft höchstens 360 Minuten. Bei zwei Versuchen dauert ein worst-case
Class-B-Job nach der konservativen Planung etwa 257 Minuten; die letzte Zelle
einer Wave beginnt bei Parallelität 1 nach etwa `3 × 257 = 771 Minuten`
(12,85 Stunden), die Wave endet nach `4 × 257 = 1.028 Minuten` (17,1 Stunden).
Alle 16 Waves dauern damit bei Parallelität 1 etwa `16 × 17,1 = 274 Stunden`
(11,4 Tage), bei 2 etwa 5,7 Tage, jeweils unter dem 35-Tage-Limit. Die Workflow- und
Executor-Bounds ergeben höchstens `2 × 4 × 25 = 200` Pakete/s repositoryweit.
Die Workflows setzen ausdrücklich `SCAN_WORKERS=4`, `NMAP_MAX_RATE=25`,
`NMAP_TIMEOUT_SECONDS=120`, `SCAN_ATTEMPTS=2` und `SCAN_RETRY_DELAY=1`; diese
Werte überschreiten die festen Executor-Hard-Caps nicht.

Die workflowweite Concurrency-Gruppe `authorized-internet-scan` verwendet
`queue: max` und `cancel-in-progress: false`, damit manuelle Läufe den
Packet-Budget nicht multiplizieren. Der geschützte `internet-scan`-Environment
muss in GitHub so konfiguriert sein, dass seine Deployment-Branch-Regel nur den
Default-Branch erlaubt. Provider-Erlaubnis und Environment-Freigabe bleiben
manuelle operative Voraussetzungen.

### Publisher (`aggregate`-Job pro Workflow)
- lädt alle `scan-*`-Artifacts in getrennte Unterverzeichnisse (kein
  `merge-multiple`-Overwrite)
- validiert exakt eine Tar-Datei pro `(Class A, Class-B-Start)` und alle sicheren
  Tar-Pfade, Rows, Coverage-Zustände und Provenienzwerte
- schreibt `results/<A>.txt`, `coverage/<A>.json`, `policy/sha256-<digest>.json`,
  `<A>.bin` und `manifest.json` in einem Snapshot; veraltete numerische Binaries
  und alte `downloaded/`-Reste werden entfernt
- verwendet die gemeinsame, nicht abbrechende Concurrency-Gruppe
  `result-publisher` mit `queue: max`, erstellt höchstens einen Commit und baut
  nach einem Push-Reject von der neuesten Result-Branch-Spitze neu auf.

`tools/csv2bin.py` akzeptiert weiterhin `results/*.txt`, lehnt unklare oder
konfligierende Rows strikt ab und erzeugt deterministisch `<A>.bin` (65536
Bytes) sowie ein versioniertes `manifest.json`. Für ein vorhandenes Raw-File
ohne `coverage/<A>.json` ist der Manifest-Status ausdrücklich `U` (unverified).

Die Webseite (`site/app.js`) lädt `manifest.json` + `<classa>.bin` per
  `raw.githubusercontent.com/<owner>/<repo>/result/` und rendert client-seitig
  per Canvas/Heatmap (kein imagemagick, keine PNG-Erzeugung in CI).

## Webseite (GitHub Pages)

Die öffentliche Heatmap-Seite liegt als Quelle in `site/` (auf `main`) und
wird über GitHub Pages aus dem **`gh-pages`-Branch (Repo-Root)** ausgeliefert
— nicht aus dem `site/`-Unterordner. `main` = Quelle, `gh-pages` = veröffentlichte Kopie.

### Deployment (`.github/workflows/deploy.yml`)
- Trigger: Push auf `main` (sowie `master`) und `workflow_dispatch`.
- Kopiert `site/*` in den Root des `gh-pages`-Branch (mit 20er-Rebase-Retry,
  identisch zum `result`-Branch-Push der Scan-Workflows) und pusht zurück.
- Änderungen an `site/` einfach nach `main` pushen — der Deploy läuft automatisch.
  Manuell auch über den Actions-Tab auslösbar.

### Seiten-Features (`site/app.js`)
- **Grid-Overlay**: faintes SVG-Raster in %-Koordinaten (scharf bei jeder
  Canvas-Skalierung) mit den 256 Class-A-Zellen (0–255) samt Nummern; die
  Quadrant-Grenzen (alle 8 Class A) sind etwas stärker gezeichnet.
- **Hover-Tooltip** zeigt unter dem Cursor:
  - **Titel** = zugewiesener Zweck/Inhaber der Class A (aus `CLASSA_NAMES`,
    einer Platzhalter-Map — nach und nach mit echten Zuweisungen füllen),
  - die volle `/24`-Adresse `A.B.C.0` und
  - die Host-Anzahl (Live-Lookup aus `binCache`, `—` falls keine Daten).
- Host-Counts werden beim Laden in `binCache` (classa → Uint8Array) gehalten,
  damit der Tooltip ohne erneuten Fetch auskommt.
