# harvest-moon

Internet-Ping-Sweeper. Scannt IPv4-Adressräume mit nmap und erzeugt
pro `/24` einen Helligkeitswert (Host-Anzahl) — ausgeliefert als `.bin`
(1 Byte pro /24) und client-seitig als Heatmap-Canvas gerendert.

## Architektur (Überblick)

- **16 Workflows** (`.github/workflows/0.yml` … `15.yml`), jeder deckt **16 aufeinanderfolgende
  Class A** ab (Workflow `g` = Class A `g*16` … `g*16+15`, also `0.yml` → 0–15, `15.yml` → 240–255).
- Jeder Workflow hat eine **2D-Matrix aus 16×16 = 256 Jobs** (`classa: [g*16…g*16+15]`,
  `classb: [0,16,32,…,240]`). Das ist exakt GitHub's Matrix-Limit (256 Jobs).
- Jeder Job ruft `scan-classb.sh <classa> <classb_start> [<count>]` auf → scannt **16 Class B** (`classb_start` … `classb_start+15`). `count` ist optional (Default 8).
- Jeder Class-B-Scan wird in **256 parallele `/24`-Scans** zerlegt (`&` + `wait`).
  → **4096 parallele nmap-Prozesse** pro Job (identisch zum 1-Class-A-Layout).
- Ergebnis pro Job: 16 Dateien `results/<classa>.<classb>.txt` (eine pro Class B).
- **Aggregate-Job** (im gleichen Workflow, `needs: scan`): lädt alle Scan-Artifacts
  (`scan-*-`), konkateniert + sortiert sie pro Class A zu `results/<classa>.txt`
  (16 Dateien pro Workflow) und pusht auf den `result`-Branch.

**Performance:** ~1:24 pro Job (16 Class B via 4096 parallele `/24`), also
~3 min pro Class A bei 20er-Concurrency. Pro Workflow (16 Class A) laufen
256 Jobs, verteilt über mehrere Waves (~13 bei 20er-Concurrency).

## scan-classb.sh

```bash
./scan-classb.sh 8 0     # scannt 8.0.0.0/16 – 8.7.0.0/16  (2048 parallel /24)
./scan-classb.sh 8 248   # scannt 8.248.0.0/16 – 8.255.0.0/16
```

Zerlegt das `/16` (65536 IPs) in 256 × `/24` (je 256 IPs) und feuert
sie parallel ab. Jeder Job deckt 16 Class B ab.

Reservierte Bereiche (10/8, 127/8, 172.16/12, 192.168/16, 224+/3) werden
übersprungen.

**nmap-Parameter** (konservativ, zuverlässig):
```
nmap -sn -n -T5 --max-rtt-timeout 200ms \
    --max-retries 1 --host-timeout 300ms \
    --min-hostgroup 65536
```
- `--max-retries 1` — ein Retry fängt Packet-Loss ab (0 Retries verpasst alive-Hosts)
- `--host-timeout 300ms` — Host raus, wenn nicht innerhalb 300 ms geantwortet
- `--max-rtt-timeout 200ms` — einzelner Probe-Timeout

**Output** (in `results/`):
- `<classa>.<classb>.txt` — `/24-Counts` (`classa.classb.classc.0,anzahl`)

## bin/generate-workflows.sh

Generiert alle 16 Workflow-Dateien aus einem Template. Nach Änderungen am
Template einfach neu ausführen:

```bash
./bin/generate-workflows.sh
```

Jede `N.yml` (N = 0…15) enthält:
- Matrix `classa: [N*16…N*16+15]`, `classb: [0,16,32,…,240]` (16×16 = 256 Jobs)
- `scan`-Job: ruft `scan-classb.sh <classa> <classb_start> 16` auf
- `aggregate`-Job: mergt Artifacts (`scan-*`) → 16× `results/<classa>.txt` → push auf `result`-Branch

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

Getriggert durch `workflow_dispatch`. Pro 16 Class A ein Workflow.

Nutzt `nmap -sn` (TCP-SYN, da ICMP auf GitHub blockiert ist) und
`imagemagick` für PNG-Generierung.

### Scan-Modus
16 Workflows (0.yml – 15.yml), jeder mit 16×16 = 256 Matrix-Jobs (2D-Matrix
`classa` × `classb`). Jeder Job scannt 16 Class B via 4096 parallele `/24`-Scans.
→ **~1:24 pro Job**, also ~3 min pro Class A bei 20er-Concurrency.

### Aggregation (`aggregate`-Job pro Workflow)
- lädt alle `scan-*`-Artifacts (`merge-multiple: true`)
- pro Class A: `cat … | sort -t. -k2,2n -k3,3n > results/<classa>.txt`
  (logisch sortiert nach Class B, dann Class C; 16 Dateien pro Workflow)
- pusht auf `result`-Branch (GitHub als Storage, Rebase-Retry bei Konflikten)
- zusätzlich Artifact `classa-<N>` (alle `results/*.txt` des Workflows) für sofortige Weiterverarbeitung

### Render (implementiert)
- Der Render-Schritt ist in jeden `N.yml`-Workflow integriert (Job `aggregate`,
  Schritt `render bin + manifest`). Nachdem der Scan-Aggregat sein
  `results/<classa>.txt` auf den `result`-Branch gepusht hat, lädt der
  Render-Schritt den gesamten `result`-Branch (via `git archive`), konvertiert
  alle `results/*.txt` mit `tools/csv2bin.py` zu:
  - `<classa>.bin` — 65536 Bytes, ein Byte pro /24 (Offset = B*256 + C)
  - `manifest.json` — JSON-Array der Class-A-Nummern mit Daten
  und pusht beides zurück auf den `result`-Branch (Repo-Root, neben `results/*.txt`).
  Es gibt keinen separaten `render.yml`-Workflow mehr (cron entfernt).
- `tools/csv2bin.py`: Input `results/*.txt` (Format `A.B.C.0,COUNT`) →
  Output `<classa>.bin` + `manifest.json` (siehe oben).
- Die Webseite (`site/app.js`) lädt `manifest.json` + `<classa>.bin` per
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
