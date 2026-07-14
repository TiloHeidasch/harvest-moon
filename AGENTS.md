# harvest-moon

Internet-Ping-Sweeper. Scannt IPv4-Adressräume mit nmap und erzeugt
Graustufen-PNGs (ein Pixel pro /24, Helligkeit = Host-Anzahl).

## harvest.sh

Nimmt eine Class A (0–255) und einen Block (0–15, jeder = 16 class B):

```bash
./harvest.sh 8 0     # scannt 8.0.0.0/16 – 8.15.0.0/16, erzeugt 8.0.png
./harvest.sh 8 1     # scannt 8.16.0.0/16 – 8.31.0.0/16, erzeugt 8.1.png
```

Reservierte Bereiche (10/8, 127/8, 172.16/12, 192.168/16, 224+/3) werden
übersprungen.

**Output** (in `results/`):
- `$classa.$block.txt` — `/24-Counts` (`classa.classb.classc.0,anzahl`)
- `$classa.$block.png` — 256×16 Graustufen-PNG

## Bild-Hierarchie

Jedes Pixel repräsentiert ein /24-Subnetz. Die Helligkeit (0–255) ist die
Anzahl live-Hosts in diesem /24.

| Level | Dimension | Pixel | Beschreibung |
|---|---|---|---|
| Class C | 16×16 | 1 Pixel | Hosts pro /24 |
| Class B | 16×16 | 256 Pixel | 256 class C in 16×16-Raster |
| Block | 16 class B | 4096 Pixel (256×16) | Im Scan-Job erzeugt |
| Class A | 16 Blöcke | 65536 Pixel (256×256) | 16 Blöcke per `-append` gestapelt |
| Gesamt | 256 Class A | 16,7M Pixel (4096×4096) | 256 Class-A-Bilder im 16×16-Quadranten |

### Pixel-Mapping pro Block (256×16)

```
cx = classc % 16       (0–15)  Spalte innerhalb 16×16-Class-C-Raster
cy = classc / 16       (0–15)  Zeile  innerhalb 16×16-Class-C-Raster
bx = classb % 16       (0–15)  Spalte innerhalb Block (16 class B)

Pixelposition = cy * 256 + (bx * 16 + cx)
```

### Render: Blöcke → Class A

`convert 8.0.png 8.1.png … 8.15.png -append 8.png`

Jeder Block liefert 16 Zeilen à 256 Pixel → 16 Blöcke = 256×256.

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

## CI (`.github/workflows/harvest.yml`)

Wird getriggert durch `workflow_dispatch`.

Nutzt `nmap -sn` (TCP-SYN, da ICMP auf GitHub blockiert ist) und
`imagemagick` für PNG-Generierung.

### Test-Modus (aktuell)

```yaml
classa: [8]
block: [0,1]
```
2 Jobs, scannen 8.0.0.0/16 – 8.31.0.0/16.

### Vollbetrieb (vorbereitet, auskommentiert)

```yaml
classa: [0,1,2,…,9,11,…,126,128,…,223]   # 222 Werte (reservierte ausgelassen)
block: [0,1,…,15]                         # 16 Werte
```
222 × 16 = 3552 Jobs, jeder scannt einen Block und erzeugt ein 256×16-PNG.
Danach kombiniert ein **render**-Job pro Class A die 16 Blöcke per `-append`
zu einem 256×256-PNG.
