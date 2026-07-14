# harvest-moon

Internet-Ping-Sweeper. Scannt IPv4-Adressräume mit nmap und erzeugt
256×256 Graustufen-PNGs (ein Pixel pro /24, Helligkeit = Host-Anzahl).

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
- `$classa.$block.png` — 16×256 Graustufen-PNG

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
222 × 16 = 3552 Jobs, jeder scannt einen Block und erzeugt ein 16×256-PNG.
Danach kombiniert ein **render**-Job pro Class A die 16 Blöcke zu einem
256×256-PNG.
