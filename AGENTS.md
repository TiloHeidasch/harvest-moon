# harvest-moon

Internet-Ping-Sweeper. Scannt IPv4-Adressräume mit nmap und erzeugt
256×256 Graustufen-PNGs (ein Pixel pro /24, Helligkeit = Host-Anzahl).

## harvest.sh

Nimmt eine Class A (0–255) und optional eine Class-B-Spezifikation:

```bash
./harvest.sh 8         # alle 256 class B in 8.x.x.x
./harvest.sh 8 8       # nur 8.8.0.0/16
./harvest.sh 8 0-15    # 8.0.0.0/16 – 8.15.0.0/16
./harvest.sh 8 8 8     # nur 8.8.8.0/24
./harvest.sh 8 8 8 9 10  # mehrere /24
```

Reservierte Bereiche (10/8, 127/8, 172.16/12, 192.168/16, 224+/3) werden
übersprungen.

**Output** (in `results/`):
- `$classa.txt` — `/24-Counts` (`classb.classc.0,anzahl`)
- `$classa.png` — 256×256 Graustufen-PNG

## CI (`.github/workflows/harvest.yml`)

Wird getriggert durch `push` auf `main` oder manuell via `workflow_dispatch`.

Nutzt `nmap -sn` (TCP-SYN, da ICMP auf GitHub blockiert ist) und
`imagemagick` für PNG-Generierung.

### Test-Modus (aktuell)

```yaml
classa: [8]
```
`./harvest.sh 8 0-15` — scannt die ersten 16 class-B-Netze von 8.x.x.x.

### Vollbetrieb (vorbereitet, auskommentiert)

```yaml
classa: [0,1,2,…,255]
```
256 Jobs, jeder scannt eine Class A und erzeugt ein PNG.
