Kusura bakma, haklısın. Markdown kod bloğunun çitlerini (`````) ham metin olarak gösterdiğimde dışarıdaki blokla çakıştığı için parçalanmış görünmüş.

Aşağıdaki alanı **sağ üst köşesindeki Kopyala (Copy) butonuna** basarak tek seferde eksiksiz kopyalayabilirsin:

```markdown
# DPI Hunter

An adaptive Deep Packet Inspection (DPI) circumvention tool for Windows, written in C++ using WinDivert.

---

## About

DPI Hunter is a lightweight network utility designed to bypass DPI systems used by ISPs and governments to throttle, monitor, or block internet traffic. It automatically tests and applies the best bypass strategy in real time without dropping active connections.

---

## Features

- **Adaptive Strategy Switching** — Automatically cycles through 9 techniques and locks onto the most effective one.
- **TLS SNI Fragmentation** — Splits Client Hello packets at the SNI extension to evade middleboxes.
- **Fake Packet Injection** — Sends decoy packets with modified TTL / sequence numbers.
- **QUIC / HTTP3 Blocking** — Forces browsers to fall back to TCP, where fragmentation works reliably.
- **Blacklist Support** — Target specific domains only, leaving other traffic untouched.
- **RST Detection** — Instantly re-tests strategies upon detecting DPI reset packets.
- **Zero-Config Setup** — Auto-elevates with UAC and remembers language preferences (`en` / `tr`).

---

## The 9 Strategies

| # | Strategy | Description |
|---|----------|-------------|
| 1-3 | SNI-Frag (1, 2, Before) | Splits packet around the SNI extension start |
| 4-6 | Frag-At (1, 2, 3) | Splits at payload bytes 1, 2, or 3 |
| 7-8 | Fake-TTL (3, 6) | Sends decoy packet with low TTL |
| 9 | Fake-TTL-3-WrongSEQ | Decoy packet with TTL=3 and invalid sequence |

---

## Requirements

- Windows 7 / 8 / 10 / 11 (x64)
- Administrator privileges
- WinDivert 2.x files (`WinDivert.dll` & `WinDivert64.sys`) in the same folder as the `.exe`

---

## Usage

### Basic Execution
1. Download the latest release.
2. Ensure `WinDivert.dll` and `WinDivert64.sys` are in the same folder as `Dpi Hunter.exe`.
3. Right-click `Dpi Hunter.exe` and select **Run as administrator**.
4. On first run, select your preferred language (`en` / `tr`). Your choice will be saved to `dpi_hunter.cfg`.

### Command-Line Arguments
```bash
Dpi Hunter.exe --lang=en    # Force English
Dpi Hunter.exe --lang=tr    # Force Turkish

```

### Blacklist

Create a `blacklist.txt` in the same directory (one domain per line):

```text
twitter.com
youtube.com
discord.com

```

*Note: If no blacklist exists, all TLS traffic is protected.*

---

## Statistics

Live metrics print to the console every 30 seconds:

```text
[07:35:51] STAT pkts=144 frag=3 fake=0 quic=0 rst=0 pass=141 | SNI-Frag-2

```

---

## Troubleshooting

* **"WinDivert could not be opened"**: Ensure you are running as Administrator and `WinDivert.dll` / `WinDivert64.sys` are in the same directory as the executable.
* **Internet connection drops**: Close the program (`Ctrl+C`). WinDivert automatically restores normal network traffic upon exit.

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

Distributed under the MIT License. See `LICENSE` for more information.

---

## Contact & Credits

* Author: [@astegtam](https://github.com/astegtam)
* Discord: `astegtam`
* WinDivert by Basil ([reqrypt.org](https://reqrypt.org))

```

```
