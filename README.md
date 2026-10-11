# DPI Hunter

An adaptive Deep Packet Inspection (DPI) circumvention tool for Windows, written in C++ using WinDivert.

---

## About

DPI Hunter is a lightweight network utility that helps bypass Deep Packet Inspection (DPI) systems used by ISPs and governments to block, throttle, or monitor internet traffic.

It automatically detects which bypass strategy works on your network, applies it in real time, and switches on the fly if the connection starts failing — without breaking existing connections or requiring manual configuration.

Just double-click and it runs.

---

## Purpose

This project was built for **personal privacy and security research**. It is intended to help users protect their own traffic from invasive inspection in regions where internet access is restricted or monitored.

It is not designed to attack, exploit, or damage any network or system.

---

## Features

- Adaptive Strategy Switching — Tests 9 different bypass techniques and locks onto whichever works best on your network.
- TLS SNI Fragmentation — Splits TLS Client Hello packets at the SNI extension to confuse DPI middleboxes.
- Fake Packet Injection — Sends decoy packets with manipulated TTL / sequence numbers.
- QUIC / HTTP3 Blocking — Drops QUIC traffic so browsers fall back to TCP, where fragmentation works.
- Blacklist Support — Apply circumvention only to specific domains, leaving other traffic untouched.
- RST Detection — Detects DPI reset packets in real time and re-tests strategies instantly.
- Live Status Panel — See the active strategy and live statistics in real time.
- Multi-Language — English and Turkish UI, configurable and remembered across runs.
- Zero-Config Setup — Auto-elevates with UAC, auto-detects the best strategy, click and go.

---

## How It Works

User Traffic
     |
     v
WinDivert Kernel Hook  (Captures outbound TCP + QUIC)
     |
     v
SNI Extractor  (Parses TLS Client Hello)
     |
     v
Strategy Engine  (9 techniques, auto-switch)
  - SNI Fragmentation
  - Fake TTL Injection
  - Wrong SEQ Numbers
     |
     v
Modified Packet  (Fragmented / Signed / Fake)
     |
     v
Internet

### The 9 Strategies

| # | Name | Description |
|---|------|-------------|
| 1 | SNI-Frag-1 | Split 1 byte after the SNI extension starts |
| 2 | SNI-Frag-2 | Split 2 bytes after the SNI extension starts |
| 3 | SNI-Frag-Before | Split right before the SNI extension |
| 4 | Frag-At-1 | Split at payload byte 1 |
| 5 | Frag-At-2 | Split at payload byte 2 |
| 6 | Frag-At-3 | Split at payload byte 3 |
| 7 | Fake-TTL-3 | Send decoy packet with TTL=3 |
| 8 | Fake-TTL-6 | Send decoy packet with TTL=6 |
| 9 | Fake-TTL-3-WrongSEQ | Send decoy with TTL=3 and invalid sequence |

The engine tests these against real HTTPS endpoints (YouTube, Twitter, Discord, or your own blacklist), measures the success rate, and switches automatically.

---

## Requirements

- Windows 7 / 8 / 10 / 11 (x64)
- Visual Studio 2019 or later
- WinDivert 2.x — Driver + library (https://reqrypt.org/windivert.html)
- Administrator privileges (required by WinDivert)

---

## Getting the Source

Clone the repository:

   git clone https://github.com/astegtam/dpi-hunter.git
   cd dpi-hunter

Or download it as ZIP from the green "Code" button on GitHub and extract it.

---

## Usage

### Basic

Just double-click Dpi Hunter.exe. On the first run, a language selection menu appears:

  Select Language / Dil Secin

    [1]  Turkce
    [2]  English

  Your choice [1-2]: _

Press 1 or 2 — your choice is saved to dpi_hunter.cfg and remembered.

### Command-Line Arguments

  Dpi Hunter.exe --lang=tr        Force Turkish for this session
  Dpi Hunter.exe --lang=en        Force English

### Changing Language Later

Delete dpi_hunter.cfg and restart — the menu will appear again.

### Blacklist

Create a blacklist.txt in the same folder as the .exe:

  # DPI Hunter blacklist — one domain per line
  # Lines starting with # are ignored

  twitter.com
  youtube.com
  discord.com
  roblox.com

When a blacklist is present, DPI Hunter only applies circumvention to those domains. All other traffic passes through untouched — better performance and compatibility.

If no blacklist exists, all TLS traffic is protected.

### QUIC Blocking

QUIC (UDP port 443) is automatically dropped so browsers fall back to TCP/TLS. This is where fragmentation actually works — DPI can't inspect encrypted QUIC the same way.

If you need QUIC for a specific application, disable this in the source (cfg.blockQuic = false).

---

## Configuration File

dpi_hunter.cfg — created automatically on first run.

  # DPI Hunter configuration
  # Delete this file to change language
  lang=en

| Key | Values | Description |
|-----|--------|-------------|
| lang | tr / en | UI language |

---

## Statistics

Live statistics are printed every 30 seconds when there's activity:

  [07:35:51] STAT pkts=144 frag=3 fake=0 quic=0 rst=0 pass=141 | SNI-Frag-2

| Field | Meaning |
|-------|---------|
| pkts | Total packets processed |
| frag | Packets fragmented |
| fake | Decoy packets sent |
| quic | QUIC packets blocked |
| rst | DPI reset packets detected |
| pass | Packets forwarded unchanged |
| Strat | Currently active strategy |

---

## Troubleshooting

### "WinDivert could not be opened"

- Make sure you're running as administrator.
- Ensure WinDivert.dll and WinDivert64.sys are in the same folder as the executable.
- Check that no antivirus is blocking the driver.

### "No strategy works"

- Your ISP might use a more advanced DPI. Try adding more domains to blacklist.txt so the tool can test more endpoints.
- Restart the program to trigger a fresh round of tests.

### Internet stops working

- DPI Hunter never drops legitimate packets — it only fragments or injects. If internet dies, close the program (Ctrl+C in the console or kill the process). WinDivert releases all hooks on exit.

### Program doesn't stop on Ctrl+C

- DPI Hunter already disables QuickEdit mode programmatically. If it still happens, right-click the console title bar -> Properties -> uncheck QuickEdit Mode.

---

## Known Limitations

- IPv6 not yet supported — Only IPv4 traffic is processed.
- No GUI — Command-line interface only.
- No Windows Service mode — Must be running to work.
- QUIC fully blocked — Applications requiring HTTP/3 will fall back to HTTP/2.

Roadmap: IPv6 support, system tray icon, service installation, per-domain traffic counters.

---

## Security Notes

- DPI Hunter requires administrator privileges because WinDivert loads a kernel-mode driver.
- The driver is signed by the WinDivert project — verify the signature before use.
- DPI Hunter does not phone home, log traffic, or send telemetry anywhere.
- The source is fully open — audit it yourself.
- No data is collected, stored, or transmitted by this program.

---

## Disclaimer

This software is provided for **educational and research purposes only**, and to help users protect their personal privacy in regions with restrictive internet policies.

The author **does not take any responsibility** for:
- Any misuse of this tool
- Any legal consequences resulting from its use
- Any network, system, or data damage caused directly or indirectly
- Any violation of local, national, or international laws

This tool does not attack, exploit, or harm any network or system. It only modifies the user's own outbound traffic before it leaves their machine.

**Use at your own risk.** You are solely responsible for how you use this software. Always comply with the laws of your country.

---

## Credits

- Author: @astegtam (https://github.com/astegtam)
- WinDivert: Basil (reqrypt.org)

---

## Contact

For questions, bug reports, feature requests, or general feedback:

- Discord: astegtam

Feel free to reach out directly on Discord.

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first.

1. Fork the repository
2. Create a feature branch (git checkout -b feature/amazing-feature)
3. Commit your changes (git commit -m 'Add amazing feature')
4. Push to the branch (git push origin feature/amazing-feature)
5. Open a Pull Request

---

## License

MIT License

---

## Support

If this project helped you, consider giving it a star on GitHub.

For direct inquiries, contact astegtam on Discord.
