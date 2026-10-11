# DPI Hunter

A small Windows tool that helps you get around DPI (Deep Packet Inspection) based website blocking. It works like GoodbyeDPI: it uses [WinDivert](https://reqrypt.org/windivert.html) to change your outgoing TLS handshakes so that the DPI system can no longer read the host name (SNI) and block the connection.

By astegtam. Current version: **v2.1**

## Features

- 10 bypass strategies (packet splitting and fake packets) plus a Safe-Mode
- Automatic strategy selection: the tool tests your sites and switches only when a site is really blocked
- Optional blacklist: only the sites in your list are touched
- QUIC blocking so browsers fall back to TCP+TLS (which this tool can bypass)
- Turkish and English interface

## Requirements

- Windows 10 / 11 (64-bit)
- Administrator rights (the tool restarts itself as admin if needed)
- WinDivert 2.2.x files next to `dpi_hunter.exe`:
  - `WinDivert.dll`
  - `WinDivert64.sys`

`WinDivert.dll`, `WinDivert64.sys` and `windivert.h` must come from the same WinDivert version.

## Usage

1. Put `dpi_hunter.exe`, `WinDivert.dll` and `WinDivert64.sys` in the same folder.
2. Run `dpi_hunter.exe`. On the first start you choose a language. The choice is saved in `dpi_hunter.cfg`; delete that file to choose again.
3. Leave the window open while you browse. Press `Ctrl+C` (or close the window) to stop.

Command line options:

```
dpi_hunter.exe --lang=tr
dpi_hunter.exe --lang=en
```

### Blacklist (optional)

Create a text file named `blacklist.txt` (`listem.txt` and `list.txt` also work) next to the exe. One domain per line, `#` starts a comment:

```
# example
discord.com
youtube.com
```

- An entry also matches its subdomains (`discord.com` matches `cdn.discord.com`).
- With a blacklist, only these sites are modified and the automatic tests use them.
- Without a blacklist, all TLS traffic is protected.

## Strategies

| Name | What it does |
|---|---|
| SNI-Frag-1 / SNI-Frag-2 / SNI-Frag-Before | Splits the ClientHello packet inside or right before the host name |
| Frag-At-1 / Frag-At-2 / Frag-At-3 | Splits the ClientHello at a fixed byte (Frag-At-2 is the default, like GoodbyeDPI `-e 2`) |
| Fake-TTL-3 / Fake-TTL-6 | Sends a fake ClientHello with a harmless host name that expires before it reaches the server |
| Fake-TTL-3-WrongSEQ | Same as above, with a wrong sequence number |
| Fake-BadChecksum | Fake ClientHello with a broken TCP checksum |
| Safe-Mode | Does nothing (passthrough) |

## How the automatic mode works

- About 8 seconds after start, and then every 5 minutes, the tool opens a TLS connection to a few sites and checks that the server answers.
- DNS or connection errors are ignored. Only "connected but the handshake was blocked" counts as DPI blocking.
- If a round fails, the tool tries the other strategies and keeps the first one that works. If none works, the old strategy stays.
- After 3 failed rounds in a row the tool enters Safe-Mode for 10 minutes and then tries again.
- If 3 connection resets arrive within 15 seconds, a recovery check starts immediately.

## Tips

- Some blocks are done with DNS as well (for example Discord in some countries). This tool does not change DNS. Turn on encrypted DNS (DNS over HTTPS) in Windows, for example with 1.1.1.1 or 8.8.8.8.
- If the tool does not start, the error code and a short reason are printed. Common causes: not running as admin, missing `WinDivert64.sys`, or mismatched WinDivert file versions.

## Limitations

- IPv4 only
- Only TLS on port 443 (and QUIC on UDP 443) is handled
- DNS is not redirected or encrypted by this tool

## Build

1. Visual Studio, C++ desktop development, target **x64**.
2. Add the WinDivert `include` folder (for `windivert.h`) and the `x64` library folder (for `WinDivert.lib`) to the project.
3. Build `dpi_hunter.cpp`. The libraries `WinDivert.lib` and `ws2_32.lib` are linked by `#pragma comment`.
4. Copy `WinDivert.dll` and `WinDivert64.sys` next to the built exe.

## Contact

Questions, bug reports or ideas: contact **astegtam** on Discord.

## Disclaimer

This project is for educational purposes. Laws about circumventing network restrictions differ between countries. You are responsible for how you use it. Use at your own risk.
