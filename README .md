# DPI Hunter

**by astegtam**

A single-file Windows tool that studies and counters Deep Packet Inspection (DPI) filtering of TLS SNI, HTTP Host, QUIC and DNS. It runs in a console with an animated intro, arrow-key menus and a live dashboard.

> **Disclaimer**
> DPI Hunter is a network security and research tool. It is provided **for educational purposes only**, "as is", without any warranty. You alone are responsible for how you use it. Follow the laws of your country and the terms of your internet service provider.

---

## Features

- **16 bypass strategies** — TCP splitting, reordering, sequence overlap, and decoy ("fake") packets with several ways of making the server ignore them
- **AUTO mode** — tests reachability in the background and repairs itself when a site stops working
- **Per-domain strategy memory** — a blocked domain gets its own strategy; everything else keeps working as before
- **Block detection** — reacts to TCP resets and to silently dropped ClientHellos (retransmissions)
- **Large ClientHello support** — handles hellos that span two TCP segments (modern Chrome/Firefox)
- **DNS over HTTPS** — 12 built-in providers, automatic latency-based selection, custom server, no Windows DNS settings changed
- **QUIC handling** — drop (force TCP), decoy, or pass through
- **Game / voice mode** — decoy datagrams for UDP flows (configurable port ranges)
- **Blacklist and exclude lists** — touch only the domains you choose, or never touch specific ones
- **ANALYZE mode** — tries every strategy against a set of sites in parallel and saves the best one
- **Start with Windows** — optional scheduled task
- **English and Turkish UI**, IPv4 and IPv6

## Requirements

- Windows 10 or 11, x64
- Administrator rights (the tool asks for elevation by itself)
- [WinDivert 2.2](https://github.com/basil00/WinDivert/releases): `WinDivert.dll` and `WinDivert64.sys` in the same folder as the executable

## Quick start

1. Put `Dpi.Hunter.exe`, `WinDivert.dll` and `WinDivert64.sys` in one folder.
2. Run `Dpi.Hunter.exe` and accept the administrator prompt.
3. Read and accept the terms of use (first start only).
4. Choose **AUTO**.

If you are not sure which strategy fits your connection, run **ANALYZE** once. It saves the best result and AUTO starts with it next time.

## Modes

| Mode | What it does |
|---|---|
| **AUTO** | Starts with the last working strategy, tests periodically, learns per-domain strategies, falls back to Safe-Mode if nothing works |
| **MANUAL** | You pick one strategy; nothing is switched automatically |
| **ANALYZE** | Tests all strategies against up to 6 sites, activates and saves the best |
| **DNS TEST** | Measures all DoH providers and lets you choose one |
| **SETTINGS** | All options, saved the moment you change them |

## Dashboard

While running, the top panel shows the state, active strategy, uptime and counters. The middle area is a scrolling log.

| Key | Action |
|---|---|
| `S` | Switch to the next strategy by hand |
| `T` | Run a reachability test now (AUTO mode) |
| `M` / `Esc` | Stop and return to the menu |
| `Q` | Quit |

| Counter | Meaning |
|---|---|
| Packets | Packets inspected by the tool |
| Split | Hellos/requests sent in modified form |
| Fake | Decoy TCP packets sent |
| QUIC | QUIC packets dropped or preceded by a decoy |
| UDP | UDP flows that received decoys (game / voice mode) |
| DoH | Queries answered via DoH / queries that fell back to normal DNS |
| Signals | Resets or retransmissions that looked like blocking |
| Fixes | Domains that received their own strategy |

The bar graph shows inspected packets per second for the last 48 seconds, scaled to the busiest second in that window.

## Strategies

| Name | Technique |
|---|---|
| Split-2 | Split after the 2nd byte |
| Split-SNI | Split right before the hostname |
| Split-MidSNI | Split in the middle of the hostname |
| MultiSplit | Three cuts: byte 1, before and inside the hostname |
| Disorder | Split inside the hostname, second part sent first |
| MultiDisorder | Three cuts, all segments in reverse order |
| SeqOvl | Split, with junk bytes overlapping the sequence number |
| Delay-Split | Split with a short delay between parts |
| Fake-TTL | Decoy hello with a low TTL, then the real one |
| Fake-BadSum | Decoy hello with a broken TCP checksum |
| Fake-BadSeq | Decoy hello with a wrong SEQ/ACK |
| Fake-MD5 | Decoy hello carrying a TCP MD5 option |
| Fake+Split | Low-TTL decoy, then a split inside the hostname |
| Fake+Disorder | Low-TTL decoy, then a reversed split |
| FakedSplit | Decoy segments mixed between the real parts |
| Combo | TTL and MD5 decoys, then MultiSplit |
| Safe-Mode | Nothing is modified (entered automatically when nothing works) |

The decoy TTL is lowered automatically per server, based on the hop distance seen in the SYN-ACK, so decoys expire before they reach it.

## Files

All files live next to the executable.

| File | Purpose |
|---|---|
| `dpi_hunter.cfg` | Settings (created automatically) |
| `blacklist.txt` | Optional. Only these domains are modified. One domain per line; subdomains match. `listem.txt` and `list.txt` are accepted too |
| `exclude.txt` | Optional. These domains are never modified |
| `dpi_hunter.hosts` | Learned per-domain strategies. Safe to delete |
| `dpi_hunter.last` | Last working default strategy |
| `dpi_hunter.log` | Log file (rotated at 512 KB) |

Without a blacklist every site on the protected ports is handled. A preset `blacklist.txt` can be generated from the settings menu.

## Configuration

`dpi_hunter.cfg` keys:

| Key | Values | Default |
|---|---|---|
| `lang` | `en`, `tr` | system language |
| `dns_mode` | `fast` (blacklisted names only), `full` (all queries), `off` | `fast` |
| `doh` | `cloudflare`, `cloudflare2`, `google`, `google2`, `quad9`, `quad9b`, `adguard`, `adguard2`, `mullvad`, `dnssb`, `dnssb2`, `libredns`, `custom` | `cloudflare` |
| `doh_auto` | `on`, `off` — measure and pick the fastest at every start | `on` |
| `doh_custom` | IPv4 address of your own DoH server | — |
| `ports` | TCP ports to protect, comma separated (max 16) | `80,443,8080,8443,2053,2083,2087,2096` |
| `http` | `on`, `off` — HTTP Host header handling | `on` |
| `ttl` | Decoy TTL, 1–20 | `6` |
| `fake_repeats` | Decoys per packet, 1–10 | `2` |
| `quic` | `drop`, `fake`, `pass` | `drop` |
| `game` | `on`, `off` — game / voice mode | `on` |
| `udp_ports` | UDP port ranges for game / voice mode | `49152-65535,19294-19344` |
| `deep` | `on`, `off` — track hellos that continue in a second segment | `on` |
| `log` | `on`, `off` | `on` |
| `intro` | `on`, `off` — intro animation | `on` |

With `fast` DNS mode and no blacklist, all queries go through DoH.

## Command line

```
Dpi.Hunter.exe                      menu
Dpi.Hunter.exe --auto               start AUTO directly
Dpi.Hunter.exe --manual             start MANUAL directly
Dpi.Hunter.exe --analyze            start ANALYZE directly
Dpi.Hunter.exe --test               DoH latency test
Dpi.Hunter.exe --help               help screen
```

| Option | Meaning |
|---|---|
| `--strategy=NAME` | Use this strategy (implies `--manual`) |
| `--dns=fast\|full\|off`, `--no-dns` | DNS mode |
| `--doh=NAME`, `--doh-auto` | DoH provider |
| `--ttl=N` | Decoy TTL (1–20) |
| `--repeats=N` | Decoys per packet (1–10) |
| `--quic=drop\|fake\|pass`, `--keep-quic` | QUIC handling |
| `--game=on\|off`, `--no-game` | Game / voice mode |
| `--udp-ports=A-B,C-D` | UDP port ranges for game / voice mode |
| `--ports=443,80` | TCP ports to protect |
| `--http=on\|off`, `--no-http` | HTTP Host handling |
| `--log`, `--no-log` | Log file |
| `--no-intro` | Skip the intro animation |
| `--block-passive` | Drop injected RST packets with IP ID 0 or 1 |
| `--lang=en\|tr` | UI language |

Command line options apply to that run only; they are not written to the config file.

## How it works

A DPI device reads the hostname from the first packet of a connection: the SNI field of a TLS ClientHello or the Host header of an HTTP request. DPI Hunter intercepts that packet with WinDivert and sends it in a form the server still understands but a simple inspector does not:

- **Splitting** cuts the packet so that no single TCP segment contains the whole hostname.
- **Reordering** sends the pieces out of order; TCP on the server puts them back together.
- **Decoys** are extra packets with a harmless hostname that are built to be discarded on the way or by the server (low TTL, bad checksum, wrong sequence number, MD5 option).

DNS queries are answered through DNS over HTTPS so that a poisoned resolver cannot return a false address. QUIC is dropped by default, which makes browsers fall back to TCP where the techniques above apply.

In game / voice mode, the first three datagrams of each UDP flow in the configured port ranges are preceded by short-lived decoy datagrams. After that the flow is left alone.

## Building

The source is one file, `DpiHunter.cpp`. It is UTF-8 **with BOM** — keep it that way, otherwise the UI text and logo break.

**MSVC (x64 Native Tools prompt)**, with `windivert.h` and `WinDivert.lib` from the WinDivert SDK in the same folder:

```
cl /O2 /EHsc DpiHunter.cpp
```

**Cross-compiling with Zig** (any OS):

```
zig c++ -target x86_64-windows-gnu -std=c++14 -O2 -s DpiHunter.cpp WinDivert.dll ^
    -lws2_32 -lwinhttp -lshell32 -ladvapi32 -o Dpi.Hunter.exe
```

## Troubleshooting

| Symptom | Things to check |
|---|---|
| "WinDivert could not be opened" | Run as administrator; `WinDivert.dll` and `WinDivert64.sys` next to the exe; close other WinDivert-based tools; add the folder to your antivirus exclusions; Memory Integrity may block the driver |
| DNS self-test says "not intercepted" | A VPN, the browser's own secure DNS, or another DNS tool is handling queries |
| A site works in ANALYZE but not in the browser | Clear the browser's DNS cache or restart it; try `quic=drop` |
| Boxes instead of symbols | Use a console font with box-drawing characters (Consolas, Cascadia Mono) |
| Slow uploads | Set `deep=off` |
| Everything stops working | Press `S` to try another strategy, or run ANALYZE again |

## Limitations

- Effectiveness depends entirely on the ISP and its DPI equipment; no strategy works everywhere, and results can change over time.
- IP-level blocks cannot be bypassed by this kind of tool.
- QUIC is not decrypted, so its hostname is not inspected. With a blacklist, QUIC is only dropped for addresses learned from DoH answers.
- TLS record fragmentation is not implemented.
- DNS answers too large for UDP fall back to TCP port 53, which is not intercepted.
- Only one WinDivert-based bypass tool should run at a time.

## Credits

- [WinDivert](https://github.com/basil00/WinDivert) by basil00 — packet interception driver and library. WinDivert is distributed under its own license (LGPLv3 / GPLv2); include its license file if you redistribute the binaries.
- Techniques are based on publicly documented DPI circumvention research, as used by projects such as [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) and [zapret](https://github.com/bol-van/zapret).

## Feedback

Your feedback matters a lot. This tool can only be tuned with reports from real connections.

If you are in Turkey, or in any other country where sites are filtered, and something does not work — a site stays blocked, a game or voice chat will not connect, the tool shows an error — please reach out:

**Discord: `astegtam`**

A useful report includes:

- your country and internet provider
- what you tried to open (site, game, voice chat) and what happened, including any error code
- the mode and strategy shown on the dashboard
- the last lines of `dpi_hunter.log`

Reports that something *does* work on your provider are just as welcome.

## License

Released under the [MIT License](LICENSE).

WinDivert is a separate component with its own license (see Credits).

---

*Security tool — for educational purposes only.*
