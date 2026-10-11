# DPI Hunter

**An adaptive DPI circumvention tool for Windows.**

DPI Hunter is a lightweight Windows utility designed to help users maintain access to websites and online services affected by Deep Packet Inspection (DPI) filtering.

It automatically tests different traffic-handling strategies, selects a suitable one for your network, and adapts when connection problems occur. The goal is to make the process as simple as possible, without requiring users to configure everything manually.

## Features

- **Automatic Strategy Detection** — Tests multiple traffic-handling strategies and selects one that works best in your network environment.
- **Adaptive Switching** — Re-evaluates strategies when connection issues are detected.
- **TLS SNI Fragmentation** — Splits TLS handshake data to help bypass certain types of DPI filtering.
- **Fake Packet Injection** — Uses decoy packets with modified TTL or sequence information to interfere with some DPI inspection methods.
- **QUIC Blocking** — Blocks QUIC traffic on UDP port 443, allowing compatible applications to fall back to TCP-based connections.
- **Domain Blacklist** — Applies circumvention selectively to specified domains.
- **Live Statistics** — Displays packet activity, fragmentation, blocked QUIC traffic, detected resets, and the active strategy.
- **Bilingual Interface** — Supports English and Turkish.
- **Simple Configuration** — Remembers your language preference and requires minimal manual setup.

## How to Use

### 1. Download and Start

Download the latest release from the [GitHub Releases](https://github.com/astegtam/dpi-hunter/releases) page, if a release is available.

Extract the downloaded files and follow the included instructions. DPI Hunter requires Windows x64, administrator privileges, and the required WinDivert files.

Run `Dpi Hunter.exe` as administrator.

### 2. Select Your Language

On the first launch, select your preferred language:

- `1` — Turkish
- `2` — English

Your selection is saved automatically.

You can also launch the program with a language argument:

- `--lang=tr` — Turkish
- `--lang=en` — English

### 3. Let It Find a Suitable Strategy

DPI Hunter automatically tests supported strategies against HTTPS endpoints and selects a suitable strategy for your network.

Keep the program running while browsing. It must remain active for its traffic-handling features to work.

### 4. Configure Specific Domains (Optional)

Create a file named `blacklist.txt` in the same directory as the executable.

Add one domain per line:

```text
# Example domains
youtube.com
discord.com
twitter.com
roblox.com
```

Lines beginning with `#` are ignored.

When a blacklist is present, the program is intended to apply its circumvention techniques only to matching domains. Without a blacklist, it attempts to process all supported TLS traffic.

**Note:** Domain matching and traffic handling depend on the implementation. Subdomains and applications using different connection methods may not behave as expected.

### 5. Monitor Activity

DPI Hunter displays live statistics in its console, including processed packets, fragmented packets, injected decoys, blocked QUIC traffic, detected resets, and the currently active strategy.

If a strategy does not work on your network, restart the program to trigger a new round of testing.

To stop DPI Hunter, use `Ctrl+C` in its console or close the process.

## Important Notes

- DPI Hunter supports IPv4 traffic only.
- QUIC is blocked by default, which may affect applications that rely on HTTP/3.
- Some websites or applications may not work correctly with every strategy.
- DPI circumvention is not guaranteed. Results depend on your ISP, network configuration, and filtering methods.
- Administrator privileges are required because the program uses the WinDivert network driver.

## Security and Privacy

DPI Hunter was developed for **personal privacy protection, security research, and educational purposes**.

Its purpose is to help users deal with restrictive network filtering on their own devices and connections. It is not intended to attack, exploit, or damage other systems.

The project is open source, allowing users to inspect the code and understand how traffic is handled. However, users should review the source code and verify the integrity of downloaded files before running the program, especially because it requires administrator privileges and uses a kernel-mode driver.

Use DPI Hunter only on devices and networks you are authorized to use, and comply with applicable laws and network policies.

**Use at your own risk.** The software is provided without warranties. The author is not responsible for misuse, service disruptions, data loss, or other consequences resulting from its use.

## Contributing

Suggestions, bug reports, improvements, and pull requests are welcome.

If you have ideas for new strategies, better compatibility, performance improvements, or other useful features, contributions are appreciated.

Feel free to open an issue or submit a pull request on GitHub. If you would like to help improve DPI Hunter, your feedback and contributions are welcome.

## Contact

**Author:** [@astegtam](https://github.com/astegtam)

For questions, bug reports, feature requests, or general feedback, feel free to contact **astegtam on Discord**.

## License

This project is released under the MIT License. See the `LICENSE` file for details.
