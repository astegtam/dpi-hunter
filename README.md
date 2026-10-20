#  DPI Hunter v5.1

###  An Open-Source DPI Circumvention Tool for Windows

**DPI Hunter** is a Windows-based network utility written in C++ that explores different techniques for handling Deep Packet Inspection (DPI), SNI filtering, and DNS-based restrictions.

Built with **MSVC (x64)** and the **WinDivert 2.2 API**, DPI Hunter combines multiple traffic-handling strategies, encrypted DNS, and automated strategy testing in a single tool.

The project is intended for technical experimentation, network research, and educational purposes, particularly in environments where internet access is restricted or certain services are difficult to reach.


##  Features

###  Multiple DPI Circumvention Strategies

DPI Hunter includes **16+ strategy variations** designed to experiment with different approaches to DPI interference and traffic filtering.

Examples include:

- **SNI Fragmentation** — Splits relevant TLS handshake data into smaller segments.
- **Fake Packet** — Uses specially constructed packets to test DPI filtering behavior.
- **HostFakeSplit** — Applies host-header manipulation and splitting techniques.
- **SeqOvl** — Experiments with TCP sequence overlap behavior.
- **Additional strategies** — Multiple other variations intended for different filtering behaviors and network configurations.

Different networks may respond differently to each strategy. No individual strategy is guaranteed to work everywhere.

###  Automatic Strategy Selection & Recovery

DPI Hunter includes an automated recovery mechanism designed to reduce the need for manual configuration.

Depending on the implementation and network conditions, it can:

- Detect connectivity problems or signs of filtering.
- Test available strategies.
- Evaluate whether connectivity improves.
- Select a strategy that appears to work better.
- Attempt recovery when the current configuration stops working.

**Important:** Automatic detection is not infallible. A failed connection may have causes unrelated to DPI, and a strategy that works today may stop working after network or ISP changes.

###  Encrypted DNS over HTTPS (DoH)

DPI Hunter integrates **DNS over HTTPS (DoH)** to help protect DNS queries from conventional DNS-based interference.

Features include:

- 12 configured DoH providers.
- Automatic response-time measurements.
- Selection of the fastest measured provider.
- Encrypted DNS queries over HTTPS.

The fastest provider may vary depending on location, routing, congestion, and provider availability. DoH alone does not guarantee access to every blocked domain or service.

###  IPv4 & IPv6 Support

The project is designed to support both major IP protocol versions:

- IPv4
- IPv6

Actual behavior depends on the active network, the selected strategy, and the relevant system configuration.

###  QUIC Handling

DPI Hunter includes an option to block **QUIC traffic over UDP port 443**.

This is intended to encourage compatible browsers and services to fall back to TCP-based HTTPS connections using TLS.

Fallback behavior depends on the browser, server, network, and application. Blocking QUIC may affect connectivity or performance for some services.

###  User Interface & Logging

DPI Hunter provides a menu-driven interface designed to make its main functions accessible without requiring users to manually configure every parameter.

It also includes detailed logging to help with troubleshooting, strategy evaluation, and reporting problems.

---

##  Technical Details

| Component | Details |
|---|---|
| Project | DPI Hunter v5.1 |
| Language | C++ |
| Compiler | Microsoft Visual C++ (MSVC) |
| Target architecture | Windows x64 |
| Packet handling | WinDivert 2.2 API |
| DNS encryption | DNS over HTTPS (DoH) |
| IP protocols | IPv4 and IPv6 |
| Strategy engine | 16+ DPI strategy variations |
| Interface | Menu-driven console interface |
| Logging | Detailed diagnostic logs |

---

##  Installation

### 1. Download the application

Download the appropriate DPI Hunter release from the project's GitHub Releases page and extract the archive into a dedicated folder.

If you compile the project yourself, use the build instructions and dependencies provided in the source code.

### 2. Verify the required files

Make sure the following files are present in the **same directory as the DPI Hunter executable**:

```text
DPI-Hunter/
├── DPI-Hunter.exe
├── WinDivert.dll
└── WinDivert64.sys
```

The executable and filenames above are illustrative. Use the actual filenames supplied by your release.

**Do not download driver files from untrusted third-party websites.** Obtain WinDivert components from a trustworthy source and make sure their versions are compatible with the application.

### 3. Run as Administrator

DPI Hunter uses WinDivert for network packet handling. This requires elevated privileges.

1. Right-click the executable.
2. Select **Run as administrator**.
3. Approve the Windows User Account Control prompt if you trust the executable.
4. Follow the on-screen menu.

Without the necessary permissions, the driver may fail to load or packet handling may not work correctly.

### 4. Windows Memory Integrity

Depending on the Windows configuration and the driver build, **Memory Integrity** may prevent the WinDivert driver from loading.

You can check its status here:

```text
Windows Security
  → Device security
    → Core isolation
      → Memory integrity
```

If Memory Integrity is blocking a compatible driver, you may need a properly signed, compatible driver or a different supported configuration.

Disabling Memory Integrity can reduce protection against certain kernel-level threats. **Do not turn off a Windows security feature simply to run an unfamiliar executable.** If you decide to disable it after understanding the risks, restart Windows and verify that the driver is compatible and trusted. Keeping Windows and its drivers updated is recommended.

---

##  Usage Guide

On startup, DPI Hunter presents a menu with several operating modes.

| Mode | Purpose |
|---|---|
| `AUTO` | Automatically tests available strategies and attempts to select a suitable configuration. |
| `MANUAL` | Allows you to select or configure a strategy yourself. |
| `TEST` | Runs strategy or connectivity tests to help compare results. |
| `ANALYZE` | Provides diagnostic information to assist with understanding network behavior. |

The exact options available may depend on the release and current implementation.

### Recommended workflow

1. Start the application as Administrator.
2. Review the startup messages and check that the required driver has loaded.
3. Begin with `AUTO` if you are unsure which strategy to try.
4. Use `TEST` to investigate whether a selected configuration improves connectivity.
5. Use `MANUAL` if you want to compare strategies yourself.
6. Use `ANALYZE` and the application logs when troubleshooting.
7. If the connection becomes worse or unstable, stop the test and restore your previous network configuration.

**Please remember:** A successful test on one connection does not guarantee that the same configuration will work on another ISP, device, or network.

---

##  Antivirus Warnings & False Positives

Applications that intercept network traffic or load packet-filtering drivers may be flagged by security products.

Depending on the binary, driver, signing status, and behavior, products such as Windows Defender or Kaspersky may classify components as `HackTool`, `RiskTool`, or another potentially unwanted category.

This can be a false positive, but **a detection should never automatically be assumed to be harmless**.

Before running DPI Hunter:

- Download it only from a source you trust.
- Review the source code and release contents.
- Verify file hashes or digital signatures when available.
- Investigate any antivirus detection rather than ignoring it blindly.
- If you have verified the files and understand the risk, consult your security product's documentation about an appropriately scoped exception.

Avoid disabling antivirus protection globally or adding broad exclusions that could expose unrelated files.

The project author cannot guarantee that every release, dependency, or third-party build will be free of security detections.

---

##  Disclaimer & Limitation of Liability

DPI Hunter is provided **for educational, research, and network troubleshooting purposes**. Its purpose is to explore and evaluate techniques for handling DPI-related interference and network restrictions.

By using this software, you acknowledge the following:

- **Use at your own risk.** You are responsible for deciding whether the software is appropriate for your device, network, and circumstances.
- **No stability guarantee.** The software is provided on an *"AS IS"* and *"AS AVAILABLE"* basis, without guarantees of uninterrupted operation, compatibility, effectiveness, or fitness for a particular purpose.
- **No guarantee of circumvention.** No strategy is guaranteed to bypass a particular ISP's filtering system or remain effective over time.
- **No warranty against damage.** Network interruptions, configuration conflicts, driver problems, system instability, or other unexpected effects may occur.
- **Legal compliance is your responsibility.** Laws and regulations governing internet access, network traffic interception, and circumvention tools differ between jurisdictions. You are responsible for understanding and complying with the rules applicable to your use.
- **No promise of anonymity.** DPI Hunter is not an anonymity tool and does not guarantee privacy, security, or protection against monitoring.
- **Limited liability.** To the extent permitted by applicable law, the author disclaims liability for losses, damages, service interruptions, or other consequences arising from the use or inability to use the software.

Nothing in this disclaimer excludes or limits any liability that cannot legally be excluded or limited under applicable law. This section is a statement of intent and is not a guarantee that the author is exempt from every legal claim.

If you do not understand the risks or are not comfortable with the required permissions and driver behavior, do not run the application.

---

##  Testing & Feedback

Network filtering systems differ between countries, ISPs, connection types, and even individual access points. As a result, meaningful feedback from different environments is especially valuable.

When reporting a problem, please include as much non-sensitive information as you can:

- Windows version and system architecture.
- ISP and country, if you are comfortable sharing them.
- Whether you are using IPv4, IPv6, or both.
- The operating mode and strategy involved.
- Relevant application log excerpts.
- What you expected to happen and what actually happened.

Please **remove personal information, public IP addresses, credentials, access tokens, and other sensitive data** before sharing logs.

Reports about failed connections are useful too. Knowing where a strategy does not work can be just as valuable as knowing where it does.

---

##  Contributing

Contributions from the open-source community are welcome.

Ways to help include:

- Reporting reproducible bugs.
- Sharing network compatibility results.
- Suggesting improvements to the interface and logging.
- Improving documentation.
- Reviewing code and suggesting fixes.
- Helping identify platform-specific issues.

When possible, provide clear reproduction steps and distinguish observed results from assumptions. This makes it much easier to investigate issues and improve the project responsibly.

Please check the repository's contribution guidelines, if available, before submitting a pull request.

---

##  Project Status

DPI Hunter is an actively testable network utility, and its effectiveness may vary across systems and network environments.

The presence of an automated recovery mechanism, multiple strategies, and encrypted DNS does **not** mean that every feature will work reliably in every situation.

Your testing and feedback can help identify bugs, uncover compatibility problems, and guide future development.

---

##  License

See the repository's `LICENSE` file for the applicable license terms.

If you are publishing this project as open source, make sure the chosen license is included in the repository. The absence of a license file should not be interpreted as permission to use, modify, or redistribute the code under an assumed license.

---

##  Community & Feedback — Get in Touch!

**I would genuinely love to hear from you.**

Especially if you live in **Türkiye, Iran, Russia, or another country where internet access is restricted**, and you have tried DPI Hunter on your own network, please consider reaching out.

Did it work for you? Did it fail? Did you discover a strange behavior, an ISP-specific issue, or a bug that I could investigate?

**Every honest report is valuable.** You do not need to be an expert developer to contribute. A clear description of what happened on your network can make a real difference.

The possibility that someone from a completely different part of the world tries this project and shares their experience is one of the things that makes open source special. **That kind of feedback would genuinely make me incredibly happy.**

###  Found a bug? Want to share your results? Have an idea?

# **📩 Discord: `astegtam`**

**Don't hesitate to reach out.** Whether you want to report a bug, suggest a feature, discuss compatibility, or simply tell me about your experience using DPI Hunter, you're welcome to get in touch.

Let's learn from each other's experiences and make the project better, together. 
