<div align="center">

# 🍪 CIAhO
### Cookie Impact Analyzer – Hybrid Object

**Automatically analyse how a website's cookie consent choices affect your privacy.**  
Captures real network traffic, detects GDPR violations, browser fingerprinting, and ranks sites by privacy score — all from a clean GUI or the command line.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)]()

</div>

---

## ✨ Features

| Feature | Details |
|---|---|
| **Three-scenario comparison** | Accept all · Necessary only · Reject all |
| **HAR traffic capture** | Full network request log via browsermob-proxy |
| **GDPR violation detection** | 7 violation categories, risk-rated HIGH / MEDIUM / LOW |
| **Browser fingerprinting detection** | Domain-based + JS API heuristic scan |
| **CAPTCHA / bot-wall detection** | Cloudflare, reCAPTCHA, hCaptcha, Turnstile, etc. |
| **Batch analysis** | Analyse multiple URLs at once (comma-separated or `.txt` list) |
| **Privacy score & grade** | Numeric score 0–100 with A–F letter grade |
| **Session ranking** | Best / worst sites ranked across the current session |
| **30+ CMP platforms supported** | OneTrust, Cookiebot, Didomi, iubenda, Quantcast, and more |
| **CLI & GUI** | Full-featured Tkinter GUI with dark theme + headless CLI |
| **PDF + JSON reports** | Machine-readable JSON and printable PDF report card |

---

## 📸 Screenshots

> GUI — Catppuccin Mocha dark theme

| Analysis tabs | Ranking |
|---|---|
| |<img width="1236" height="581" alt="Zrzut ekranu z 2026-03-10 08-04-38" src="https://github.com/user-attachments/assets/5b34147b-0a3f-47f6-9617-0a923244ee8c" />

<img width="1157" height="581" alt="Zrz<img width="779" height="387" alt="Zrzut ekranu z 2026-03-10 08-06-41" src="https://github.com/user-attachments/assets/5c04d1f0-bbbd-46fd-8c0d-e8dc94685b27" />
ut ekranu z 2026-03-10 08-05-39" src="https://github.com/user-attachments/assets/242fb511-39c5-4d8e-9284-54443c25c055" />

---<img width="779" height="905" alt="Zrzut ekranu z 2026-03-10 08-07-44" src="https://github.com/user-attachments/assets/072aa1af-7154-4215-9bba-86615b09f10a" />


## 🏗️ How it works

```
                        ┌─────────────────────────────────────┐
                        │           Target website            │
                        └──────────────┬──────────────────────┘
                                       │
              ┌──────── browsermob-proxy (HAR capture) ────────┐
              │                        │                        │
         Accept all            Necessary only              Reject all
              │                        │                        │
              └──────────────── CIAhO engine ─────────────────┘
                                       │
                    ┌──────────────────┼──────────────────────┐
                    │                  │                       │
           GDPR analysis     Fingerprinting scan      Privacy score
                    │                  │                       │
                    └──────── JSON / PDF / GUI report ─────────┘
```

1. **browsermob-proxy** is started to intercept all HTTP/S requests.
2. For each of the three consent scenarios, a headless browser:
   - loads the page,
   - detects the cookie banner (5-stage strategy including Shadow DOM and iframe search),
   - clicks the appropriate button,
   - waits for traffic to settle,
   - captures HAR, cookies, and page HTML.
3. CIAhO compares all three captures and produces:
   - bar & pie charts (`.png`)
   - full JSON report (`analysis.json`)
   - GDPR violation report with evidence
   - browser fingerprinting risk assessment
   - numeric privacy score and letter grade

---

## 🚨 GDPR Violation Detection

CIAhO automatically assigns a compliance risk level based on what is observed in network traffic after each consent choice:

| Risk | GDPR Article | Violation |
|---|---|---|
| 🔴 **High** | Art. 6 & 7 | Tracking domains active **after rejecting** consent |
| 🔴 **High** | Art. 6 | Tracking cookies set **after rejecting** consent |
| 🔴 **High** | Art. 7(3) | No reject button (consent asymmetry) |
| 🟡 **Medium** | Art. 7 / ePrivacy | No consent banner despite active trackers |
| 🟡 **Medium** | Art. 6 | Trackers active on "necessary only" choice |
| 🟡 **Medium** | Art. 7 / ePrivacy | No "necessary only" option offered |
| 🟢 **Low** | Art. 5(1)(c) | Excessive trackers (data minimisation) |

> ⚠️ Results represent an automated technical analysis of network traffic, **not legal advice**. A full compliance assessment requires legal review.

---

## 🕵️ Browser Fingerprinting Detection

CIAhO cross-references captured domains against a curated list of known fingerprinting services (FingerprintJS, Hotjar, FullStory, Clarity, DataDome, PerimeterX, and others) and scans page HTML for fingerprinting JS API calls (`canvas.toDataURL`, `WebGLRenderingContext`, `AudioContext`, `navigator.plugins`, etc.).

Risk is rated **HIGH / MEDIUM / LOW / NONE** and shown in a dedicated tab in the GUI.

---

## 🗂️ Supported CMP Platforms

OneTrust · Cookiebot · Didomi · Quantcast Choice · Sourcepoint · iubenda · Klaro · CookieYes · Complianz · Axeptio · Google Funding Choices · Borlabs Cookie · Usercentrics · Termly · Civic Cookie Control · TrustArc · and many more (30+).

Detection uses **5 escalating strategies**:

| Step | Method |
|---|---|
| 1 | CSS selectors – known CMP IDs and classes |
| 2 | Shadow DOM pierce – Usercentrics, Google FC, etc. |
| 3 | Broad text-pattern scan (regex on visible element text) |
| 4 | Iframe search – Google Consent, TrustArc, Sourcepoint |
| 5 | Deep JS walk – visits every visible text node including shadow roots |

---

## 📦 Requirements

| Dependency | Minimum version |
|---|---|
| Python | 3.10+ |
| Java (JRE/JDK) | 8+ |
| Google Chrome / Chromium / Firefox / Edge | any current release |

> Java is required to run **browsermob-proxy**.

---

## ⚙️ Installation

```bash
# 1) Clone the repository
git clone https://github.com/sp0ko/ciaho.git
cd ciaho

# 2) Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3) Install Python dependencies
pip install -r requirements.txt
```

browsermob-proxy is bundled in the repository. Java must be available in your `PATH`.

> **Linux (Debian/Ubuntu):** if tkinter is missing, run `sudo apt install python3-tk`

---

## 🚀 Usage

### GUI (recommended)

```bash
python ciaho_gui.py
```

Enter one or more comma-separated URLs, or click 📂 to load a `.txt` list. Results appear across multiple tabs: **Charts · Privacy Score · Summary · Cookie Details · GDPR · Fingerprinting · Ranking · JSON**.

### CLI

```bash
# Single URL
python ciaho.py https://example.com

# Multiple URLs (comma-separated)
python ciaho.py https://example.com,https://another.com

# Load list from file
python ciaho.py --list sites.txt
```

A ranking table is printed to the terminal and saved as `ranking_TIMESTAMP.json` when more than one URL is analysed.

---

## 📁 Output Structure

```
output_example_com_20260309_123456/
├── analysis.json          # full JSON report
├── analysis_report.pdf    # PDF report card
├── comparison.png         # comparison bar chart
└── domain_categories.png  # domain category pie charts
```

### Key fields in `analysis.json`

```jsonc
{
  "url": "https://example.com",
  "score": 72,
  "grade": "C",
  "gdpr": {
    "overall_risk": "HIGH",
    "compliant": false,
    "violations": [
      {
        "severity": "HIGH",
        "article": "Art. 6 & 7 GDPR",
        "title": "Tracking domains active after rejecting consent",
        "evidence": ["tracker.example.net"]
      }
    ]
  },
  "fingerprinting": {
    "risk": "MEDIUM",
    "domains": ["fp.example.com"],
    "signals": ["canvas.toDataURL", "navigator.plugins"]
  }
}
```

---

## 🗃️ Project Structure

```
ciaho/
├── ciaho.py            # analysis engine + CLI entry point
├── ciaho_gui.py        # graphical interface (Tkinter, Catppuccin Mocha)
├── requirements.txt    # Python dependencies
├── setup.sh            # quick-start shell script
├── browsermob-proxy/   # bundled proxy binary
├── README.md           # documentation (EN)
└── README.pl.md        # documentation (PL)
```

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## ⚠️ Disclaimer

CIAhO is a **research and auditing tool**. It automates real browser sessions and captures live network traffic. Use it only on websites you own or have explicit permission to test. The authors are not responsible for any misuse.

GDPR and fingerprinting results are based on automated heuristics. They do **not** constitute legal advice.

---

## 📄 License

[MIT](LICENSE) — free to use, modify, and distribute.
