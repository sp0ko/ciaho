<div align="center">

# 🍪 CIAhO
### Cookie Impact Analyzer – Hybrid Object

**Automatyczna analiza wpływu wyboru zgody na pliki cookie na Twoją prywatność.**  
Przechwytuje rzeczywisty ruch sieciowy, wykrywa naruszenia RODO, fingerprintowanie przeglądarki i ocenia strony punktowo — z poziomu GUI lub wiersza poleceń.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)]()

</div>

---

## ✨ Funkcje

| Funkcja | Opis |
|---|---|
| **Porównanie trzech scenariuszy** | Akceptuj wszystkie · Tylko niezbędne · Odrzuć |
| **Przechwytywanie ruchu HAR** | Pełny dziennik żądań HTTP/S przez browsermob-proxy (QUIC/HTTP2 wyłączone dla kompletnego przechwycenia) |
| **Wykrywanie naruszeń RODO** | 12 kategorii naruszeń, ocena ryzyka: WYSOKIE / ŚREDNIE / NISKIE |
| **Skan localStorage / sessionStorage** | Migawki przed i po zgodzie, oznacza klucze śledzące zapisane po odrzuceniu |
| **Audyt atrybutów ciasteczek** | HttpOnly, Secure, SameSite=None, czas życia > 13 miesięcy (wytyczne EROD) |
| **Przeciwdziałanie lazy loading** | Symulacja przewijania (350 px) + ruch myszy — wyzwala zasoby gated przez IntersectionObserver |
| **Crawlowanie podstron** | Wybierana głębokość 1–5: odwiedza wewnętrzne podstrony w tej samej sesji HAR |
| **Obsługa drugiej warstwy zgody** | Automatyczne wyłączanie wszystkich przełączników w granularnych panelach zgody |
| **Wykrywanie fingerprintowania** | Domeny + heurystyczny skan wywołań JS API |
| **Wykrywanie CAPTCHA / bot-wall** | Cloudflare, reCAPTCHA, hCaptcha, Turnstile itp. |
| **Analiza wsadowa** | Wiele URL naraz (po przecinku lub plik `.txt`) |
| **Wynik i ocena prywatności** | Wynik 0–100 z oceną literową A–F |
| **Ranking sesji** | Najlepsze / najgorsze strony w bieżącej sesji |
| **30+ platform CMP** | OneTrust, Cookiebot, Didomi, iubenda, Quantcast i inne |
| **CLI i GUI** | Pełne GUI Tkinter (ciemny motyw Catppuccin Mocha) + tryb headless CLI |
| **Raporty PDF + JSON** | Maszynowo czytelny JSON i drukowalny raport PDF |

---

## 📸 Zrzuty ekranu

> GUI — ciemny motyw Catppuccin Mocha

<div align="center">

**Okno główne — wprowadzanie URL, wybór przeglądarki i głębokości crawlowania**

<img width="1236" alt="Okno główne CIAhO" src="https://github.com/user-attachments/assets/5b34147b-0a3f-47f6-9617-0a923244ee8c" />

</div>

<br>

| Wyniki — Wykresy i ocena prywatności | Zakładka naruszeń RODO |
|:---:|:---:|
| <img width="779" alt="Wykresy i ocena prywatności" src="https://github.com/user-attachments/assets/5c04d1f0-bbbd-46fd-8c0d-e8dc94685b27" /> | <img width="779" alt="Szczegóły naruszeń RODO" src="https://github.com/user-attachments/assets/072aa1af-7154-4215-9bba-86615b09f10a" /> |

---

## 🏗️ Jak to działa?

```
                        ┌─────────────────────────────────────┐
                        │           Docelowa strona            │
                        └──────────────┬──────────────────────┘
                                       │
              ┌──────── browsermob-proxy (przechwytywanie HAR) ──────┐
              │                        │                              │
       Akceptuj wszystkie       Tylko niezbędne               Odrzuć
              │                        │                              │
              └──────────────── silnik CIAhO ────────────────────────┘
                                       │
                    ┌──────────────────┼──────────────────────┐
                    │                  │                       │
           Analiza RODO     Skan fingerprintowania     Wynik prywatności
                    │                  │                       │
                    └──────── Raport JSON / PDF / GUI ─────────┘
```

1. **browsermob-proxy** jest uruchamiany do przechwytywania całego ruchu HTTP/1.1 (QUIC/HTTP3 i HTTP/2 są wyłączone w przeglądarce, aby żadne domeny śledzące nie ominęły przechwytywania).
2. Dla każdego z trzech scenariuszy zgody przeglądarka headless:
   - ładuje stronę,
   - symuluje przewijanie (350 px) i ruch myszy, aby wyzwolić zasoby z lazy loading,
   - opcjonalnie crawluje wewnętrzne podstrony (głębokość 1–5),
   - wykrywa baner zgody (5-etapowa strategia, w tym Shadow DOM i iframe),
   - wyłącza wszystkie przełączniki w panelach drugiej warstwy zgody,
   - klika odpowiedni przycisk,
   - czeka na ustabilizowanie się ruchu,
   - zapisuje HAR, ciasteczka, migawki localStorage/sessionStorage i HTML strony.
3. CIAhO porównuje trzy przechwycenia i generuje:
   - wykresy słupkowe i kołowe (`.png`)
   - pełny raport JSON (`analysis.json`)
   - raport naruszeń RODO z dowodami
   - ocenę ryzyka fingerprintowania
   - numeryczny wynik prywatności i ocenę literową

---

## 🚨 Wykrywanie naruszeń RODO

CIAhO automatycznie przypisuje poziom ryzyka na podstawie ruchu sieciowego, ciasteczek i pamięci przeglądarki po każdym wyborze zgody:

| Ryzyko | Artykuł RODO | Naruszenie |
|---|---|---|
| 🔴 **Wysokie** | Art. 6 & 7 | Domeny śledzące aktywne **po odrzuceniu** zgody |
| 🔴 **Wysokie** | Art. 6 | Śledzące ciasteczka ustawione **po odrzuceniu** |
| 🔴 **Wysokie** | Art. 5 ust. 1 lit. b | Klucze śledzące w **localStorage po odrzuceniu** |
| 🔴 **Wysokie** | Art. 32 | **SameSite=None bez Secure** na śledzącym ciasteczku |
| 🔴 **Wysokie** | Art. 7 ust. 3 | Brak przycisku odrzucenia (asymetria zgody) |
| 🟡 **Średnie** | Art. 7 / ePrivacy | Brak baneru przy aktywnych trackerach |
| 🟡 **Średnie** | Art. 6 | Trackery aktywne przy „tylko niezbędne" |
| 🟡 **Średnie** | Art. 7 / ePrivacy | Brak opcji „tylko niezbędne" |
| 🟡 **Średnie** | Art. 32 | Brak **HttpOnly / Secure** na śledzącym ciasteczku |
| 🟢 **Niskie** | Art. 5 ust. 1 lit. c | Nadmierna liczba trackerów (minimalizacja danych) |
| 🟢 **Niskie** | Art. 5 ust. 1 lit. e | Śledzące ciasteczko ważne **> 13 miesięcy** (EROD) |

> ⚠️ Wyniki to automatyczna analiza techniczna, **nie porada prawna**. Pełna ocena wymaga analizy prawnej.

---

## 🕵️ Wykrywanie fingerprintowania przeglądarki

CIAhO sprawdza przechwycone domeny względem listy znanych serwisów fingerprintowania (FingerprintJS, Hotjar, FullStory, Clarity, DataDome, PerimeterX i inne) oraz skanuje HTML pod kątem wywołań JS API fingerprintowania (`canvas.toDataURL`, `WebGLRenderingContext`, `AudioContext`, `navigator.plugins` itp.).

Ryzyko: **WYSOKIE / ŚREDNIE / NISKIE / BRAK** — widoczne w dedykowanej zakładce GUI.

---

## 🗂️ Obsługiwane platformy CMP

OneTrust · Cookiebot · Didomi · Quantcast Choice · Sourcepoint · iubenda · Klaro · CookieYes · Complianz · Axeptio · Google Funding Choices · Borlabs Cookie · Usercentrics · Termly · Civic Cookie Control · TrustArc · i wiele innych (30+).

Wykrywanie używa **5 eskalujących strategii**:

| Krok | Metoda |
|---|---|
| 1 | Selektory CSS — znane ID i klasy platform CMP |
| 2 | Przebijanie Shadow DOM — Usercentrics, Google FC itp. |
| 3 | Skanowanie wzorców tekstowych (regex na widocznych elementach) |
| 4 | Przeszukiwanie iframe — Google Consent, TrustArc, Sourcepoint |
| 5 | Głęboki spacer JS — odwiedza każdy węzeł tekstowy, w tym shadow roots |

Po wykryciu baneru, wszystkie granularne **przełączniki i checkboxy** w panelach drugiej warstwy są automatycznie wyłączane przed kliknięciem „Odrzuć".

---

## 📦 Wymagania

| Zależność | Wersja minimalna |
|---|---|
| Python | 3.10+ |
| Java (JRE/JDK) | 8+ |
| Google Chrome / Chromium / Firefox / Edge | dowolna aktualna |

> Java jest wymagana do uruchomienia **browsermob-proxy**.

---

## ⚙️ Instalacja

```bash
# 1) Sklonuj repozytorium
git clone https://github.com/sp0ko/ciaho.git
cd ciaho

# 2) Utwórz i aktywuj środowisko wirtualne
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3) Zainstaluj zależności Python
pip install -r requirements.txt
```

browsermob-proxy jest dołączony do repozytorium. Java musi być dostępna w `PATH`.

> **Linux (Debian/Ubuntu):** jeśli brakuje tkinter — `sudo apt install python3-tk`

---

## 🚀 Użycie

### GUI (zalecane)

```bash
python ciaho_gui.py
```

Wpisz jeden lub więcej URL oddzielonych przecinkami, lub kliknij 📂 aby wczytać plik `.txt`. Wybierz przeglądarkę i głębokość, a następnie uruchom skan. Wyniki wyświetlają się w zakładkach: **Wykresy · Ocena prywatności · Podsumowanie · Szczegóły ciasteczek · RODO · Fingerprintowanie · Ranking · JSON**.

**Legenda głębokości crawlowania:**

| Głębokość | Zakres |
|---|---|
| 1 | Tylko strona główna |
| 2 | Strona główna + 1 wewnętrzna podstrona |
| 3 | Strona główna + 2 podstrony |
| 4 | Strona główna + 3 podstrony |
| 5 | Strona główna + 4 podstrony |

### CLI

```bash
# Jeden URL
python ciaho.py https://example.com

# Wiele URL (po przecinku)
python ciaho.py https://example.com,https://another.com

# Wczytaj listę z pliku
python ciaho.py --list sites.txt

# Ustaw głębokość crawlowania (domyślnie: 1)
python ciaho.py https://example.com --crawl-depth 3
```

---

## 📁 Struktura plików wynikowych

```
output_example_com_20260309_123456/
├── analysis.json             # pełny raport JSON
├── analysis_report.pdf       # karta raportu PDF
├── comparison.png            # wykres porównawczy (słupkowy)
├── domain_categories.png     # wykresy kołowe kategorii domen
├── screenshot_accept.png     # zrzut strony po Akceptuj
├── screenshot_reject.png     # zrzut strony po Odrzuć
└── screenshot_necessary.png  # zrzut strony po Tylko niezbędne
```

### Kluczowe pola w `analysis.json`

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
        "article": "Art. 6 & 7 RODO",
        "title": "Domeny śledzące aktywne po odrzuceniu zgody",
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

## 🗃️ Struktura projektu

```
ciaho/
├── ciaho.py            # silnik analizy + punkt wejścia CLI
├── ciaho_gui.py        # interfejs graficzny (Tkinter, Catppuccin Mocha)
├── requirements.txt    # zależności Python
├── setup.sh            # skrypt szybkiego startu
├── browsermob-proxy/   # dołączone proxy
├── README.md           # dokumentacja (EN)
└── README.pl.md        # dokumentacja (PL)
```

---

## ⚠️ Zastrzeżenie

CIAhO jest **narzędziem badawczym i audytowym**. Automatyzuje rzeczywiste sesje przeglądarki i przechwytuje ruch sieciowy na żywo. Używaj go tylko na stronach, które posiadasz lub masz wyraźne pozwolenie na testowanie.

Wyniki dotyczące RODO i fingerprintowania opierają się na automatycznych heurystykach. **Nie stanowią porady prawnej.**

---

## 📄 Licencja

[MIT](LICENSE) — wolne do użytku, modyfikacji i dystrybucji.
