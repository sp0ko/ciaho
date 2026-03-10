# 🍪 Cookie Impact Analyzer (CIAHO)

Narzędzie do analizy wpływu plików cookie na ruch sieciowy strony internetowej
oraz do **automatycznego wykrywania potencjalnych naruszeń RODO / GDPR**.

Porównuje trzy scenariusze: **akceptacja wszystkich**, **tylko niezbędne** i **odrzucenie** ciasteczek –
zbierając dane HAR, ciasteczka przeglądarki oraz kod HTML strony.

---

## Wymagania

| Zależność | Wersja minimalna |
|-----------|-----------------|
| Python | 3.10+ |
| Java (JRE/JDK) | 8+ |
| Google Chrome / Chromium / Firefox / Edge | dowolna aktualna |

> Java jest wymagana do uruchomienia **browsermob-proxy**.

---

## Instalacja

```bash
# 1) Sklonuj lub pobierz repozytorium
git clone https://github.com/twoje-konto/ciaho.git
cd ciaho

# 2) Utwórz i aktywuj środowisko wirtualne
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 3) Zainstaluj zależności
pip install -r requirements.txt
```

Program automatycznie pobierze **browsermob-proxy** przy pierwszym uruchomieniu,
jeśli nie zostanie wykryte w katalogu `browsermob-proxy/`.

---

## Uruchomienie

### Wersja terminalowa

```bash
python ciaho.py https://example.com
```

### Wersja GUI

```bash
python ciaho_gui.py
```

---

## Jak to działa?

1. Program uruchamia **browsermob-proxy** (przechwytuje ruch HTTP jako HAR).
2. Dla każdego z trzech scenariuszy otwiera przeglądarkę w trybie headless:
   - ładuje stronę,
   - wykrywa baner zgody na pliki cookie (obsługa 30+ platform CMP),
   - klika odpowiedni przycisk (Akceptuj / Tylko niezbędne / Odrzuć),
   - czeka na ustabilizowanie się ruchu sieciowego,
   - zapisuje HAR, ciasteczka i kod HTML.
3. Porównuje wyniki między scenariuszami i generuje:
   - wykresy słupkowe i kołowe (`.png`),
   - raport JSON z pełnymi danymi,
   - **raport naruszeń RODO** (ocena ryzyka + lista dowodów),
   - podsumowanie tekstowe w terminalu / w GUI.

---

## Wykrywanie naruszeń RODO / GDPR

Po zakończeniu analizy CIAHO automatycznie ocenia zgodność serwisu z RODO
i przypisuje poziom ryzyka: 🔴 Wysokie / 🟡 Średnie / 🟢 Niskie / ✅ Brak.

| Poziom | Artykuł RODO | Naruszenie |
|--------|-------------|------------|
| 🔴 Wysokie | Art. 6 & 7 | Domeny śledzące aktywne **po odrzuceniu** zgody |
| 🔴 Wysokie | Art. 6 | Śledzące ciasteczka ustawiane po odrzuceniu |
| 🔴 Wysokie | Art. 7 ust. 3 | Brak przycisku odrzucenia (asymetria zgody) |
| 🟡 Średnie | Art. 7 / ePrivacy | Brak baneru przy aktywnych trackerach |
| 🟡 Średnie | Art. 6 | Trackery aktywne przy wyborze „tylko niezbędne" |
| 🟡 Średnie | Art. 7 / ePrivacy | Brak opcji „tylko niezbędne ciasteczka" |
| 🟢 Niskie | Art. 5 ust. 1 lit. c | Nadmierna liczba domen śledzących (minimalizacja danych) |

Wyniki trafiają do pola `gdpr` w pliku `analysis.json` oraz do zakładki
**🔴 RODO / GDPR** w interfejsie graficznym.

> ⚠ Wyniki to analiza techniczna ruchu sieciowego, nie porada prawna.
> Dokładna ocena wymaga analizy prawnej uwzględniającej całą politykę prywatności.

---

## Strategia wykrywania baneru zgody

Przyciski zgody są wyszukiwane 5 eskalującymi metodami:

| Krok | Metoda |
|------|--------|
| 1 | Selektory CSS – znane ID i klasy platform CMP |
| 2 | Przebijanie shadow DOM (Usercentrics, Google FC itp.) |
| 3 | Skanowanie tekstu (wyrażenia regularne na widocznych elementach) |
| 4 | Przeszukiwanie iframe (Google consent, TrustArc, Sourcepoint itp.) |
| 5 | Głęboki spacer JS – odwiedza każdy węzeł tekstowy w dokumencie |

**Obsługiwane platformy CMP:** OneTrust · Cookiebot · Didomi · Quantcast Choice ·
Sourcepoint · iubenda · Klaro · CookieYes · Complianz · Axeptio ·
Google Funding Choices · Borlabs Cookie · TechLab · Usercentrics ·
Termly · Civic Cookie Control · i wiele innych.

---

## Struktura plików wynikowych

```
output_example_com_20260309_123456/
├── analysis.json          # pełny raport JSON (zawiera sekcję "gdpr")
├── comparison.png         # wykres porównawczy (słupkowy)
└── domain_categories.png  # wykresy kołowe kategorii domen
```

### Kluczowe pola w `analysis.json`

```jsonc
{
  "gdpr": {
    "overall_risk": "HIGH",          // poziom ryzyka: HIGH/MEDIUM/LOW/NONE
    "compliant": false,
    "severity_counts": { "HIGH": 1, "MEDIUM": 1, "LOW": 1 },
    "violations": [
      {
        "severity": "HIGH",
        "article": "Art. 6 & 7 RODO",
        "title": "Śledzące domeny aktywne po odrzuceniu zgody",
        "description": "...",
        "evidence": ["raspl.tagger.opecloud.com"]
      }
    ]
  }
}
```

---

## Struktura projektu

```
ciaho/
├── ciaho.py          # silnik analizy + CLI
├── ciaho_gui.py      # interfejs graficzny (Tkinter)
├── requirements.txt  # zależności Python
├── README.md         # dokumentacja (PL)
└── README.en.md      # dokumentacja (EN)
```

---

## Licencja

MIT License – używaj i modyfikuj swobodnie.
