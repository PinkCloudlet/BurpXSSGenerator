# Burp XSS Cheatsheet Generator

A Burp Suite extension (Jython, classic `IBurpExtender` API) that generates XSS payloads for **Intruder**, based on the PortSwigger cheatsheet — with a unique marker, encoding variants, and support for loading a custom payload list.

## Features

- **Random marker instead of a static `alert(1)`** — each attack generates a unique 6-character marker (e.g. `alert(kqzmpv)`), making it easier to identify hits and helping bypass simple filters that block literal `alert(1)`.
- **Automatic encoding variants** — every base payload is expanded into plain, URL-encoded, and HTML-entity-encoded versions (each variant can be toggled independently).
- **Custom payload list loading** — a button in the panel lets you pick a `.txt` file with payloads (one per line, may include the `{MARK}` placeholder), no code editing required.
- **Context-aware injection** — optional appending of the payload to the original field value (`baseValue + payload`) instead of always overwriting it.
- **Configuration panel inside Burp** — a dedicated "XSS Gen" tab with checkboxes and the currently active list status.
- **Logging to the Output tab** — instead of `print()` to the console.

## Requirements

- Burp Suite (Community or Professional)
- [Jython standalone JAR](https://www.jython.org/download) configured in Burp (Extender → Options → Python Environment)

## Installation

1. Download [Jython standalone](https://www.jython.org/download) and point Burp Suite to the `.jar` file: `Extender → Options → Python Environment Location`.
2. In Burp, go to `Extender → Extensions → Add`.
3. Extension type: `Python`.
4. Select the `BurpXSSPayloadGenerator.py` file.
5. Click `Next` — the Output console should show a successful load message.

## Usage

1. Send a request to **Intruder** and mark an attack position (`§...§`).
2. In the `Payloads` tab, select the payload type: **Extension-generated**.
3. Click `Select generator...` and choose **PortSwigger XSS Cheatsheet Payloads**.
4. (Optional) Go to the **XSS Gen** tab in Burp's main bar to:
   - enable/disable the random marker,
   - enable/disable URL/HTML-encoded variants,
   - load a custom payload list from a file,
   - enable injection into the `baseValue` context.
5. Launch the attack.

## Custom payload file format

A plain text file, one payload per line. The `{MARK}` placeholder is replaced with the current marker (random or `1`, depending on settings):

```
<script>alert({MARK})</script>
<img src=x onerror=alert({MARK})>
"><svg onload=alert({MARK})>
```

## Base payload structure

The default list is grouped by injection context:

- HTML context (`<script>`, `<img>`, `<svg>`, `<iframe>`)
- attribute context (`" onfocus=... autofocus="`)
- JavaScript context (`;alert(...)//`, `'-alert(...)-'`)
- HTML5 polyglot/bypass (`<details ontoggle=...>`, `<math><mtext>...`)

## Limitations and notes

- The extension relies on Burp's classic API (Jython) — it is not compatible with the Montoya API without adaptation.
- The base list is a starting point, not a complete WAF-bypass set — extend it via custom payload files tailored to your target.
- This tool is intended solely for use in authorized penetration testing activities. The user is responsible for ensuring usage complies with applicable law and the agreed testing scope.

## License

MIT 
