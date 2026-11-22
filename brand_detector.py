
# PunyGuard XDR
# Automated Brand Impersonation Detection

import json
import unicodedata
from pathlib import Path
from confusable_homoglyphs import confusables

WATCHLIST = Path(__file__).parent / "brands.json"

with WATCHLIST.open(encoding="utf-8") as file:
    BRANDS = json.load(file)


def normalize_domain(domain):
    normalized = ""

    for char in unicodedata.normalize("NFKC", domain.lower()):
        if char.isascii():
            normalized += char
            continue

        matches = confusables.confusables_data.get(char, [])

        replacement = char

        for match in matches:
            candidate = match["c"].lower()

            if candidate.isascii() and candidate.isalpha():
                replacement = candidate
                break

        normalized += replacement

    return normalized


def detect_brand(domain):
    for label in domain.lower().split("."):
        normalized = normalize_domain(label)

        if normalized != label and normalized in BRANDS:
            return normalized

    return None
