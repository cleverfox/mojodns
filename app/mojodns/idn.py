"""IDN helpers: store/serve punycode, display unicode (parity with the old
Net::IDN::Encode usage). Conversion is label-wise so wildcard (*) and
underscore labels (_dmarc, _acme-challenge) pass through untouched."""

import idna


def _label_to_ascii(label: str) -> str:
    if label.isascii():
        return label.lower()
    try:
        return idna.encode(label, uts46=True).decode()
    except idna.IDNAError:
        return label.lower()


def _label_to_unicode(label: str) -> str:
    if not label.startswith("xn--"):
        return label
    try:
        return idna.decode(label)
    except idna.IDNAError:
        return label


def to_ascii(name: str) -> str:
    name = name.strip()
    trailing = name.endswith(".")
    labels = [_label_to_ascii(l) for l in name.rstrip(".").split(".") if l or False]
    return ".".join(labels) + ("." if trailing else "")


def to_unicode(name: str) -> str:
    trailing = name.endswith(".")
    labels = [_label_to_unicode(l) for l in name.rstrip(".").split(".")]
    return ".".join(labels) + ("." if trailing else "")
