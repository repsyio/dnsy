"""Validate one SVG: well-formed XML with a viewBox, and nothing active or external.

Usage: python3 -I check-svg.py FILE. Prints one reason per line and exits 1 on any failure.
"""
import re
import sys
import xml.dom.minidom as minidom

BANNED_ELEMENTS = {"script", "foreignobject", "image", "style", "iframe", "object", "embed", "use"}
HREF = {"href", "xlink:href"}
URL_REF = re.compile(r"url\(\s*(['\"]?)\s*([^)'\"]*)\1\s*\)", re.IGNORECASE)


def problems(path):
    raw = open(path, "rb").read()
    if re.search(rb"<!\s*(DOCTYPE|ENTITY)", raw, re.IGNORECASE):
        return ["DOCTYPE or ENTITY declaration"]
    try:
        doc = minidom.parseString(raw)
    except Exception as err:  # expat raises several types
        return [f"not well-formed: {err}"]
    out = []
    root = doc.documentElement
    if root.tagName.split(":")[-1].lower() != "svg":
        out.append("root element is not svg")
    if not root.hasAttribute("viewBox"):
        out.append("no viewBox")
    stack = [root]
    while stack:
        el = stack.pop()
        name = el.tagName.split(":")[-1].lower()
        if name in BANNED_ELEMENTS:
            out.append(f"banned element <{name}>")
        for key, value in el.attributes.items():
            k = key.lower()
            if k.startswith("on"):
                out.append(f"event handler attribute {key}")
            if k in HREF and not value.startswith("#"):
                out.append(f"external {key}")
            if k == "attributename" and value.lower() in HREF:
                out.append("SMIL animation of href")
            for m in URL_REF.finditer(value):
                if not m.group(2).startswith("#"):
                    out.append(f"url() to a non-fragment in {key}")
            if "@import" in value:
                out.append(f"@import in {key}")
        stack.extend(c for c in el.childNodes if c.nodeType == c.ELEMENT_NODE)
    return out


def main():
    bad = problems(sys.argv[1])
    for reason in bad:
        print(reason)
    return 1 if bad else 0


sys.exit(main())
