"""Parameter-name vocabulary shared by the sink-selecting checks.

Which parameters are worth probing for a given vulnerability class is a naming
heuristic, and more than one check needs the same list: ``ssrf`` picks URL-ish
params for its reflected probe, and ``oob_injection`` picks the same ones (plus
the file-inclusion names) for its out-of-band probe. Keeping the vocabulary here
means neither check has to import the other's privates, and adding a name
benefits both.
"""
from __future__ import annotations

#: Params whose name suggests the server will fetch the value (SSRF sinks).
SSRF_PARAM_HINTS = frozenset({
    "url", "uri", "link", "callback", "webhook", "redirect", "dest",
    "target", "host", "domain", "image", "img", "src", "feed", "next",
    "return_url", "image_url", "fetch",
})

#: Params whose name suggests the server will include/read a path (RFI sinks).
RFI_PARAM_HINTS = frozenset({
    "file", "path", "page", "include", "inc", "template", "tpl", "doc",
    "document", "load", "read", "view", "module", "conf", "config",
})


def is_urlish(name: str) -> bool:
    """True when ``name`` reads like it carries a URL the server may fetch."""
    n = name.lower()
    return n in SSRF_PARAM_HINTS or n.endswith("url")


def is_fetchable(name: str) -> bool:
    """True for either a URL-ish or a file-inclusion parameter name."""
    n = name.lower()
    return n in SSRF_PARAM_HINTS or n in RFI_PARAM_HINTS
