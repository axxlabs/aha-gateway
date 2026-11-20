"""WhatsApp formatting for the simulator, copied from amb-v2 (its spec §15.2).

A message as the phone shows it: *bold*, _italic_, ~strikethrough~, `code`, ``` monospace blocks ``` and
"> " quotes. A marker counts only when it touches a word on its inner side and not on its outer side, as on
WhatsApp; inside a monospace block or a web address nothing is formatted. The text is escaped first, so no
message becomes HTML.
"""

from __future__ import annotations

import re

from markupsafe import Markup, escape

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+?(?=[.,;:!?)]*(?:\s|$))")
MONO_BLOCK = re.compile(r"```(.*?)```", re.S)
INLINE_CODE = re.compile(r"`([^`\n]+)`")
QUOTE_LINE = re.compile(r"^&gt; ?(.*)$", re.M)
STYLES = [
    (re.compile(rf"(?<![\w{m}])\{m}(?=\S)([^{m}\n]*?\S)\{m}(?![\w{m}])"), tag)
    for m, tag in (("*", "strong"), ("_", "em"), ("~", "s"))
]


def linkify(text: str) -> Markup:
    escaped = str(escape(text))
    return Markup(
        URL_PATTERN.sub(
            lambda m: f'<a href="{m.group(0)}" target="_blank" rel="noopener noreferrer">{m.group(0)}</a>',
            escaped,
        )
    )


def _styled(text: str) -> str:
    out = str(escape(text))
    out = INLINE_CODE.sub(r"<code>\1</code>", out)
    for pattern, tag in STYLES:
        out = pattern.sub(rf"<{tag}>\1</{tag}>", out)
    return QUOTE_LINE.sub(r'<span class="quote">\1</span>', out)


def _inline(text: str) -> str:
    out, last = [], 0
    for m in URL_PATTERN.finditer(text):
        out += [_styled(text[last : m.start()]), str(linkify(m.group(0)))]
        last = m.end()
    return "".join([*out, _styled(text[last:])])


def whatsapp(text: str) -> Markup:
    parts = MONO_BLOCK.split(text)
    out = []
    for i, part in enumerate(parts):
        if i % 2:
            out.append(f'<code class="mono">{escape(part.strip(chr(10)))}</code>')
            continue
        if i > 0:
            part = part.removeprefix("\n")
        if i < len(parts) - 1:
            part = part.removesuffix("\n")
        out.append(_inline(part))
    return Markup("".join(out))
