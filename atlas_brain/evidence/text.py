"""LF-delimited UTF-8/ASCII text views; every character maps to raw bytes."""
from dataclasses import dataclass

from atlas_brain.kernel.states import ByteSpan


@dataclass(frozen=True, slots=True)
class TextLine:
    text: str
    span: ByteSpan
    offsets: tuple[int, ...]
    decoding_errors: bool

    def raw_span(self, start: int, end: int) -> ByteSpan:
        if not 0 <= start <= end <= len(self.text):
            raise ValueError("invalid_text_span")
        return ByteSpan(start=self.offsets[start], end=self.offsets[end])


def text_lines(raw: bytes, codec: str) -> tuple[TextLine, ...]:
    if codec not in ("utf-8", "ascii", "latin-1"):
        raise ValueError("unsupported_codec")
    lines: list[TextLine] = []
    start = 0
    while start < len(raw):
        stop = raw.find(b"\n", start)
        end = len(raw) if stop == -1 else stop + 1
        body = raw[start:end - 1] if stop != -1 else raw[start:end]
        if stop != -1 and body.endswith(b"\r"):
            body = body[:-1]
        text = body.decode(codec, errors="surrogateescape")
        offsets = [start]
        for char in text:
            offsets.append(offsets[-1] + len(char.encode(codec, errors="surrogateescape")))
        clean = "".join("\ufffd" if 0xDC80 <= ord(c) <= 0xDCFF else c for c in text)
        lines.append(TextLine(clean, ByteSpan(start=start, end=end), tuple(offsets), clean != text))
        start = end
    return tuple(lines)
