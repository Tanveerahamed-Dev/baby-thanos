"""P3 text custody only; each owner accounts for the entire supplied body."""
import re

from atlas_brain.evidence.admission import AdmissionRefused
from atlas_brain.evidence.p3_records import OPERATIONS
from atlas_brain.kernel import states as k


def integrity(raw: bytes, operation: str) -> k.IntegrityState:
    if operation not in OPERATIONS:
        raise AdmissionRefused("p3_operation")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise AdmissionRefused("p3_invalid_encoding") from error
    if "\r" in text.replace("\r\n", "") or any(
        ord(char) < 32 and char not in "\t\r\n" or char in "\x7f\u0085\u2028\u2029" for char in text
    ):
        raise AdmissionRefused("p3_invalid_text")
    lines = [line.removesuffix("\r") for line in text.split("\n") if line.strip()]
    failed = any(line.lstrip().startswith("%") or "command authorization failed" in line.casefold() for line in lines)
    truncated = any(marker in text.casefold() for marker in (
        "--more--", "<--- more --->", "--(more)--", "[truncated]", "<output truncated>"))
    prompt, command = r"[A-Za-z0-9_.:-]+[>#]", OPERATIONS[operation]
    opening = re.fullmatch("(" + prompt + r") ?(.+)", lines[0], re.ASCII) if lines else None
    if opening and opening[2] != command:
        raise AdmissionRefused("p3_mixed_context")
    if opening or lines and lines[0] == command:
        lines = lines[1:]
    if lines and re.fullmatch(prompt, lines[-1], re.ASCII):
        if opening and lines[-1] != opening[1]:
            raise AdmissionRefused("p3_mixed_context")
        lines = lines[:-1]
    contexts = (r"[a-z0-9_.:-]+(?:\([^)]*\))?[>#].*",
                r"(?:do[ \t]+)?sh(?:ow|o)?[ \t].*", r"banner(?:[ \t]|$).*")
    if any(re.fullmatch(pattern, line.strip().casefold(), re.ASCII) for line in lines for pattern in contexts):
        raise AdmissionRefused("p3_mixed_context")
    if failed:
        return k.IntegrityState.ERROR
    if truncated:
        return k.IntegrityState.TRUNCATED
    return k.IntegrityState.COMPLETE if lines else k.IntegrityState.EMPTY
