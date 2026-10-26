"""P3 envelope classification is byte custody, never semantic parser approval."""
import pytest

from atlas_brain.evidence.admission import AdmissionRefused
from atlas_brain.evidence.p3_records import OPERATIONS
from atlas_brain.evidence.p3_text import integrity
from atlas_brain.kernel import states as k


@pytest.mark.parametrize("operation,command", tuple(OPERATIONS.items()))
@pytest.mark.parametrize("ending", [b"\n", b"\r\n", b""])
def test_exact_operation_wrappers_retain_a_complete_supplied_body(operation, command, ending):
    raw = b"sw-a#" + command.encode() + b"\nopaque owner-parsed body" + ending
    assert integrity(raw, operation) is k.IntegrityState.COMPLETE
    assert integrity(command.encode() + b"\nopaque body\n", operation) is k.IntegrityState.COMPLETE


@pytest.mark.parametrize("operation", tuple(OPERATIONS))
def test_correct_closing_prompt_and_unadorned_body_are_admitted(operation):
    command = OPERATIONS[operation].encode()
    assert integrity(b"sw-a#" + command + b"\nbody\nsw-a#\n", operation) is k.IntegrityState.COMPLETE
    assert integrity(b"body without wrapper\n", operation) is k.IntegrityState.COMPLETE


@pytest.mark.parametrize("raw,code", [
    (b"sw-a#show version\nbody\n", "p3_mixed_context"),
    (b"sw-a#show ip interface\nbody\nsw-b#\n", "p3_mixed_context"),
    (b"sw-a(config)#ip mtu 1500\n", "p3_mixed_context"),
    (b"body\nsw-a#show version\n", "p3_mixed_context"),
    (b"body\nshow version\n", "p3_mixed_context"),
    (b"banner motd ^C\n", "p3_mixed_context"),
    (b"\xff", "p3_invalid_encoding"),
    (b"body\rrewritten\n", "p3_invalid_text"),
    (b"\x1b[31mbody\n", "p3_invalid_text"),
    ("body\u2028hidden".encode(), "p3_invalid_text"),
])
def test_wrong_command_context_and_text_damage_refuse(raw, code):
    with pytest.raises(AdmissionRefused, match="^" + code + "$"):
        integrity(raw, "iosxe.show_ip_interface")


@pytest.mark.parametrize("raw,expected", [
    (b"", k.IntegrityState.EMPTY), (b" \t\n", k.IntegrityState.EMPTY),
    (b"sw-a#show ip interface\nsw-a#\n", k.IntegrityState.EMPTY),
    (b"% Invalid input\n", k.IntegrityState.ERROR),
    (b"Command authorization failed\n", k.IntegrityState.ERROR),
    (b"body\n--More--\n", k.IntegrityState.TRUNCATED),
    (b"body\n<output truncated>\n", k.IntegrityState.TRUNCATED),
    (b"% Invalid input\n--More--\n", k.IntegrityState.ERROR),
])
def test_error_empty_and_truncation_are_not_repaired_by_body_text(raw, expected):
    assert integrity(raw, "iosxe.show_ip_interface") is expected


@pytest.mark.parametrize("operation", ["iosxe.show_version", "show ip interface", "", "iosxe.show_ip_ospf_neighbor_detail"])
def test_operation_vocabulary_stays_closed(operation):
    with pytest.raises(AdmissionRefused, match="^p3_operation$"):
        integrity(b"body\n", operation)
