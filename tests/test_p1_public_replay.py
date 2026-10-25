import copy
import hashlib
import io
import json
from types import SimpleNamespace

import pytest

from tools import p1_public_replay as study

HEAD, OTHER = "a" * 40, "b" * 40
SPECS = (("up", "up", "up", "up", "ok"),
         ("up", "up", "down", "down", "problem"),
         ("down", None, "down", "down", "unknown"))

def source(specs=SPECS, operation="show ip interface brief", method="unset"):
    lines = [] if operation == "show interfaces" else ["Interface IP-Address OK? Method Status Protocol"]
    for i, (admin_raw, _, oper_raw, _, _) in enumerate(specs):
        if admin_raw is None:
            text = f"Sentinel0{i}"
        elif operation == "show interfaces":
            text = f"Sentinel0{i} is {admin_raw}" + ("" if oper_raw is None else f", line protocol is {oper_raw}")
        else:
            text = f"Sentinel0{i} unassigned YES {method} {admin_raw}" + ("" if oper_raw is None else f" {oper_raw}")
        lines.append(text)
    return ("\n".join(lines) + "\n").encode("ascii")
RAW = source()
PRIVATE = "DO_NOT_PUBLISH_SYNTHETIC_SENTINEL"

def sha(value):
    return hashlib.sha256(value).hexdigest()

def profile():
    return (*study.PROFILES[0][:3], len(RAW), sha(RAW), *study.PROFILES[0][5:])

def pack(value):
    return next(iter(value["facts"].values()))

def grounded(specs=SPECS, parse="complete", operation="show ip interface brief", method="unset"):
    raw = source(specs, operation, method)
    capture = "cap:" + sha(b"public.txt\0" + raw)
    whole = {"capture": capture, "sha256": sha(raw), "locator": "whole_capture"}
    needs = [{"node": "node:file:" + sha(b"public.txt"), "operation": operation,
              "resolves": ["l1.interface.admin", "l1.interface.oper"],
              "reruns": ["l1.interface.admin_up_oper_down"]}]
    def reference(start, end):
        return {"capture": capture, "sha256": sha(raw[start:end]), "locator": "bytes", "start": start, "end": end}
    def field(value, start, end, context=None, reason="parse_partial"):
        refs = ([] if start is None else [reference(start, end)]) + ([] if context is None else [copy.deepcopy(context)])
        return ({"state": "known", "basis": "observed", "value": value, "evidence": refs} if value is not None
                else {"state": "unknown", "reason": reason, "detail": PRIVATE,
                      "evidence": refs, "next_evidence": copy.deepcopy(needs)})
    lines = raw.splitlines()[0 if operation == "show interfaces" else 1:]
    rows = []
    for i, ((admin_raw, admin_value, oper_raw, oper_value, state), line) in enumerate(zip(specs, lines)):
        start = raw.index(line)
        context = reference(start, start + len(line))
        marker = b" is " if operation == "show interfaces" else b" " + method.encode("ascii") + b" "
        admin_start = None if admin_raw is None else start + line.index(marker) + len(marker)
        oper_start = None
        if oper_raw is not None:
            oper_start = (start + line.index(b", line protocol is ") + len(b", line protocol is ")
                          if operation == "show interfaces" else admin_start + len(admin_raw) + 1)
        admin_reason = "not_observable" if admin_raw == "down" else "parse_partial"
        check = {"id": "l1.interface.admin_up_oper_down", "state": state,
                 "next_evidence": [] if state == "ok" else copy.deepcopy(needs)}
        if state == "unknown":
            check["reason"] = admin_reason if admin_value is None else "parse_partial"
        rows.append({"name": field(f"Sentinel0{i}", start, start + len(f"Sentinel0{i}")),
                     "admin": field(admin_value, admin_start, None if admin_start is None else admin_start + len(admin_raw), context, admin_reason),
                     "oper": field(oper_value, oper_start, None if oper_start is None else oper_start + len(oper_raw), context),
                     "check": check})
    item = {"pack": "l1.interface", "variant_support": "allowlisted", "operation": operation, "parse": parse,
            "denominator": {"scope": "observed_in_capture", "count": len(rows)},
            "coverage": {"state": "unknown", "reason": "denominator_open", "evidence": [whole], "detail": PRIVATE,
                         "next_evidence": copy.deepcopy(needs)}, "interfaces": rows}
    evidence = json.dumps([{"capture": capture, "sha256": sha(raw)}], sort_keys=True, separators=(",", ":")).encode("ascii")
    return {"schema": "atlas-brain.runner-manifest/1", "evidence": {"files": 1, "digest": sha(evidence)},
            "plan": {"steps": 8, "witness_attempts": 4},
            "egress": {"parent_denied": 4, "coordinator_denied": 4, "worker_denied": 32, "denied": 40},
            "steps": [{"id": f"witness/{i:02d}", "denied": 4} for i in range(8)], "facts": {capture: item}}, raw

def manifest():
    return grounded()[0]

@pytest.mark.parametrize("context_ref", [False, True])
def test_summary_is_closed_and_source_bound(context_ref):
    value = manifest()
    if context_ref:
        row = pack(value)["interfaces"][0]
        row["name"]["evidence"].append(copy.deepcopy(row["admin"]["evidence"][-1]))
    result = study.summary(value, RAW, "show ip interface brief")
    assert result == {"captures": 1, "parse": "complete", "observed": 3, "coverage": "unknown",
                      "verdicts": {"ok": 1, "problem": 1, "unknown": 1}, "grounding": True,
                      "admin_up_oper_down": 1, "admin_down_oper_up": 0, "unknown_with_next_evidence": 1,
                      "grounded_rows": 3, "problem_with_next_evidence": 1}
    assert PRIVATE not in json.dumps(result)

@pytest.mark.parametrize("mutate", [
    lambda m: m.update(extra=PRIVATE),
    lambda m: m.update(schema="wrong"),
    lambda m: m["evidence"].update(files=True),
    lambda m: m["evidence"].update(digest="0" * 64),
    lambda m: m["plan"].update(steps=True),
    lambda m: m["egress"].update(denied=39),
    lambda m: m["steps"][1].update(id="witness/00"),
    lambda m: m.update(facts={}),
    lambda m: pack(m).update(pack="l2.interface"),
    lambda m: pack(m).update(operation="show vlan"),
    lambda m: pack(m).update(variant_support="unapproved"),
    lambda m: pack(m).update(parse="garbled"),
    lambda m: pack(m)["coverage"].update(state="complete"),
    lambda m: pack(m)["denominator"].update(count=999),
    lambda m: pack(m).update(interfaces=[pack(m)["interfaces"][0]],
                             denominator={"scope": "observed_in_capture", "count": True}),
    lambda m: pack(m)["interfaces"][0]["check"].update(state=PRIVATE),
    lambda m: pack(m)["interfaces"][0]["name"]["evidence"][0].update(sha256="0" * 64),
    lambda m: pack(m)["interfaces"][0]["name"]["evidence"][0].update(capture="cap:" + "0" * 64),
    lambda m: pack(m)["coverage"]["evidence"][0].update(locator="bytes", start=True, end=2, sha256=sha(RAW[1:2])),
])
def test_summary_refuses_corruption_without_echo(mutate):
    value = manifest()
    mutate(value)
    with pytest.raises(study.StudyRefused) as error:
        study.summary(value, RAW, "show ip interface brief")
    assert PRIVATE not in str(error.value)

@pytest.mark.parametrize("mutate,head", [
    (lambda m: m.update({PRIVATE: PRIVATE}), HEAD),
    (lambda m: m["profiles"][0].update({PRIVATE: PRIVATE}), HEAD),
    (lambda m: m["profiles"][0].update(observed=999), HEAD),
    (lambda m: m["profiles"][0].update(captures=True), HEAD),
    (lambda m: m.update(format_floor=0), HEAD),
    (lambda m: m["profiles"][0].update(grounding=1), HEAD),
    (lambda m: m["profiles"][0].update(grounded_rows=21.0), HEAD),
    (lambda m: m["profiles"][0].update(problem_with_next_evidence=False), HEAD),
    (lambda m: m["profiles"][0].update(admin_up_oper_down=99), HEAD),
    (lambda m: m["profiles"][0].update(admin_down_oper_up=False), HEAD),
    (lambda m: m["profiles"][0].update(unknown_with_next_evidence=True), HEAD),
    (lambda m: m.update(schema="atlas-brain.p1-public-replay/1"), HEAD),
    (lambda m: m.update(phase_exit=False), HEAD),
    (lambda m: None, OTHER),
])
def test_report_publisher_is_closed_typed_and_head_bound(mutate, head):
    valid = study.report(HEAD)
    assert json.loads(study.screen(valid, HEAD)) == valid
    bad = copy.deepcopy(valid)
    mutate(bad)
    with pytest.raises(study.StudyRefused):
        study.screen(bad, head)

@pytest.mark.parametrize("data", ['{"a":1,"a":2}', '{"x":{"a":1,"a":2}}', 'NaN', 'Infinity', '-Infinity'])
def test_loader_rejects_ambiguous_json(data):
    with pytest.raises(study.StudyRefused):
        study.load(data)

@pytest.mark.parametrize("fault", ["none", "short", "long", "hash", "status", "network"])
def test_fetch_is_bounded_without_network(monkeypatch, fault):
    item = list(profile())
    payload = RAW[:-1] if fault == "short" else RAW + b"x" if fault == "long" else RAW
    if fault in ("short", "long"):
        item[4] = sha(payload)  # Correct digest isolates the length guard.
    if fault == "hash":
        item[4] = "0" * 64
    class Response(io.BytesIO):
        status = 302 if fault == "status" else 200
        def read(self, size=-1):
            assert size == len(RAW) + 1
            return super().read(size)
    def open_fake(url, timeout):
        assert timeout == 30 and url == f"https://raw.githubusercontent.com/{study.REPO}/{study.PIN}/{study.PREFIX}{item[1]}"
        if fault == "network":
            raise OSError("synthetic network failure")
        return Response(payload)
    monkeypatch.setattr(study, "build_opener", lambda *args: SimpleNamespace(open=open_fake))
    if fault == "none":
        assert study.fetch_source(tuple(item)) == RAW
    else:
        with pytest.raises((study.StudyRefused, OSError)):
            study.fetch_source(tuple(item))

@pytest.mark.parametrize("code,out,err", [(1, b"runner: ok egress_denied=40", b""),
    (0, b"runner: ok egress_denied=40", b"synthetic stderr"), (0, b"wrong", b"")])
def test_runner_failure_cannot_create_success(monkeypatch, tmp_path, code, out, err):
    monkeypatch.setattr(study.subprocess, "run", lambda *a, **kw:
                        SimpleNamespace(returncode=code, stdout=out, stderr=err))
    with pytest.raises(study.StudyRefused):
        study.replay(profile(), tmp_path / "replay", RAW)

@pytest.mark.parametrize("fault", ["none", "stale", "wrong_head", "fetch"])
def test_main_transaction_boundaries(monkeypatch, tmp_path, capsys, fault):
    checkout, outside = tmp_path / "checkout", tmp_path / "outside"
    checkout.mkdir()
    outside.mkdir()
    monkeypatch.setattr(study, "ROOT", checkout)
    for key, value in {"GITHUB_ACTIONS": "true", "EXPECTED_HEAD": HEAD, "RUNNER_TEMP": str(outside)}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(study.sys, "argv", ["study", "publish" if fault == "wrong_head" else "run"])
    events = []
    monkeypatch.setattr(study, "engine_commit", lambda commit: events.append("head"))
    def fetch(item):
        events.append("fetch")
        if fault == "fetch" and events.count("fetch") == 2:
            raise study.StudyRefused("refused")
        return RAW
    monkeypatch.setattr(study, "fetch_source", fetch)
    monkeypatch.setattr(study, "replay", lambda *args: events.append("replay"))
    target = outside / "p1-public-report.json"
    if fault == "fetch":
        with pytest.raises(study.StudyRefused):
            study.main()
        assert events == ["head", "fetch", "fetch"] and not target.exists()
    elif fault != "none":
        before = study.screen(study.report(OTHER if fault == "wrong_head" else HEAD), OTHER if fault == "wrong_head" else HEAD)
        target.write_bytes(before)
        with pytest.raises(study.StudyRefused):
            study.main()
        assert target.read_bytes() == before and events == []
        assert capsys.readouterr().out == ""
    else:
        study.main()
        count = len(study.PROFILES)
        assert count >= 2 and events == ["head"] + ["fetch"] * count + ["replay"] * count + ["head"]
        assert target.read_bytes() == study.screen(study.report(HEAD), HEAD)

def test_redirect_is_refused():
    with pytest.raises(study.StudyRefused):
        study.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid")

@pytest.mark.parametrize("spec,up_down,down_up", [
    (("up", "up", "up", "up", "ok"), 0, 0),
    (("administratively down", "down", "down", "down", "ok"), 0, 0),
    (("administratively down", "down", "up", "up", "problem"), 0, 1),
    (("up", "up", "up , Autostate Enabled", "up", "ok"), 0, 0),
    (("up", "up", "down , Autostate Enabled", "down", "problem"), 1, 0),
])
def test_closed_literals_and_both_mismatch_directions(spec, up_down, down_up):
    value, raw = grounded((spec,), operation="show interfaces")
    result = study.summary(value, raw, "show interfaces")
    assert result == {"captures": 1, "parse": "complete", "observed": 1, "coverage": "unknown",
                      "verdicts": {state: int(state == spec[4]) for state in ("ok", "problem", "unknown")},
                      "grounding": True, "admin_up_oper_down": up_down, "admin_down_oper_up": down_up,
                      "unknown_with_next_evidence": 0, "grounded_rows": 1, "problem_with_next_evidence": int(spec[4] == "problem")}

def test_partial_equal_states_remain_actionable_unknown():
    value, raw = grounded((("up", "up", "up", "up", "unknown"),), parse="partial")
    result = study.summary(value, raw, "show ip interface brief")
    assert result == {"captures": 1, "parse": "partial", "observed": 1, "coverage": "unknown",
                      "verdicts": {"ok": 0, "problem": 0, "unknown": 1}, "grounding": True,
                      "admin_up_oper_down": 0, "admin_down_oper_up": 0, "unknown_with_next_evidence": 1,
                      "grounded_rows": 1, "problem_with_next_evidence": 0}

@pytest.mark.parametrize("mutate", [
    lambda m: pack(m)["interfaces"][0]["name"].update(value=PRIVATE),
    lambda m: pack(m)["interfaces"][0]["admin"].update(value="down"),
    lambda m: pack(m)["interfaces"][0]["oper"].update(value="down"),
    lambda m: pack(m)["interfaces"][0]["admin"].update(basis="inferred"),
    lambda m: pack(m)["interfaces"][0]["check"].update(state="problem", next_evidence=copy.deepcopy(pack(m)["coverage"]["next_evidence"])),
    lambda m: pack(m)["interfaces"][0]["check"].update(state="unknown", next_evidence=copy.deepcopy(pack(m)["coverage"]["next_evidence"])),
    lambda m: pack(m)["interfaces"][1]["check"].update(state="ok", next_evidence=[]),
    lambda m: pack(m)["interfaces"][1]["check"].update(state="unknown"),
    lambda m: pack(m)["interfaces"][2]["check"].update(state="problem"),
    lambda m: pack(m)["interfaces"][2]["check"].update(state="ok", next_evidence=[]),
    lambda m: pack(m).update(parse="partial"),
    lambda m: pack(m)["interfaces"][0]["admin"]["evidence"].append(copy.deepcopy(pack(m)["interfaces"][0]["admin"]["evidence"][0])),
    lambda m: pack(m)["interfaces"][0]["admin"]["evidence"][-1].update(sha256="0" * 64),
])
def test_semantic_contradictions_are_refused_without_echo(mutate):
    value = manifest()
    mutate(value)
    with pytest.raises(study.StudyRefused) as error:
        study.summary(value, RAW, "show ip interface brief")
    assert PRIVATE not in str(error.value)

@pytest.mark.parametrize("spec", [
    ("down", "down", "down", "down", "ok"),
    ("up", "up", "standby", "up", "ok"),
])
def test_matching_hash_cannot_admit_unmapped_known_literal(spec):
    value, raw = grounded((spec,), operation="show interfaces")
    with pytest.raises(study.StudyRefused):
        study.summary(value, raw, "show interfaces")

@pytest.mark.parametrize("fault", ["token_transplant", "name_transplant", "multiline", "whole_bytes", "partial_name"])
def test_grounded_tokens_must_belong_to_one_complete_row(fault):
    operation = "show interfaces" if fault == "whole_bytes" else "show ip interface brief"
    value, raw = grounded(operation=operation)
    first, second = pack(value)["interfaces"][:2]
    if fault == "token_transplant":
        first["admin"]["evidence"][0] = copy.deepcopy(second["admin"]["evidence"][0])
    elif fault == "name_transplant":
        first["name"] = copy.deepcopy(second["name"])
    elif fault in ("multiline", "whole_bytes"):
        context = copy.deepcopy(first["admin"]["evidence"][-1])
        context["end"] = len(raw) - 1 if fault == "whole_bytes" else second["admin"]["evidence"][-1]["end"]
        context["sha256"] = sha(raw[context["start"]:context["end"]])
        for field in ("admin", "oper"):
            first[field]["evidence"][-1] = copy.deepcopy(context)
    else:
        first["name"]["value"] = "Sentinel0"
        ref = first["name"]["evidence"][0]
        ref["end"] = ref["start"] + len("Sentinel0")
        ref["sha256"] = sha(raw[ref["start"]:ref["end"]])
    with pytest.raises(study.StudyRefused):
        study.summary(value, raw, operation)

@pytest.mark.parametrize("target", ["coverage", "admin", "problem", "unknown"])
@pytest.mark.parametrize("fault", ["empty", "duplicate", "node", "operation", "resolves", "reruns", "extra"])
def test_unknowns_and_problems_require_actionable_next_evidence(target, fault):
    value = manifest()
    rows = pack(value)["interfaces"]
    item = {"coverage": pack(value)["coverage"], "admin": rows[2]["admin"],
            "problem": rows[1]["check"], "unknown": rows[2]["check"]}[target]
    needs = copy.deepcopy(item["next_evidence"])
    if fault == "empty":
        needs = []
    elif fault == "duplicate":
        needs *= 2
    else:
        needs[0][fault] = {"node": PRIVATE, "operation": "show vlan", "resolves": ["l1.interface.admin"],
                           "reruns": [], "extra": True}[fault]
    item["next_evidence"] = needs
    with pytest.raises(study.StudyRefused) as error:
        study.summary(value, RAW, "show ip interface brief")
    assert PRIVATE not in str(error.value)

def test_public_report_records_grounding_without_promoting_evidence():
    report = study.report(HEAD)
    assert report["schema"] == "atlas-brain.p1-public-replay/2"
    assert report["phase_exit"] == "not_evaluated" and report["format_floor"] is False
    assert report["raw_republication"] == "held" and report["truth"] == "not_measured"
    assert all(report[key] == "unknown" for key in ("origin", "model", "train", "capture_authenticity"))
    assert [p["profile"] for p in report["profiles"]] == ["brief", "full"]
    for profile, expected in zip(report["profiles"], ((0, 0, 1), (21, 0, 127))):
        assert profile["grounding"] is True and profile["grounded_rows"] == profile["observed"]
        assert profile["problem_with_next_evidence"] == profile["verdicts"]["problem"]
        assert tuple(profile[key] for key in ("admin_up_oper_down", "admin_down_oper_up", "unknown_with_next_evidence")) == expected

def test_partial_known_mismatch_cannot_be_hidden_as_unknown():
    value, raw = grounded((("up", "up", "down", "down", "problem"),), parse="partial")
    result = study.summary(value, raw, "show ip interface brief")
    assert result["verdicts"] == {"ok": 0, "problem": 1, "unknown": 0}
    assert result["admin_up_oper_down"] == 1 and result["unknown_with_next_evidence"] == 0
    pack(value)["interfaces"][0]["check"]["state"] = "unknown"
    with pytest.raises(study.StudyRefused):
        study.summary(value, raw, "show ip interface brief")

@pytest.mark.parametrize("admin_raw,oper_raw", [("startup", "shutdown"), ("unexpected up", "unexpected down")])
def test_literal_suffixes_cannot_be_laundered_as_complete_states(admin_raw, oper_raw):
    value, raw = grounded(((admin_raw, "up", oper_raw, "down", "problem"),), operation="show interfaces")
    row = pack(value)["interfaces"][0]
    for field, token in (("admin", b"up"), ("oper", b"down")):
        ref = row[field]["evidence"][0]
        ref["start"] = ref["end"] - len(token)
        ref["sha256"] = sha(raw[ref["start"]:ref["end"]])
    with pytest.raises(study.StudyRefused):
        study.summary(value, raw, "show interfaces")

def test_duplicate_row_cannot_replace_another_same_verdict_row():
    value, raw = grounded((SPECS[0], SPECS[0]))
    rows = pack(value)["interfaces"]
    rows[1] = copy.deepcopy(rows[0])
    with pytest.raises(study.StudyRefused):
        study.summary(value, raw, "show ip interface brief")

@pytest.mark.parametrize("mutate", [
    lambda m: pack(m)["coverage"].update(reason="parse_partial"),
    lambda m: pack(m)["interfaces"][2]["admin"].update(reason="parse_partial"),
    lambda m: pack(m)["interfaces"][2]["admin"].pop("reason"),
    lambda m: pack(m)["interfaces"][2]["check"].update(reason="parse_partial"),
    lambda m: pack(m)["interfaces"][0]["admin"].update(reason=PRIVATE),
    lambda m: pack(m)["interfaces"][0]["check"].update(reason=PRIVATE),
    lambda m: pack(m)["interfaces"][1]["check"].update(reason=PRIVATE),
])
def test_reasons_are_canonical_and_absent_for_known_results(mutate):
    value = manifest()
    mutate(value)
    with pytest.raises(study.StudyRefused) as error:
        study.summary(value, RAW, "show ip interface brief")
    assert PRIVATE not in str(error.value)

@pytest.mark.parametrize("index,key,known", [(0, "admin", False), (0, "oper", False), (2, "admin", True)])
def test_raw_field_decides_known_or_unknown_state(index, key, known):
    value = manifest()
    row = pack(value)["interfaces"][index]
    refs = copy.deepcopy(row[key]["evidence"])
    needs = copy.deepcopy(pack(value)["coverage"]["next_evidence"])
    row[key] = ({"state": "known", "basis": "observed", "value": "down", "evidence": refs} if known else
                {"state": "unknown", "reason": "parse_partial", "evidence": refs, "next_evidence": needs})
    row["check"] = {"id": "l1.interface.admin_up_oper_down", "state": "ok" if known else "unknown",
                    "next_evidence": [] if known else copy.deepcopy(needs)}
    if not known:
        row["check"]["reason"] = "parse_partial"
    with pytest.raises(study.StudyRefused):
        study.summary(value, RAW, "show ip interface brief")

@pytest.mark.parametrize("operation", ["show interfaces", "show ip interface brief"])
@pytest.mark.parametrize("spec", [("startup", None, "up", "up", "unknown"),
    ("up", "up", "standby", None, "unknown"), ("up", "up", None, None, "unknown"),
    (None, None, None, None, "unknown")])
def test_unsupported_and_absent_fields_remain_actionable_unknown(operation, spec):
    value, raw = grounded((spec,), parse="partial", operation=operation)
    result = study.summary(value, raw, operation)
    assert result["verdicts"] == {"ok": 0, "problem": 0, "unknown": 1}
    assert result["grounding"] is True and result["grounded_rows"] == 1
    assert result["unknown_with_next_evidence"] == 1 and result["problem_with_next_evidence"] == 0

def test_equal_method_token_cannot_replace_the_status_field():
    value, raw = grounded(method="up")
    row = pack(value)["interfaces"][0]
    ref = row["admin"]["evidence"][0]
    ref["start"] = raw.index(b" YES up ") + len(b" YES ")
    ref["end"] = ref["start"] + 2
    ref["sha256"] = sha(raw[ref["start"]:ref["end"]])
    with pytest.raises(study.StudyRefused):
        study.summary(value, raw, "show ip interface brief")

@pytest.mark.parametrize("name,oper", [("Sentinel00", "up"), ("Sentinel00", "down"), ("Sentinel01", "down")])
def test_raw_census_refuses_duplicates_conflicts_and_omitted_rows(monkeypatch, name, oper):
    original = source
    suffix = f"{name} is up, line protocol is {oper}\n".encode("ascii")
    monkeypatch.setitem(globals(), "source", lambda *args, **kwargs: original(*args, **kwargs) + suffix)
    value, raw = grounded((SPECS[0],), operation="show interfaces")
    assert len(pack(value)["interfaces"]) == 1
    with pytest.raises(study.StudyRefused):
        study.summary(value, raw, "show interfaces")
