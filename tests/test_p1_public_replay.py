import copy
import hashlib
import io
import json
from types import SimpleNamespace
import pytest
from tools import p1_public_replay as study

HEAD, OTHER = "a" * 40, "b" * 40
RAW = b"DO_NOT_PUBLISH_SYNTHETIC_SENTINEL\n"
PRIVATE = RAW.decode().strip()

def sha(value):
    return hashlib.sha256(value).hexdigest()

def profile():
    return (*study.PROFILES[0][:3], len(RAW), sha(RAW), *study.PROFILES[0][5:])

def pack(value):
    return next(iter(value["facts"].values()))

def manifest(states=("ok", "problem", "unknown")):
    capture = "cap:" + sha(b"public.txt\0" + RAW)
    ref = {"capture": capture, "sha256": sha(RAW), "locator": "whole_capture"}
    fact = {"state": "known", "value": PRIVATE, "evidence": [ref]}
    rows = [{**{key: copy.deepcopy(fact) for key in ("name", "admin", "oper")},
             "check": {"id": "l1.interface.admin_up_oper_down", "state": state, "next_evidence": [], "reason": PRIVATE}} for state in states]
    item = {"pack": "l1.interface", "variant_support": "allowlisted", "operation": "show ip interface brief", "parse": "complete",
            "denominator": {"scope": "observed_in_capture", "count": len(rows)},
            "coverage": {"state": "unknown", "evidence": [ref], "detail": PRIVATE}, "interfaces": rows}
    evidence = json.dumps([{"capture": capture, "sha256": sha(RAW)}], sort_keys=True, separators=(",", ":")).encode("ascii")
    return {"schema": "atlas-brain.runner-manifest/1", "evidence": {"files": 1, "digest": sha(evidence)},
            "plan": {"steps": 8, "witness_attempts": 4},
            "egress": {"parent_denied": 4, "coordinator_denied": 4, "worker_denied": 32, "denied": 40},
            "steps": [{"id": f"witness/{i:02d}", "denied": 4} for i in range(8)], "facts": {capture: item}}

@pytest.mark.parametrize("byte_ref", [False, True])
def test_summary_is_closed_and_source_bound(byte_ref):
    value = manifest()
    if byte_ref:
        pack(value)["interfaces"][0]["name"]["evidence"][0].update(locator="bytes", start=0, end=3, sha256=sha(RAW[:3]))
    result = study.summary(value, RAW, "show ip interface brief")
    assert result == {"captures": 1, "parse": "complete", "observed": 3, "coverage": "unknown", "verdicts": {"ok": 1, "problem": 1, "unknown": 1}}
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
    lambda m: pack(m)["interfaces"][0]["name"]["evidence"][0].update(locator="bytes", start=True, end=2, sha256=sha(RAW[1:2])),
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
