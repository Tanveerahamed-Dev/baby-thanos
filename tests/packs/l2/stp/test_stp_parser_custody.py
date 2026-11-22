"""Actual STP parser returns cannot replace coordinates used by its owning cache."""
import pytest
from test_global_root_guard import LIMITS, scenario, write

from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as tree
from atlas_brain.runner import p4_pipeline


class OpenId(str):
    def __hash__(self):
        raise AssertionError("hashed an open capture ID")

    def __eq__(self, _other):
        raise AssertionError("compared an open capture ID")


class OpenKey(str):
    __hash__ = str.__hash__

    def __eq__(self, _other):
        raise AssertionError("compared an open parser cache key")


@pytest.mark.parametrize("plant", ["original", "id", "source", "context", "raw_copy", "map_copy", "open_key", "owner_class"])
def test_actual_stp_parser_closes_original_coordinates_before_cache_write(tmp_path, monkeypatch, plant):
    files, side = scenario()
    channel_target = next(row for row in side["targets"] if row["id"] == "ec")
    channel_target["params"] = {"groups": ["1"], "ports": ["Gi1/0/1", "Gi1/0/2"]}
    write(tmp_path, files, side)
    root_guard = tree.RootGuardPack[object](LIMITS)
    summary = SummaryPack[object](LIMITS)
    own = root_guard
    owner_batch, live_requests, observations = [], [], []
    prepare, parse = own.prepare, tree.stp.parse_capture

    def preparing(envelope):
        batch = prepare(envelope)
        handler, = batch.handlers
        parser = handler.parser
        dispatch = parser.parse

        def observing_request(request):
            live_requests.append(request)
            return dispatch(request)

        monkeypatch.setattr(parser, "parse", observing_request)
        owner_batch.append((parser, parser.produced, batch.requests[0], type(parser)))
        return batch

    def parsing(capture, *coordinates):
        materialized = parse(capture, *coordinates)
        observations.append((capture, materialized))
        parser, produced, original, _original_class = owner_batch[0]
        request = live_requests[0]
        assert request is not original and request.capture is original.capture is capture
        if plant == "id":
            object.__setattr__(capture, "id", OpenId(capture.id))
        elif plant == "source":
            object.__setattr__(capture, "source", "node:demo:changed")
        elif plant == "context":
            object.__setattr__(request, "context", "changed")
        elif plant == "raw_copy":
            copied = bytes(bytearray(capture.raw))
            assert copied == capture.raw and copied is not capture.raw
            object.__setattr__(capture, "raw", copied)
        elif plant == "map_copy":
            parser.produced = dict(produced)
        elif plant == "open_key":
            produced[OpenKey(capture.id)] = materialized
        elif plant == "owner_class":
            class OpenOwner(type(parser)):
                __slots__ = ()

                def __getattribute__(self, name):
                    raise AssertionError(f"read open parser owner: {name}")

            object.__setattr__(parser, "__class__", OpenOwner)
        return materialized

    monkeypatch.setattr(own, "prepare", preparing)
    monkeypatch.setattr(tree.stp, "parse_capture", parsing)
    monkeypatch.setattr(FactWriter, "write", lambda *_a, **_kw: pytest.fail("parser custody wrote a fact"))
    if plant == "original":
        run = p4_pipeline.execute_p4_folder(tmp_path, LIMITS, packs=(root_guard, summary))
        capture, value = observations[0]
        output, = (item for item in run.executed if item.receipt.capture is capture)
        assert output.value is value and output.receipt.parse is value.parse
        produced = owner_batch[0][1]
        assert len(produced) == 1 and produced[capture.id] is value
    else:
        try:
            with pytest.raises(ValueError, match="^stp_parser_custody$"):
                p4_pipeline.execute_p4_folder(tmp_path, LIMITS, packs=(root_guard, summary))
        finally:
            if plant == "owner_class" and owner_batch:
                parser, _produced, _original, original_class = owner_batch[0]
                object.__setattr__(parser, "__class__", original_class)
        original_cache = owner_batch[0][1]
        if plant == "open_key":
            key, = original_cache
            assert type(key) is OpenKey
        else:
            assert not original_cache
    assert len(owner_batch) == len(live_requests) == len(observations) == 1
