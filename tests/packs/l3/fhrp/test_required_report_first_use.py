"""Real first-callback handle and flat-argument tests for six-subject and two-requirement phases."""
from dataclasses import replace

import pytest
from first_use_support import (
    DATA_FAULTS,
    HANDLE_FAULTS,
    poison_data,
    poison_handle,
    poison_value_class,
)
from presence_test_support import capture
from required_report_cases import original_inputs
from test_gateway_source import LIMITS

from atlas_brain.model import store
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import reported_presence as present
from atlas_brain.packs.l3.fhrp import required_report_profile as profile
from atlas_brain.packs.l3.fhrp import required_report_run as required

PHASES=("source_reader","positive_writer","presence_reader","required_writer")
CASES=[(phase,fault) for phase in PHASES for fault in HANDLE_FAULTS+DATA_FAULTS]
CASES +=[(phase,"value_class") for phase in ("positive_writer","required_writer")]


@pytest.mark.parametrize("phase,fault",CASES)
def test_first_actual_callback_cannot_poison_next_use_or_defer_argument_lookup(tmp_path,monkeypatch,phase,fault):
    root=tmp_path/"inputs"
    _envelope,policies,raw,_files=original_inputs(root,multiple=True)
    seen=capture(monkeypatch,present.PresencePack)
    stage=required.RequiredReportRun.read_presence
    read,write=store.FactReader.read,store.FactWriter.write
    calls,ops=[],[]
    def recording(self):
        seen["required"]=self
        return stage(self)
    def rows_for():
        live=seen["pack"].factory
        if phase=="source_reader":return live.original_rows
        if phase in ("positive_writer","presence_reader"):return live.original_presence_rows
        return seen["required"].rows
    def plant(handle,kw):
        ops.append(kw["subject"])
        if len(ops)!=1:return
        if fault in HANDLE_FAULTS:poison_handle(handle,fault,calls)
        elif fault=="value_class":poison_value_class(rows_for()[1].value,calls)
        else:
            rows=rows_for()
            if fault=="source_class" and phase=="required_writer":
                rows=seen["pack"].factory.original_presence_rows
            poison_data(rows,fault,calls)
    def reading(self,**kw):
        value=read(self,**kw)
        if phase=="source_reader" and self.step is present.STEP and kw["fact"]==state.REPORTED_STATE:plant(self,kw)
        elif phase=="presence_reader" and self.step is profile.STEP:plant(self,kw)
        return value
    def writing(self,**kw):
        value=write(self,**kw)
        if phase=="positive_writer" and kw["fact"]==present.FACT:plant(self,kw)
        elif phase=="required_writer" and kw["fact"]==profile.MISSING:plant(self,kw)
        return value
    monkeypatch.setattr(required.RequiredReportRun,"read_presence",recording)
    monkeypatch.setattr(store.FactReader,"read",reading)
    monkeypatch.setattr(store.FactWriter,"write",writing)
    step=present.STEP if phase in ("source_reader","positive_writer") else profile.STEP
    original_reads=step.reads
    try:
        with pytest.raises(ValueError):required.RequiredReportRun(root,replace(LIMITS),policies,raw)
    finally:
        object.__setattr__(step,"reads",original_reads)
    expected=1 if fault in HANDLE_FAULTS or fault=="value_class" else 2 if phase=="required_writer" else 6
    assert len(ops)==expected and calls==[]
