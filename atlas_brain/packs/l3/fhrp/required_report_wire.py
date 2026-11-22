"""Four fixed canonical files from owned DTOs; bounded formatting, not proof admission."""
from hashlib import sha256
from typing import cast

from atlas_brain.contract.bundle import result_bundle
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k

NAMES=("result.json","facts/fhrp_local.jsonl","facts/fhrp_requirement.jsonl","MANIFEST.sha256")
type Rows = dict[tuple[str,str],dict[str,object]]


def _bounded(size: int,limit: int) -> int:
    if size>limit:raise BudgetExceeded("required_report_outputs")
    return size


def _size(value: object,limit: int,depth: int=0) -> int:
    """Count the canonical integer-only encoding without allocation; depth is at most 64."""
    if depth>64:raise BudgetExceeded("required_report_outputs")
    kind=type(value)
    if value is None:size=4
    elif kind is bool:size=4 if value else 5
    elif kind is int:
        integer=cast(int,value)
        k.require(-9007199254740991<=integer<=9007199254740991,"integer_out_of_range")
        size=len(str(integer))
    elif kind is str:
        string=cast(str,value)
        _bounded(len(string)+2,limit)
        size=2
        for char in string:
            code=ord(char)
            k.require(not 0xD800<=code<=0xDFFF,"non_unicode_scalar")
            width=(2 if char in '"\\\b\f\n\r\t' else 6 if code<32 else
                1 if code<128 else 2 if code<2048 else 3 if code<65536 else 4)
            size=_bounded(size+width,limit)
    elif kind is dict:
        entries=cast(dict[object,object],value)
        size=_bounded(2+max(0,len(entries)-1),limit)
        for key,item in entries.items():
            k.require(type(key) is str,"required_report_wire")
            size+=_size(key,limit-size,depth+1)+1
            size+=_size(item,limit-size,depth+1)
    elif kind is list or kind is tuple:
        items=cast(list[object] | tuple[object,...],value)
        size=_bounded(2+max(0,len(items)-1),limit)
        for item in items:size+=_size(item,limit-size,depth+1)
    else:raise TypeError("non_json_type")
    return _bounded(size,limit)


class WireBudget:
    def __init__(self,inputs: tuple[bytes,...],limits: tuple[int,int,int]) -> None:
        k.require(type(inputs) is tuple and type(limits) is tuple and len(limits)==3
            and all(type(limit) is int and limit>0 for limit in limits),"required_report_wire")
        if len(inputs)+len(NAMES)>limits[2]:raise BudgetExceeded("required_report_outputs")
        self.limits,self.input_bytes=limits,0
        self.sizes={name:0 for name in NAMES}
        for raw in inputs:
            k.require(type(raw) is bytes,"required_report_wire")
            _bounded(len(raw),limits[1])
            self.input_bytes=_bounded(self.input_bytes+len(raw),limits[0])
        WireBudget.add(self,"MANIFEST.sha256",sum(67+len(name) for name in NAMES if name!="MANIFEST.sha256"))

    def room(self,name: str) -> int:
        return min(self.limits[1]-self.sizes[name],self.limits[0]-self.input_bytes-sum(self.sizes.values()))

    def add(self,name: str,count: int) -> None:
        k.require(type(count) is int and count>=0,"required_report_wire")
        self.sizes[name]+=_bounded(count,WireBudget.room(self,name))


def _reserve(row: dict[str,object],budget: WireBudget,index: int,payload: tuple[str,bytes] | None=None) -> None:
    k.require(type(row) is dict,"required_report_wire")
    room=WireBudget.room(budget,"result.json")
    size=_size(row,room)
    if payload is not None:
        name,raw=payload
        k.require(type(raw) is bytes and name not in row,"required_report_wire")
        size+=_size(name,room)+3+2*len(raw)+int(bool(row))
    WireBudget.add(budget,"result.json",size+int(index>0))


def _rows(rows: Rows,budget: WireBudget,name: str) -> None:
    k.require(type(rows) is dict,"required_report_wire")
    _bounded(3*len(rows),WireBudget.room(budget,name))
    for key,row in rows.items():
        k.require(type(key) is tuple and len(key)==2 and all(type(part) is str for part in key)
            and type(row) is dict,"required_report_wire")
        size=_size(row,WireBudget.room(budget,name)-1)
        k.require(type(row.get("subject")) is str and type(row.get("fact")) is str
            and key==(row["subject"],row["fact"]),"required_report_wire")
        WireBudget.add(budget,name,size+1)


def render(header: dict[str,object],inputs: tuple[bytes,...],limits: tuple[int,int,int],
    captures: tuple[dict[str,object],...],registry: tuple[tuple[dict[str,object],bytes],...],
    local: Rows,requirements: Rows,
) -> dict[str,bytes]:
    """Preflight depth, exact bytes and row-key binding before canonical or HEX allocation."""
    budget=WireBudget(inputs,limits)
    k.require(type(header) is dict and type(captures) is tuple and type(registry) is tuple,"required_report_wire")
    _size(header,WireBudget.room(budget,"result.json"))
    k.require(not any(key in header for key in ("raws","captures","registry_records")),"required_report_wire")
    result: dict[str,object]={**header,"raws":[],"captures":[],"registry_records":[]}
    WireBudget.add(budget,"result.json",_size(result,WireBudget.room(budget,"result.json")))
    _bounded(2*(len(captures)+len(registry)),WireBudget.room(budget,"result.json"))
    for index,record in enumerate(captures):_reserve(record,budget,index)
    for index,entry in enumerate(registry):
        k.require(type(entry) is tuple and len(entry)==2 and type(entry[1]) is bytes,"required_report_wire")
        _reserve(entry[0],budget,index,("canonical",entry[1]))
    _rows(local,budget,"facts/fhrp_local.jsonl")
    _rows(requirements,budget,"facts/fhrp_requirement.jsonl")
    blobs: dict[str,bytes]={}
    for raw in inputs:
        digest=sha256(raw).hexdigest()
        k.require(digest not in blobs or blobs[digest]==raw,"required_report_wire")
        blobs[digest]=raw
    raw_records: list[tuple[dict[str,object],bytes]]=[({"sha256":digest,"bytes":len(raw),"encoding":"hex"},raw)
        for digest,raw in sorted(blobs.items())]
    for index,(record,raw) in enumerate(raw_records):_reserve(record,budget,index,("data",raw))
    result.update(raws=[{**record,"data":raw.hex()} for record,raw in raw_records],
        captures=[dict(record) for record in captures],
        registry_records=[{**record,"canonical":fragment.hex()} for record,fragment in registry])
    files=result_bundle(result,facts={"fhrp_local":local,"fhrp_requirement":requirements},checks={})
    k.require(set(files)==set(NAMES) and all(type(raw) is bytes and len(raw)==budget.sizes[name]
        for name,raw in files.items()),"required_report_wire")
    return files
