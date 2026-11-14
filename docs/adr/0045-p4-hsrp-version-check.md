# ADR-0045: Conditional reported HSRP version comparison

Status: proposed (design only; separate named Lead merge decision required).

The trusted owning checker reads only registered protocol VERSION facts through its declared Reader.
It validates every original source subject and the whole owning Store before any finding, including empty policies and unselected cells.
The logical key remains envelope/domain/VLAN/AF/protocol/group. Version and VIP are operands, never keys.
Missing domain or Unknown binding prevents joining, including when supplied version values differ.
Only plain reported version tokens 1 and 2 are admitted as Known operands. For a joined group, two distinct Known versions yield a conditional reported difference even with additional Unknown operands; every operand and gap need remains visible.
Otherwise the canonical first binding/operand Unknown remains exact. A singleton Known operand stays NOT_OBSERVABLE; equal untimed Known reports stay AS_OF_MISSING.
VERSION collection needs use show standby all and the VERSION fact. Original missing-domain declaration needs are retained, not relabeled as ALL capture proof.
Original declared participants, denominator and coverage uncertainty remain unchanged; no healthy, absence, redundancy or contemporaneous-fault inference is added.

The lower checker trusts owning Source and policy closure; typed Store/plan/result objects are not admission or origin seals.
A fresh root/budgets/policies wrapper and proof expansion require separate slices and qualification.
No legacy/Root/VIP behavior, platform/train floor, full P4/M1/field or P5 acceptance is amended.
