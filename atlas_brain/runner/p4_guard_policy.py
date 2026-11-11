"""Trusted fixed three-pack composition for caller-declared STP guard-policy plans."""
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l2.etherchannel import build as etherchannel
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l2.stp import guard_policy as policy
from atlas_brain.packs.l3.fhrp import build as fhrp


def plan_guard_comparisons(envelope: p4.Envelope, budgets: Budgets,
                           policies: tuple[policy.GuardPolicy, ...]) -> policy.GuardPlan:
    if type(envelope) is not p4.Envelope:
        raise ValueError("stp_guard_policy_envelope")
    compiled = compile_packs((stp.DECLARATION, etherchannel.DECLARATION, fhrp.DECLARATION))
    if envelope.registration_sha256 != compiled.registration_sha256:
        raise ValueError("stp_guard_policy_profile")
    owners = {binding.operation: binding.step for binding in compiled.operations}
    if (type(envelope.targets) is not tuple or not all(type(target) is p4.Target and target.operation in owners
            and target.owner == owners[target.operation] for target in envelope.targets)):
        raise ValueError("stp_guard_policy_profile")
    return policy.plan_for_declared_scope(envelope, budgets, policies)
