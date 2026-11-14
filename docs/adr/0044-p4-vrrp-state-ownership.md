# ADR-0044: Distinct reported VRRP state ownership

Status: proposed (design only); separate named Lead merge decision required.

The synthetic profile owns l3.fhrp.reported_vrrp_state via l3.fhrp/parse_vrrp and
iosxe.show_vrrp under existing l3.fhrp/fhrp_local ownership, never the HSRP fact/step.
Local subjects use atlas-brain.vrrp-local/1, declared context, original node,
exact interface, IPv4, protocol vrrp and group; VIP/version remain operands.
Only synthetic groups 100/101 are admitted; no numeric/platform floor or version inference.
Compilation and immutable input snapshots are comparison data, never admission or origin.
Later units must close actual parser/cache/registration/receipts/raw claims,
independent declared census and canonical Store/Reader/evidence values before positive facts.
Absent/partial/error/unmodelled inputs remain Unknown with actual witnesses/needs;
empty captures never establish healthy absence or a redundancy baseline.
VRRP-only is intermediate: final P4 still requires HSRP/VRRP coexistence.
Duplicate pack IDs are refused; later use one new literal combined FHRP declaration
and trusted composite, never two l3.fhrp declarations or widened old profiles/defaults.
Accepted P0-P3 bytes stay fixed. No producer/factory/comparison/anycast, EX-02/full P4/M1/field acceptance or P5 qualification is established here.
