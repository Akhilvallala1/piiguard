from piiguard.redteam.generator import generate_attacks, split_dataset, SEED_PEOPLE

def test_offline_attacks_embed_exact_surface_forms_in_text():
    attacks = generate_attacks(n=40, seed=7, carrier_fn=None)
    assert len(attacks) == 40
    for a in attacks:
        assert a["surface_forms"], a
        assert all(sf in a["text"] for sf in a["surface_forms"]), a
        assert a["technique"] and a["pii_type"] and a["id"]

def test_offline_generation_is_deterministic_for_same_seed():
    assert generate_attacks(n=10, seed=1) == generate_attacks(n=10, seed=1)
    assert generate_attacks(n=10, seed=1) != generate_attacks(n=10, seed=2)

def test_split_is_disjoint_and_covers_all():
    attacks = generate_attacks(n=50, seed=3)
    train, val, heldout = split_dataset(attacks, ratios=(0.6, 0.2, 0.2), seed=0)
    ids = [a["id"] for a in train + val + heldout]
    assert len(ids) == 50 and len(set(ids)) == 50
    assert len(heldout) == 10

def test_seed_people_are_synthetic_with_required_fields():
    for p in SEED_PEOPLE:
        assert {"name", "ssn", "email", "phone", "credit_card", "dob"} <= set(p)


def test_domain_pack_generates_attacks_with_domain_pii_types():
    from piiguard.redteam.domains import DOMAINS
    from piiguard.redteam.generator import generate_attacks
    ins = DOMAINS["insurance"]
    attacks = generate_attacks(n=30, seed=3, people=ins["people"], pii_types=ins["pii_types"], labels=ins["labels"])
    types = {a["pii_type"] for a in attacks}
    assert "adjuster_badge" in types and "claim_number" in types
    assert all(all(sf in a["text"] for sf in a["surface_forms"]) for a in attacks)
