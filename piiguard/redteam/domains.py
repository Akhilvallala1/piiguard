"""Industry packs: identifiers that are PII inside one industry and noise everywhere else.
A generic detector has no recognizer for an adjuster badge; a red team that speaks the domain teaches the guard."""

INSURANCE_PEOPLE = [
    {"name": "Maria Chen", "adjuster_badge": "ADJ-48213-TX", "claim_number": "CLM-2026-0048213", "policy_number": "POL 88-4421-7730", "ssn": "912-34-5678", "phone": "555-010-1234"},
    {"name": "Devon Okafor", "adjuster_badge": "ADJ-50977-CA", "claim_number": "CLM-2026-0050977", "policy_number": "POL 31-9902-1184", "ssn": "923-45-6789", "phone": "(555) 010-2345"},
    {"name": "Priya Raman", "adjuster_badge": "ADJ-61205-NY", "claim_number": "CLM-2025-0961205", "policy_number": "POL 74-1130-6645", "ssn": "934-56-7890", "phone": "555.010.3456"},
    {"name": "Lucas Moreau", "adjuster_badge": "ADJ-73391-FL", "claim_number": "CLM-2026-0073391", "policy_number": "POL 19-7756-2208", "ssn": "945-67-8901", "phone": "+1 555-010-4567"},
    {"name": "Aisha Bello", "adjuster_badge": "ADJ-84460-WA", "claim_number": "CLM-2026-0084460", "policy_number": "POL 55-3307-9912", "ssn": "956-78-9012", "phone": "555-010-5678"},
    {"name": "Tomás Herrera", "adjuster_badge": "ADJ-90512-AZ", "claim_number": "CLM-2025-0890512", "policy_number": "POL 62-8841-0037", "ssn": "967-89-0123", "phone": "555 010 6789"},
]

DOMAINS = {
    "insurance": {
        "people": INSURANCE_PEOPLE,
        "pii_types": ["adjuster_badge", "claim_number", "policy_number", "ssn", "phone"],
        "labels": {"adjuster_badge": "adjuster badge", "claim_number": "claim number", "policy_number": "policy number", "ssn": "SSN", "phone": "phone"},
    }
}
