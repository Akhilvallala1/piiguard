"""Industry packs: what counts as PII depends on where you work. Each pack carries
  - people / pii_types / labels   -> the red team speaks the domain (generate_attacks --domain X)
  - prompt_addendum               -> the classifier is told the domain's identifiers
  - seed_rules                    -> precise, prefix-anchored starting rules (gen-0 of that domain); the coach evolves from here
  - preset                        -> a demo prompt with its ground-truth PII values, so the page grades against the domain, not itself
A generic detector has no recognizer for an adjuster badge, a medical record number, a routing number or a docket number."""
from __future__ import annotations

from ..pii.guard import Guard
from ..pii.rules import RuleSet

DOMAINS: dict[str, dict] = {
    "insurance": {
        "title": "Insurance claim",
        "people": [
            {"name": "Maria Chen", "adjuster_badge": "ADJ-48213-TX", "claim_number": "CLM-2026-0048213", "policy_number": "POL 88-4421-7730", "ssn": "912-34-5678", "phone": "555-010-1234"},
            {"name": "Devon Okafor", "adjuster_badge": "ADJ-50977-CA", "claim_number": "CLM-2026-0050977", "policy_number": "POL 31-9902-1184", "ssn": "923-45-6789", "phone": "(555) 010-2345"},
            {"name": "Priya Raman", "adjuster_badge": "ADJ-61205-NY", "claim_number": "CLM-2025-0961205", "policy_number": "POL 74-1130-6645", "ssn": "934-56-7890", "phone": "555.010.3456"},
            {"name": "Lucas Moreau", "adjuster_badge": "ADJ-73391-FL", "claim_number": "CLM-2026-0073391", "policy_number": "POL 19-7756-2208", "ssn": "945-67-8901", "phone": "+1 555-010-4567"},
            {"name": "Aisha Bello", "adjuster_badge": "ADJ-84460-WA", "claim_number": "CLM-2026-0084460", "policy_number": "POL 55-3307-9912", "ssn": "956-78-9012", "phone": "555-010-5678"},
            {"name": "Tomás Herrera", "adjuster_badge": "ADJ-90512-AZ", "claim_number": "CLM-2025-0890512", "policy_number": "POL 62-8841-0037", "ssn": "967-89-0123", "phone": "555 010 6789"},
        ],
        "pii_types": ["adjuster_badge", "claim_number", "policy_number", "ssn", "phone"],
        "labels": {"adjuster_badge": "adjuster badge", "claim_number": "claim number", "policy_number": "policy number", "ssn": "SSN", "phone": "phone"},
        "what_counts": "adjuster badge numbers, claim numbers, policy numbers, names, SSNs, phones",
        "prompt_addendum": "Domain: insurance. In this domain adjuster badge numbers (e.g. ADJ-48213-TX), claim numbers (CLM-2026-0048213) and policy numbers (POL 88-4421-7730) are PII and must be returned as spans, in addition to names, SSNs, phones and emails.",
        "seed_rules": [
            {"name": "adjuster_badge", "pattern": r"\bADJ-\d{5}-[A-Z]{2}\b"},
            {"name": "claim_number", "pattern": r"\bCLM-\d{4}-\d{7}\b"},
            {"name": "policy_number", "pattern": r"\bPOL \d{2}-\d{4}-\d{4}\b"},
        ],
        "preset": {"prompt": "Claim CLM-2026-0048213: adjuster badge ADJ-48213-TX approved policy POL 88-4421-7730 for Maria Chen, callback 555-010-1234. Summarize for the file.",
                   "expected": ["CLM-2026-0048213", "ADJ-48213-TX", "POL 88-4421-7730", "Maria Chen", "555-010-1234"],
                   "rules_catch": {"Maria Chen": False}},
    },
    "healthcare": {
        "title": "Healthcare",
        "people": [
            {"name": "Grace Kim", "mrn": "MRN 00482137", "npi": "NPI 1932847561", "member_id": "BCB-77Q-4421903", "dob": "12/25/1990", "phone": "(555) 010-7890"},
            {"name": "Samuel Adeyemi", "mrn": "MRN 00509771", "npi": "NPI 1467593820", "member_id": "AET-19K-8830114", "dob": "08/08/1972", "phone": "555-010-8901"},
            {"name": "Maria Chen", "mrn": "MRN 00612050", "npi": "NPI 1750384926", "member_id": "UHC-55M-2209876", "dob": "03/14/1988", "phone": "555-010-1234"},
            {"name": "Devon Okafor", "mrn": "MRN 00733915", "npi": "NPI 1083746295", "member_id": "CIG-42R-7731098", "dob": "11/02/1979", "phone": "(555) 010-2345"},
        ],
        "pii_types": ["mrn", "npi", "member_id", "dob", "phone"],
        "labels": {"mrn": "medical record number", "npi": "provider NPI", "member_id": "insurance member ID", "dob": "date of birth", "phone": "phone"},
        "what_counts": "medical record numbers, provider NPIs, insurance member IDs, dates of birth, diagnoses tied to a person",
        "prompt_addendum": "Domain: healthcare (HIPAA). Medical record numbers (MRN 00482137), provider NPIs (NPI 1932847561), insurance member IDs (BCB-77Q-4421903), dates of birth and any diagnosis tied to a named person are PHI and must be returned as spans, in addition to names, phones and emails.",
        "seed_rules": [
            {"name": "mrn", "pattern": r"\bMRN ?\d{8}\b"},
            {"name": "npi", "pattern": r"\bNPI ?\d{10}\b"},
            {"name": "member_id", "pattern": r"\b[A-Z]{3}-\d{2}[A-Z]-\d{7}\b"},
            {"name": "dob_slash", "pattern": r"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b"},
        ],
        "preset": {"prompt": "Patient Grace Kim, MRN 00482137, DOB 12/25/1990, member BCB-77Q-4421903, seen by Dr. Patel NPI 1932847561 for type 2 diabetes follow-up. Draft the discharge note.",
                   "expected": ["Grace Kim", "MRN 00482137", "12/25/1990", "BCB-77Q-4421903", "NPI 1932847561"],
                   "rules_catch": {"Grace Kim": False}},
    },
    "finance": {
        "title": "Finance",
        "people": [
            {"name": "Lucas Moreau", "account": "ACCT 4471-9920-3318", "routing": "routing 021000021", "iban": "GB29 NWBK 6016 1331 9268 19", "ssn": "945-67-8901", "credit_card": "4111 1111 1111 1111"},
            {"name": "Aisha Bello", "account": "ACCT 8830-1140-7765", "routing": "routing 026009593", "iban": "DE89 3704 0044 0532 0130 00", "ssn": "956-78-9012", "credit_card": "5555 5555 5555 4444"},
            {"name": "Priya Raman", "account": "ACCT 2209-8761-5540", "routing": "routing 121000248", "iban": "FR14 2004 1010 0505 0001 3M02 606", "ssn": "934-56-7890", "credit_card": "3782 822463 10005"},
        ],
        "pii_types": ["account", "routing", "iban", "ssn", "credit_card"],
        "labels": {"account": "account number", "routing": "routing number", "iban": "IBAN", "ssn": "SSN", "credit_card": "card number"},
        "what_counts": "account numbers, routing numbers, IBANs, card numbers, SSNs, balances tied to a person",
        "prompt_addendum": "Domain: finance. Account numbers (ACCT 4471-9920-3318), ABA routing numbers (routing 021000021), IBANs (GB29 NWBK 6016 1331 9268 19), card numbers and SSNs are PII and must be returned as spans, in addition to names, phones and emails.",
        "seed_rules": [
            {"name": "account_number", "pattern": r"\bACCT \d{4}-\d{4}-\d{4}\b"},
            {"name": "routing_number", "pattern": r"\b(?:routing|ABA) ?\d{9}\b", "ignore_case": True},
            {"name": "iban", "pattern": r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b"},
        ],
        "preset": {"prompt": "Wire request from Lucas Moreau: debit ACCT 4471-9920-3318, routing 021000021, to IBAN GB29 NWBK 6016 1331 9268 19. Verify against SSN 945-67-8901 and confirm.",
                   "expected": ["Lucas Moreau", "ACCT 4471-9920-3318", "routing 021000021", "GB29 NWBK 6016 1331 9268 19", "945-67-8901"],
                   "rules_catch": {"Lucas Moreau": False}},
    },
    "legal": {
        "title": "Law firm",
        "people": [
            {"name": "Tomás Herrera", "docket": "Case No. 2:26-cv-04821", "matter": "Matter 2026-0417-HER", "bar_number": "Bar No. 284913", "ssn": "967-89-0123", "email": "tomas.h@example.com"},
            {"name": "Grace Kim", "docket": "Case No. 1:25-cr-00977", "matter": "Matter 2025-1188-KIM", "bar_number": "Bar No. 301552", "ssn": "978-90-1234", "email": "grace.kim@example.org"},
            {"name": "Samuel Adeyemi", "docket": "Case No. 3:26-cv-01205", "matter": "Matter 2026-0033-ADE", "bar_number": "Bar No. 177204", "ssn": "989-01-2345", "email": "sam.adeyemi@example.net"},
        ],
        "pii_types": ["docket", "matter", "bar_number", "ssn", "email"],
        "labels": {"docket": "docket number", "matter": "client matter number", "bar_number": "bar number", "ssn": "SSN", "email": "email"},
        "what_counts": "client names, docket numbers, client-matter numbers, bar numbers, privileged facts tied to a client",
        "prompt_addendum": "Domain: law firm (privilege). Client names, docket numbers (Case No. 2:26-cv-04821), client-matter numbers (Matter 2026-0417-HER) and attorney bar numbers (Bar No. 284913) identify a client or a matter and must be returned as spans, in addition to SSNs, phones and emails.",
        "seed_rules": [
            {"name": "docket_number", "pattern": r"\b(?:Case No\. )?\d:\d{2}-(?:cv|cr|bk|mc)-\d{5}\b"},
            {"name": "matter_number", "pattern": r"\bMatter \d{4}-\d{4}-[A-Z]{3}\b"},
            {"name": "bar_number", "pattern": r"\bBar No\. \d{6}\b"},
        ],
        "preset": {"prompt": "Privileged: client Tomás Herrera, Case No. 2:26-cv-04821, Matter 2026-0417-HER. Opposing counsel Bar No. 284913 requested the deposition transcript; client email tomas.h@example.com. Draft the response.",
                   "expected": ["Tomás Herrera", "2:26-cv-04821", "Matter 2026-0417-HER", "Bar No. 284913", "tomas.h@example.com"],
                   "rules_catch": {"Tomás Herrera": False}},
    },
}


def domain_guard(base: Guard, domain: str | None) -> Guard:
    """The base guard plus the domain's seed rules and prompt addendum. The classifier is shared."""
    if not domain or domain not in DOMAINS:
        return base
    d = DOMAINS[domain]
    from ..coach.retrospective import rules_to_yaml
    import yaml
    existing = yaml.safe_load(base.rules.source)["rules"] if base.rules.source else [{"name": r.name, "pattern": r.pattern, "validator": r.validator} for r in base.rules.rules]
    names = {r["name"] for r in existing}
    merged = existing + [r for r in d["seed_rules"] if r["name"] not in names]
    rules = RuleSet.from_yaml_text(rules_to_yaml(merged, base.rules.version))
    return Guard(rules, (base.prompt.rstrip() + "\n\n" + d["prompt_addendum"]), base.classifier)
