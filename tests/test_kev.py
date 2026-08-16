from src.collect.kev import parse_row


def test_parse_row_extracts_expected_fields():
    entry = {
        "cveID": "CVE-2024-0001",
        "vendorProject": "Acme",
        "product": "Widget",
        "vulnerabilityName": "Acme Widget RCE",
        "dateAdded": "2024-01-01",
        "shortDescription": "desc",
        "requiredAction": "Patch",
        "dueDate": "2024-01-15",
        "knownRansomwareCampaignUse": "Known",
        "notes": "irrelevant",
    }
    parsed = parse_row(entry)

    assert parsed == {
        "cve_id": "CVE-2024-0001",
        "vendor_project": "Acme",
        "product": "Widget",
        "vulnerability_name": "Acme Widget RCE",
        "date_added": "2024-01-01",
        "short_description": "desc",
        "required_action": "Patch",
        "due_date": "2024-01-15",
        "known_ransomware_campaign_use": "Known",
    }
