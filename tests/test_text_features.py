from src.features.text_features import has_exploit_keyword, vendor_category


def test_has_exploit_keyword_true_cases():
    assert has_exploit_keyword("A remote code execution vulnerability.")
    assert has_exploit_keyword("This is a zero-day flaw.")
    assert has_exploit_keyword("An RCE was found.")


def test_has_exploit_keyword_false_case():
    assert not has_exploit_keyword("A denial of service issue.")
    assert not has_exploit_keyword(None)


def test_vendor_category_matches_first_hit():
    assert vendor_category("A vulnerability in the Windows kernel.") == "os"
    assert vendor_category("A WordPress plugin allows SQL injection.") == "web"
    assert vendor_category("Cisco router firmware issue.") == "network"


def test_vendor_category_defaults_to_other():
    assert vendor_category("Some generic software issue.") == "other"
    assert vendor_category(None) == "other"
