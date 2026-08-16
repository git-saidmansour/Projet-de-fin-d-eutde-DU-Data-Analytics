from src.features.cwe_mapping import categorize_cwe


def test_categorize_known_cwe():
    assert categorize_cwe("CWE-79") == "injection"
    assert categorize_cwe("CWE-787") == "memory"


def test_categorize_uses_first_recognized_cwe():
    assert categorize_cwe("CWE-9999,CWE-89") == "injection"


def test_categorize_unknown_cwe_returns_other():
    assert categorize_cwe("CWE-9999") == "other"


def test_categorize_empty_returns_none():
    assert categorize_cwe("") == "none"
    assert categorize_cwe(None) == "none"
