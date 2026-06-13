from mojodns.config import Settings


def test_primary_only():
    s = Settings(tsig_key="aksinet-xfr", tsig_extra_keys="")
    assert s.tsig_key_names == ["aksinet-xfr"]


def test_primary_plus_extras():
    s = Settings(tsig_key="aksinet-xfr", tsig_extra_keys="he-xfr, partner-xfr")
    assert s.tsig_key_names == ["aksinet-xfr", "he-xfr", "partner-xfr"]


def test_dedup_and_empty():
    s = Settings(tsig_key="aksinet-xfr", tsig_extra_keys="aksinet-xfr,he-xfr")
    assert s.tsig_key_names == ["aksinet-xfr", "he-xfr"]
    assert Settings(tsig_key="", tsig_extra_keys="").tsig_key_names == []
