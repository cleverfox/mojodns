from mojodns.pdns import canonical, is_custom_zone

CAT = "catalog.aksinet.net."


def test_catalog_member_is_not_custom():
    z = {"name": "example.com.", "kind": "Master", "catalog": "catalog.aksinet.net."}
    assert is_custom_zone(z, CAT) is False


def test_producer_is_not_custom():
    z = {"name": "catalog.aksinet.net.", "kind": "Producer", "catalog": ""}
    assert is_custom_zone(z, CAT) is False


def test_empty_catalog_master_is_custom():
    z = {"name": "private.example.", "kind": "Master", "catalog": ""}
    assert is_custom_zone(z, CAT) is True
    # None catalog also counts as custom
    assert is_custom_zone({"name": "p.example.", "kind": "Master", "catalog": None}, CAT) is True


def test_catalog_zone_by_name_not_custom_even_without_kind():
    # the configured catalog zone itself is never "custom"
    z = {"name": "catalog.aksinet.net.", "kind": "Master", "catalog": ""}
    assert is_custom_zone(z, CAT) is False


def test_per_zone_keys_exclude_primary():
    # mirrors the zone_view logic: per-zone keys = master_tsig_key_ids - primary
    primary = canonical("aksinet-xfr")
    ids = ["aksinet-xfr.", "he-xfr.aksinet.net.", "private.example."]
    per_zone = [k.rstrip(".") for k in ids if k != primary]
    assert per_zone == ["he-xfr.aksinet.net", "private.example"]
