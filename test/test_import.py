"""Smoke tests for the pytun extension module."""


def test_import():
    import pytun

    assert pytun.__file__ is not None


def test_tun_tap_constants():
    import pytun

    assert hasattr(pytun, "IFF_TUN")
    assert hasattr(pytun, "IFF_TAP")
