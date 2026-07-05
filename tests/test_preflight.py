"""Dependency preflight + --install-opt. All deterministic (availability and pip
are monkeypatched); nothing here installs anything or hits the network.
"""
import types

import pytest


def _args(**kw):
    base = dict(per_day=False, validate=None, tsa=None, gpg=None, gpg_k=None,
                ssh=None, ssh_fido=None, install_opt=False)
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_no_capabilities_when_nothing_requested(tool):
    assert tool._required_capabilities(_args()) == []


def test_per_day_requires_yaml(tool, monkeypatch):
    monkeypatch.setattr(tool, "_module_available", lambda n: False)
    caps = tool._required_capabilities(_args(per_day=True))
    assert len(caps) == 1 and caps[0].pip_pkgs == ("pyyaml",) and not caps[0].ok


def test_tsa_satisfied_by_openssl_or_lib(tool, monkeypatch):
    monkeypatch.setattr(tool, "_module_available", lambda n: False)
    monkeypatch.setattr(tool, "openssl_available", lambda: True)
    assert tool._required_capabilities(_args(tsa="digicert"))[0].ok        # openssl
    monkeypatch.setattr(tool, "openssl_available", lambda: False)
    monkeypatch.setattr(tool, "_module_available", lambda n: n == "rfc3161ng")
    assert tool._required_capabilities(_args(tsa="digicert"))[0].ok        # lib


def test_preflight_pip_missing_prints_and_exits(tool, monkeypatch, capsys):
    monkeypatch.setattr(tool, "_module_available", lambda n: False)        # no jsonschema
    with pytest.raises(SystemExit) as e:
        tool.preflight_dependencies(_args(validate="x"))
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert "pip install jsonschema" in err and "--install-opt" in err


def test_preflight_external_missing_exits_with_reason(tool, monkeypatch, capsys):
    monkeypatch.setattr(tool, "gpg_available", lambda: False)
    with pytest.raises(SystemExit) as e:
        tool.preflight_dependencies(_args(gpg="FPR"))
    assert e.value.code == 2
    assert "GPG" in capsys.readouterr().err


def test_preflight_tsa_missing_is_pip_installable_not_hard_exit(tool, monkeypatch, capsys):
    # Neither openssl nor the lib: should offer the pip install, NOT treat it as
    # an uninstallable external tool.
    monkeypatch.setattr(tool, "openssl_available", lambda: False)
    monkeypatch.setattr(tool, "_module_available", lambda n: False)
    with pytest.raises(SystemExit):
        tool.preflight_dependencies(_args(tsa="digicert"))
    err = capsys.readouterr().err
    assert "pip install rfc3161ng" in err and "--install-opt" in err


def test_preflight_install_opt_runs_pip_then_stops(tool, monkeypatch):
    monkeypatch.setattr(tool, "_module_available", lambda n: False)
    got = {}
    monkeypatch.setattr(tool, "_pip_install", lambda pkgs: got.update(pkgs=pkgs) or True)
    with pytest.raises(SystemExit) as e:
        tool.preflight_dependencies(_args(validate="x", install_opt=True))
    assert e.value.code == 0                     # installed -> re-run, don't proceed
    assert got["pkgs"] == ["jsonschema"]


def test_install_all_optional_installs_only_missing(tool, monkeypatch):
    monkeypatch.setattr(tool, "_module_available", lambda n: n == "yaml")   # only yaml present
    got = {}
    monkeypatch.setattr(tool, "_pip_install", lambda pkgs: got.update(pkgs=pkgs) or True)
    tool.install_all_optional()
    assert "pyyaml" not in got["pkgs"] and "jsonschema" in got["pkgs"] and "rfc3161ng" in got["pkgs"]
