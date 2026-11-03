"""Regression guards for the P0 import/migration work."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_no_legacy_package_imports():
    """The old ``xoxss_modules`` / ``xoxss_advanced`` paths must never return."""
    files = [ROOT / "xoxss.py"] + sorted((ROOT / "xoxss").rglob("*.py"))
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert "xoxss_modules" not in text, path
        assert "xoxss_advanced" not in text, path


def test_entry_points_resolve():
    import xoxss
    from xoxss.scanner import main

    assert callable(main)
    assert callable(xoxss.main)
    assert xoxss.__version__


def test_root_entry_point_is_thin():
    """xoxss.py is a compatibility shim, not the implementation."""
    lines = (ROOT / "xoxss.py").read_text(encoding="utf-8").splitlines()
    assert len([line for line in lines if line.strip()]) < 25
    assert "xoxss.scanner" in "\n".join(lines)


def test_advanced_modules_import():
    """Every analysis module imported by the scanner must exist."""
    from xoxss.analysis import cors, csp, jsonp, mxss, per_char, polyglot
    from xoxss.analysis import proto_pollution, rate_limit
    from xoxss.analysis import dom_clobbering, trusted_types, graphql, websocket
    from xoxss.analysis import file_upload, postmessage

    assert all(
        module is not None
        for module in (
            cors,
            csp,
            jsonp,
            mxss,
            per_char,
            polyglot,
            proto_pollution,
            rate_limit,
            dom_clobbering,
            trusted_types,
            graphql,
            websocket,
            file_upload,
            postmessage,
        )
    )
