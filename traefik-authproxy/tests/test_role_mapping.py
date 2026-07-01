import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from traefik_authproxy import load_role_mappings


def _write(p, content):
    p.write_text(content, encoding="utf-8")


def test_missing_sources_graceful():
    protected, public = load_role_mappings("", "")
    assert protected == {}
    assert public == []


def test_single_file(tmp_path):
    f = tmp_path / "base.yaml"
    _write(f, "/health: []\n/api/v1/x:\n  - admin-role\n")
    protected, public = load_role_mappings(str(f), "")
    assert protected == {"/api/v1/x": ["admin-role"]}
    assert public == ["/health"]


def test_dir_merge(tmp_path):
    d = tmp_path / "fragments"
    d.mkdir()
    _write(d / "auditflow.yaml", "/auditflow/api:\n  - auditflow-role\n/auditflow/v3/api-docs: []\n")
    _write(d / "checkout.yaml", "/checkout/api:\n  - ecommerce-role\n")
    protected, public = load_role_mappings("", str(d))
    assert protected == {
        "/auditflow/api": ["auditflow-role"],
        "/checkout/api": ["ecommerce-role"],
    }
    assert public == ["/auditflow/v3/api-docs"]


def test_file_plus_dir_dir_overrides(tmp_path):
    f = tmp_path / "base.yaml"
    _write(f, "/health: []\n/auditflow/api:\n  - old-role\n")
    d = tmp_path / "fragments"
    d.mkdir()
    _write(d / "auditflow.yaml", "/auditflow/api:\n  - new-role\n")
    protected, public = load_role_mappings(str(f), str(d))
    assert protected == {"/auditflow/api": ["new-role"]}
    assert public == ["/health"]


def test_invalid_fragment_skipped(tmp_path):
    d = tmp_path / "fragments"
    d.mkdir()
    _write(d / "bad.yaml", "- just\n- a\n- list\n")
    _write(d / "good.yaml", "/api:\n  - some-role\n")
    protected, public = load_role_mappings("", str(d))
    assert protected == {"/api": ["some-role"]}
    assert public == []
