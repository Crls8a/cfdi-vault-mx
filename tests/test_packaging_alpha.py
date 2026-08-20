from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_local_installer_alpha_docs_and_script_cover_offline_first_use() -> None:
    guide = (REPO_ROOT / "docs" / "installer" / "local-installer-alpha.md").read_text(encoding="utf-8")
    script = (REPO_ROOT / "scripts" / "bootstrap_local.ps1").read_text(encoding="utf-8")

    for expected in (
        'pip install -e ".[dev,webapi]"',
        "cfdi_vault.adapters.webapi.app",
        "POST /api/setup",
        "GET /api/profile/{profile_id}/status",
        "GET /api/system/doctor",
        "SAT real is not executed",
    ):
        assert expected in guide

    for expected in (
        "CFDI_VAULT_ALLOW_REAL_SAT",
        "CFDI_VAULT_ALLOW_REAL_CREDENTIALS",
        "Validate installed package imports",
        "Live SAT was not executed",
    ):
        assert expected in script

    # The retired CLI binary and its fake/offline download pipeline must not
    # reappear as a runnable step by accident. The temp-folder name
    # legitimately contains "cfdi-vault-local-alpha-" (a naming prefix, not an
    # invocation), and the guide's safety-boundaries section legitimately
    # mentions "download plan" in prose explaining why it was retired, so this
    # checks for an actual command invocation rather than the bare phrase.
    assert "cfdi-vault.exe" not in script
    assert "cfdi-vault --" not in script
    assert "cfdi-vault download" not in script
    assert "cfdi-vault download plan" not in guide
