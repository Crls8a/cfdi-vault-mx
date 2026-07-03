from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_local_installer_alpha_docs_and_script_cover_offline_first_use() -> None:
    guide = (REPO_ROOT / "docs" / "installer" / "local-installer-alpha.md").read_text(encoding="utf-8")
    script = (REPO_ROOT / "scripts" / "bootstrap_local.ps1").read_text(encoding="utf-8")

    for expected in (
        'pip install -e ".[dev]"',
        "cfdi-vault --help",
        "cfdi-vault setup --help",
        "cfdi-vault doctor --help",
        "cfdi-vault download plan",
        "cfdi-vault download request",
        "cfdi-vault download sync",
        "cfdi-vault download status",
        "SAT real is not executed",
    ):
        assert expected in guide

    for expected in (
        "CFDI_VAULT_ALLOW_REAL_SAT",
        "CFDI_VAULT_ALLOW_REAL_CREDENTIALS",
        "download plan",
        "download request",
        "download sync",
        "download status",
        "Live SAT was not executed",
    ):
        assert expected in script
