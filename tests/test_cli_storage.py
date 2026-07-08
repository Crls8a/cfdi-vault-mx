from typer.testing import CliRunner

from cfdi_vault.cli import app


def test_doctor_uses_cfdi_storage_root_when_storage_option_is_omitted(tmp_path, reset_postgres_database: str) -> None:
    env_storage = tmp_path / "env-storage-root"

    result = CliRunner().invoke(
        app,
        ["doctor"],
        env={"CFDI_STORAGE_ROOT": str(env_storage), "DATABASE_URL": reset_postgres_database},
    )

    assert result.exit_code == 0
    assert f"OK storage: {env_storage}" in result.output
    assert env_storage.is_dir()


def test_doctor_storage_option_overrides_cfdi_storage_root(tmp_path, reset_postgres_database: str) -> None:
    env_storage = tmp_path / "env-storage-root"
    option_storage = tmp_path / "option-storage-root"

    result = CliRunner().invoke(
        app,
        ["doctor", "--storage", str(option_storage)],
        env={"CFDI_STORAGE_ROOT": str(env_storage), "DATABASE_URL": reset_postgres_database},
    )

    assert result.exit_code == 0
    assert f"OK storage: {option_storage}" in result.output
    assert option_storage.is_dir()
    assert not env_storage.exists()
