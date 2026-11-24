from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from filevow.cli.main import app
from filevow.services.context import AppContext

runner = CliRunner()
PASSPHRASE = "a long test passphrase"


def invoke(ctx: AppContext, *args: str, input_text: str | None = None):  # type: ignore[no-untyped-def]
    return runner.invoke(app, list(args), obj=ctx, input=input_text)


def test_full_cli_workflow(ctx: AppContext, site: Path, tmp_path: Path) -> None:
    key_path = tmp_path / "usb" / "baseline.pem"

    result = invoke(ctx, "init")
    assert result.exit_code == 0, result.output

    result = invoke(ctx, "keygen", "--out", str(key_path), input_text=f"{PASSPHRASE}\n{PASSPHRASE}\n")
    assert result.exit_code == 0, result.output
    assert key_path.exists() and b"ENCRYPTED PRIVATE KEY" in key_path.read_bytes()

    result = invoke(ctx, "path", "add", str(site), "--exclude", "*.log")
    assert result.exit_code == 0, result.output

    result = invoke(ctx, "baseline", "--key", str(key_path), input_text=f"{PASSPHRASE}\n")
    assert result.exit_code == 0, result.output
    assert "3 signed" in result.output

    result = invoke(ctx, "verify")
    assert result.exit_code == 0, result.output

    (site / "index.html").write_text("<h1>Hacked</h1>", encoding="utf-8")
    result = invoke(ctx, "verify")
    assert result.exit_code == 2
    assert "FILE_MODIFIED" in result.output

    result = invoke(ctx, "audit", "verify")
    assert result.exit_code == 0, result.output
    assert "intact" in result.output


def test_keygen_refuses_short_passphrase(ctx: AppContext, tmp_path: Path) -> None:
    result = invoke(ctx, "keygen", "--out", str(tmp_path / "k.pem"), input_text="short\nshort\n")
    assert result.exit_code == 1
    assert not (tmp_path / "k.pem").exists()


def test_baseline_with_wrong_passphrase_fails(ctx: AppContext, site: Path, tmp_path: Path) -> None:
    key_path = tmp_path / "k.pem"
    invoke(ctx, "keygen", "--out", str(key_path), input_text=f"{PASSPHRASE}\n{PASSPHRASE}\n")
    invoke(ctx, "path", "add", str(site))
    result = invoke(ctx, "baseline", "--key", str(key_path), input_text="not the passphrase\n")
    assert result.exit_code == 1
    assert "could not unlock" in result.output


def test_vault_folder_cannot_be_monitored(ctx: AppContext) -> None:
    result = invoke(ctx, "path", "add", str(ctx.settings.vault_dir))
    assert result.exit_code == 1
    assert "cannot be monitored" in result.output
