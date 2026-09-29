import configparser
from pathlib import Path

import pytest

from ssobroker import aws_config_sync
from ssobroker.config import Account, ConfigError, OrgConfig


def _cfg(**accounts: Account) -> OrgConfig:
    return OrgConfig(
        name="test",
        sso_start_url="https://example.awsapps.com/start",
        sso_region="us-east-1",
        default_region="us-east-1",
        accounts=accounts,
    )


def _backups(path: Path) -> list[Path]:
    return sorted(path.parent.glob(path.name + ".bak*"))


@pytest.fixture(autouse=True)
def _fake_home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


def test_writes_new_profile_from_scratch(tmp_path):
    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["read-only"]))
    written, skipped, conflicts, path, _backup = aws_config_sync.sync(cfg)

    assert written == ["prod"]
    assert skipped == []
    assert conflicts == []
    assert path.exists()

    parser = configparser.ConfigParser()
    parser.read(path)
    assert parser.get("profile prod", "credential_process") == (
        "ssobroker creds-process --account prod --role read-only"
    )


def test_rerun_overwrites_its_own_previously_written_section(tmp_path):
    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["read-only"]))
    aws_config_sync.sync(cfg)

    # Change the registry (e.g. a different role) and sync again.
    cfg2 = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["admin"]))
    written, skipped, conflicts, path, _backup = aws_config_sync.sync(cfg2)

    assert written == ["prod"]
    assert conflicts == []
    parser = configparser.ConfigParser()
    parser.read(path)
    assert "admin" in parser.get("profile prod", "credential_process")


def test_preexisting_unmanaged_profile_is_left_untouched(tmp_path):
    # Simulate a profile the user already had, e.g. from `aws configure`,
    # that happens to share a name with an ssobroker account alias.
    path = tmp_path / ".aws" / "config"
    path.parent.mkdir(parents=True)
    path.write_text("[profile prod]\naws_access_key_id = AKIAEXAMPLE\nregion = us-west-2\n")

    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["read-only"]))
    written, skipped, conflicts, returned_path, backup = aws_config_sync.sync(cfg)

    assert written == []
    assert conflicts == ["prod"]

    # File must be byte-for-byte untouched — no backup, no rewrite.
    assert returned_path.read_text() == (
        "[profile prod]\naws_access_key_id = AKIAEXAMPLE\nregion = us-west-2\n"
    )
    assert backup is None
    assert _backups(returned_path) == []


def test_dry_run_writes_nothing(tmp_path):
    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["read-only"]))
    written, skipped, conflicts, path, _backup = aws_config_sync.sync(cfg, dry_run=True)

    assert written == ["prod"]
    assert not path.exists()


def test_skips_account_with_multiple_roles_and_no_default(tmp_path):
    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["read-only", "admin"]))
    written, skipped, conflicts, path, _backup = aws_config_sync.sync(cfg)

    assert written == []
    assert skipped == ["prod"]


def _three_accounts() -> OrgConfig:
    return _cfg(
        a=Account(alias="a", account_id="111111111111", roles=["ro"], default_role="ro"),
        b=Account(alias="b", account_id="222222222222", roles=["ro"], default_role="ro"),
        c=Account(alias="c", account_id="333333333333", roles=["ro", "admin"], default_role="ro"),
    )


def test_prefix_keeps_one_profile_per_account():
    # Regression: with --prefix, every account collapsed into a profile named
    # exactly <prefix>, so only the last account survived.
    written, _, _, path, _ = aws_config_sync.sync(_three_accounts(), prefix="corp")

    assert sorted(written) == ["corp-a", "corp-b", "corp-c"]
    parser = configparser.ConfigParser()
    parser.read(path)
    assert parser.get("profile corp-b", "credential_process").endswith("--account b --role ro")


def test_prefix_with_all_roles_keeps_one_profile_per_account_and_role():
    written, _, _, _, _ = aws_config_sync.sync(_three_accounts(), prefix="corp", all_roles=True)
    assert sorted(written) == ["corp-a-ro", "corp-b-ro", "corp-c-admin", "corp-c-ro"]


def test_colliding_profile_names_raise_instead_of_dropping_one():
    cfg = _cfg(
        **{
            "a-b": Account(alias="a-b", account_id="111111111111", roles=["c"]),
            "a": Account(alias="a", account_id="222222222222", roles=["b-c"]),
        }
    )
    with pytest.raises(ConfigError, match="a-b-c"):
        aws_config_sync.sync(cfg, all_roles=True)


ORIGINAL_CONFIG = (
    "# my important comment about the dev account\n"
    "[profile dev]\n"
    "region = us-west-2\n"
    "# keep this\n"
    "Output = json\n"
    "\n"
    "[default]\n"
    "s3 =\n"
    "  max_concurrent_requests = 20\n"
)


def _write_aws_config(tmp_path, text: str) -> Path:
    path = tmp_path / ".aws" / "config"
    path.parent.mkdir(parents=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        f.write(text)
    return path


def _read(path: Path) -> str:
    with path.open(encoding="utf-8", newline="") as f:
        return f.read()


def test_existing_content_is_preserved_byte_for_byte(tmp_path):
    # Regression: the file used to be round-tripped through configparser,
    # which dropped comments, lowercased keys and reflowed everything.
    path = _write_aws_config(tmp_path, ORIGINAL_CONFIG)
    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["ro"]))

    aws_config_sync.sync(cfg)

    updated = _read(path)
    assert updated.startswith(ORIGINAL_CONFIG)
    assert "[profile prod]\ncredential_process = ssobroker creds-process" in updated


def test_rewriting_own_section_keeps_neighbouring_comments(tmp_path):
    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["ro"]))
    path = _write_aws_config(tmp_path, ORIGINAL_CONFIG)
    aws_config_sync.sync(cfg)
    # A user then adds their own profile (with a leading comment) after ours.
    with path.open("a", encoding="utf-8", newline="") as f:
        f.write("\n# staging is special\n[profile staging]\nregion = eu-west-1\n")

    cfg2 = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["admin"]))
    aws_config_sync.sync(cfg2)

    updated = _read(path)
    assert "--role admin" in updated
    assert "--role ro" not in updated
    assert "# staging is special\n[profile staging]\nregion = eu-west-1\n" in updated
    assert updated.startswith(ORIGINAL_CONFIG)


def test_rerun_with_no_changes_writes_nothing_and_makes_no_backup(tmp_path):
    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["ro"]))
    path = _write_aws_config(tmp_path, ORIGINAL_CONFIG)
    aws_config_sync.sync(cfg)
    after_first = _read(path)
    backups_after_first = _backups(path)

    _, _, _, _, backup = aws_config_sync.sync(cfg)

    assert backup is None
    assert _read(path) == after_first
    assert _backups(path) == backups_after_first


def test_backups_are_never_overwritten_so_the_original_survives(tmp_path):
    # Regression: a single fixed .bak was overwritten on every run, so after
    # the second sync the user's original file was gone.
    path = _write_aws_config(tmp_path, ORIGINAL_CONFIG)
    cfg1 = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["ro"]))
    cfg2 = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["admin"]))

    _, _, _, _, first_backup = aws_config_sync.sync(cfg1)
    _, _, _, _, second_backup = aws_config_sync.sync(cfg2)

    assert first_backup is not None and second_backup is not None
    assert first_backup != second_backup
    assert _read(first_backup) == ORIGINAL_CONFIG
    assert "--role ro" in _read(second_backup)
    assert len(_backups(path)) == 2


def test_no_backup_when_config_file_did_not_exist_yet():
    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["ro"]))
    _, _, _, path, backup = aws_config_sync.sync(cfg)
    assert backup is None
    assert _backups(path) == []


def test_dry_run_makes_no_backup_and_leaves_file_alone(tmp_path):
    path = _write_aws_config(tmp_path, ORIGINAL_CONFIG)
    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["ro"]))

    _, _, _, _, backup = aws_config_sync.sync(cfg, dry_run=True)

    assert backup is None
    assert _read(path) == ORIGINAL_CONFIG
    assert _backups(path) == []


def test_crlf_line_endings_are_preserved(tmp_path):
    crlf = ORIGINAL_CONFIG.replace("\n", "\r\n")
    path = _write_aws_config(tmp_path, crlf)
    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["ro"]))

    aws_config_sync.sync(cfg)

    updated = _read(path)
    assert updated.startswith(crlf)
    assert "\n" not in updated.replace("\r\n", "")


def test_section_written_by_older_configparser_version_is_still_recognised(tmp_path):
    # Older releases wrote sections via configparser; they must still count as
    # managed (so they're updated in place, not reported as conflicts).
    legacy = (
        "[profile prod]\n"
        "credential_process = ssobroker creds-process --account prod --role old\n"
        "region = us-east-1\n"
        "_ssobroker_managed = true\n"
        "\n"
    )
    path = _write_aws_config(tmp_path, legacy)
    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["new"]))

    written, _, conflicts, _, _ = aws_config_sync.sync(cfg)

    assert written == ["prod"]
    assert conflicts == []
    assert "--role new" in _read(path)
    assert _read(path).count("[profile prod]") == 1


def test_section_written_under_the_old_orgctl_name_is_taken_over(tmp_path):
    # Before the rename, sections were tagged `_orgctl_managed` and pointed at
    # the `orgctl` command. They must be updated in place, not reported as
    # conflicts, and come out pointing at `ssobroker` with the new marker.
    legacy = (
        "[profile prod]\n"
        "credential_process = orgctl creds-process --account prod --role ro\n"
        "region = us-east-1\n"
        "_orgctl_managed = true\n"
        "\n"
    )
    path = _write_aws_config(tmp_path, legacy)
    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["ro"]))

    written, _, conflicts, _, _ = aws_config_sync.sync(cfg)

    updated = _read(path)
    assert written == ["prod"]
    assert conflicts == []
    assert "credential_process = ssobroker creds-process" in updated
    assert "_ssobroker_managed = true" in updated
    assert "orgctl" not in updated
    assert updated.count("[profile prod]") == 1


def test_file_without_trailing_newline_gets_clean_separator(tmp_path):
    path = _write_aws_config(tmp_path, "[profile dev]\nregion = us-west-2")
    cfg = _cfg(prod=Account(alias="prod", account_id="111111111111", roles=["ro"]))

    aws_config_sync.sync(cfg)

    assert _read(path).startswith("[profile dev]\nregion = us-west-2\n\n[profile prod]\n")
