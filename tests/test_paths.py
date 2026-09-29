from ssobroker import paths


def test_env_override_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path / "custom"))
    assert paths.home_dir() == tmp_path / "custom"


def test_defaults_to_dot_ssobroker(monkeypatch, tmp_path):
    monkeypatch.delenv("SSOBROKER_HOME", raising=False)
    monkeypatch.setattr(paths.Path, "home", lambda: tmp_path)
    assert paths.home_dir() == tmp_path / ".ssobroker"


def test_falls_back_to_pre_rename_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("SSOBROKER_HOME", raising=False)
    monkeypatch.setattr(paths.Path, "home", lambda: tmp_path)
    (tmp_path / ".orgctl").mkdir()
    assert paths.home_dir() == tmp_path / ".orgctl"


def test_new_dir_preferred_once_it_exists(monkeypatch, tmp_path):
    monkeypatch.delenv("SSOBROKER_HOME", raising=False)
    monkeypatch.setattr(paths.Path, "home", lambda: tmp_path)
    (tmp_path / ".orgctl").mkdir()
    (tmp_path / ".ssobroker").mkdir()
    assert paths.home_dir() == tmp_path / ".ssobroker"
