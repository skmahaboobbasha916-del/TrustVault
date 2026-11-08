from unittest.mock import MagicMock

import app as trustvault_app
import pytest


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setitem(trustvault_app.app.config, "TESTING", True)
    monkeypatch.setitem(trustvault_app.app.config, "SECRET_KEY", "test-secret")
    return trustvault_app.app.test_client()


def test_normal_server_entrypoint_keeps_debug_disabled(monkeypatch):
    run = MagicMock()
    monkeypatch.setattr(trustvault_app.app, "run", run)
    monkeypatch.setenv("FLASK_DEBUG", "1")

    trustvault_app.run_server()

    run.assert_called_once_with(debug=False)


@pytest.mark.parametrize(
    "secret_key",
    [
        None,
        "short-secret",
        "a" * 64,
        "change-me-" + "x" * 40,
        "abcdefghijklmnop" * 2,
    ],
)
def test_production_app_rejects_missing_or_weak_secret_without_echoing_it(
    monkeypatch, secret_key
):
    monkeypatch.setenv("TRUSTVAULT_ENV", "production")
    if secret_key is None:
        monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)
    else:
        monkeypatch.setenv("FLASK_SECRET_KEY", secret_key)

    with pytest.raises(RuntimeError) as error:
        trustvault_app.create_app()

    assert "FLASK_SECRET_KEY" in str(error.value)
    assert secret_key is None or secret_key not in str(error.value)


def test_production_app_accepts_explicit_strong_secret(monkeypatch):
    strong_key = "n4vR!1uKz0pX8mQ3#eY7bL2@hD5sA9cW"
    monkeypatch.setenv("TRUSTVAULT_ENV", "production")
    monkeypatch.setenv("FLASK_SECRET_KEY", strong_key)

    application = trustvault_app.create_app()

    assert application.secret_key == strong_key


def test_development_and_test_apps_require_explicit_keys(monkeypatch):
    monkeypatch.setenv("TRUSTVAULT_ENV", "development")
    monkeypatch.setenv("FLASK_SECRET_KEY", "explicit-local-dev-key")
    local_app = trustvault_app.create_app()
    assert local_app.secret_key == "explicit-local-dev-key"

    monkeypatch.setenv("TRUSTVAULT_ENV", "production")
    monkeypatch.delenv("FLASK_SECRET_KEY")
    test_app = trustvault_app.create_app({
        "TESTING": True,
        "SECRET_KEY": "explicit-test-configuration-key-32",
    })
    assert test_app.secret_key == "explicit-test-configuration-key-32"

    with pytest.raises(RuntimeError, match="FLASK_SECRET_KEY must be configured"):
        trustvault_app.create_app({"TESTING": True})


def test_unmatched_admin_api_path_returns_404_with_no_store(client):
    response = client.get("/api/admin/no-such-endpoint")

    assert response.status_code == 404
    assert response.headers["Cache-Control"] == "no-store"


def test_unsupported_admin_api_method_returns_405_with_no_store(client):
    response = client.post("/api/admin/audit-events")

    assert response.status_code == 405
    assert response.headers["Cache-Control"] == "no-store"
