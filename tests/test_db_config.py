from unittest.mock import MagicMock

from config import db


def test_database_connections_set_session_timezone_to_utc(monkeypatch):
    connect = MagicMock(return_value=MagicMock())
    monkeypatch.setattr(db.pymysql, "connect", connect)

    db.get_db_connection()

    assert connect.call_args.kwargs["init_command"] == "SET time_zone = '+00:00'"
