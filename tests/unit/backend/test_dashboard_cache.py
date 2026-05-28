import pytest
from unittest.mock import MagicMock, patch
from src.dashboard import service as dashboard_service


@pytest.fixture(autouse=True)
def reset_redis_conn():
    # Force re-initialization of the redis connection for each test
    dashboard_service._redis_conn = None
    yield
    dashboard_service._redis_conn = None


@patch("redis.Redis.from_url")
def test_get_redis_success(mock_from_url):
    mock_redis = MagicMock()
    mock_from_url.return_value = mock_redis

    conn = dashboard_service._get_redis()
    assert conn == mock_redis
    mock_from_url.assert_called_once()


@patch("redis.Redis.from_url")
def test_get_redis_failure_degrades_gracefully(mock_from_url):
    mock_from_url.side_effect = Exception("Redis unreachable")

    conn = dashboard_service._get_redis()
    assert conn is None


@patch("redis.Redis.from_url")
def test_safe_execute_uses_cached_result(mock_from_url):
    mock_redis = MagicMock()
    mock_redis.get.return_value = b'[["2026-05-29T00:00:00", 100]]'
    mock_from_url.return_value = mock_redis

    mock_client = MagicMock()

    result = dashboard_service._safe_execute(mock_client, "SELECT count() FROM logs")
    assert result == [["2026-05-29T00:00:00", 100]]
    mock_redis.get.assert_called_once()
    mock_client.execute.assert_not_called()


@patch("redis.Redis.from_url")
def test_safe_execute_writes_to_cache_on_miss(mock_from_url):
    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    mock_from_url.return_value = mock_redis

    mock_client = MagicMock()
    mock_client.execute.return_value = [["2026-05-29T00:00:00", 100]]

    result = dashboard_service._safe_execute(mock_client, "SELECT count() FROM logs")
    assert result == [["2026-05-29T00:00:00", 100]]
    
    mock_redis.get.assert_called_once()
    mock_client.execute.assert_called_once_with("SELECT count() FROM logs")
    mock_redis.setex.assert_called_once()


@patch("redis.Redis.from_url")
def test_safe_execute_graceful_degradation_on_redis_error(mock_from_url):
    mock_redis = MagicMock()
    mock_redis.get.side_effect = Exception("Read error")
    mock_redis.setex.side_effect = Exception("Write error")
    mock_from_url.return_value = mock_redis

    mock_client = MagicMock()
    mock_client.execute.return_value = [["2026-05-29T00:00:00", 100]]

    # Should not throw exception, should query ClickHouse directly
    result = dashboard_service._safe_execute(mock_client, "SELECT count() FROM logs")
    assert result == [["2026-05-29T00:00:00", 100]]
    mock_client.execute.assert_called_once_with("SELECT count() FROM logs")
