"""Tests for the BurnBar Cloud platform-plugin adapter."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from gateway.config import PlatformConfig
from tests.gateway._plugin_adapter_loader import load_plugin_adapter

_burnbar = load_plugin_adapter("burnbar")

BurnBarAdapter = _burnbar.BurnBarAdapter
DEFAULT_API_BASE_URL = _burnbar.DEFAULT_API_BASE_URL
DEFAULT_HOME_CHANNEL = _burnbar.DEFAULT_HOME_CHANNEL
MAX_MESSAGE_LENGTH = _burnbar.MAX_MESSAGE_LENGTH
check_requirements = _burnbar.check_requirements
is_connected = _burnbar.is_connected
register = _burnbar.register
validate_config = _burnbar.validate_config


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _response(status_code=200, payload=None, text="OK"):
    response = MagicMock()
    response.status_code = status_code
    response.text = text
    response.json.return_value = payload or {}
    return response


def test_platform_enum_resolves_via_plugin_scan():
    from gateway.config import Platform

    platform = Platform("burnbar")
    assert platform.value == "burnbar"
    assert Platform("burnbar") is platform


def test_requirements_and_config_checks(monkeypatch):
    monkeypatch.setattr(_burnbar, "HTTPX_AVAILABLE", True)
    monkeypatch.delenv("BURNBAR_ACCESS_TOKEN", raising=False)

    assert check_requirements() is False
    assert validate_config(PlatformConfig(enabled=True, extra={})) is False
    assert is_connected(PlatformConfig(enabled=True, extra={})) is False

    monkeypatch.setenv("BURNBAR_ACCESS_TOKEN", "obb_hgw_test")
    assert check_requirements() is True
    assert validate_config(PlatformConfig(enabled=True, extra={})) is True
    assert is_connected(PlatformConfig(enabled=True, extra={})) is True

    monkeypatch.delenv("BURNBAR_ACCESS_TOKEN", raising=False)
    cfg = PlatformConfig(enabled=True, extra={"access_token": "from-extra"})
    assert validate_config(cfg) is True
    assert is_connected(cfg) is True


def test_env_enablement_seeds_extra_and_home_channel(monkeypatch):
    monkeypatch.setenv("BURNBAR_ACCESS_TOKEN", "obb_hgw_test")
    monkeypatch.setenv("BURNBAR_API_BASE_URL", "https://burnbar.example.test/v1/hermes-gateway/")
    monkeypatch.setenv("BURNBAR_HOME_CHANNEL", "dest_main")
    monkeypatch.setenv("BURNBAR_HOME_CHANNEL_NAME", "Main BurnBar")

    seed = _burnbar._env_enablement()

    assert seed == {
        "api_base_url": "https://burnbar.example.test/v1/hermes-gateway",
        "access_token": "obb_hgw_test",
        "home_channel": {"chat_id": "dest_main", "name": "Main BurnBar"},
    }


def test_load_gateway_config_auto_enables_from_env(tmp_path, monkeypatch):
    from gateway.config import Platform, load_gateway_config

    hermes_home = tmp_path / ".hermes"
    hermes_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setenv("BURNBAR_ACCESS_TOKEN", "obb_hgw_test")
    monkeypatch.setenv("BURNBAR_API_BASE_URL", "https://burnbar.example.test/v1/hermes-gateway")
    monkeypatch.setenv("BURNBAR_HOME_CHANNEL", "dest_main")

    config = load_gateway_config()
    platform = Platform("burnbar")

    assert platform in config.platforms
    assert config.platforms[platform].enabled is True
    assert config.platforms[platform].extra["access_token"] == "obb_hgw_test"
    assert config.platforms[platform].extra["api_base_url"] == "https://burnbar.example.test/v1/hermes-gateway"
    assert config.platforms[platform].home_channel.chat_id == "dest_main"


def test_apply_yaml_config_sets_extra_and_preserves_env_precedence(monkeypatch):
    monkeypatch.delenv("BURNBAR_API_BASE_URL", raising=False)
    extra = _burnbar._apply_yaml_config(
        {
            "api_base_url": "https://burnbar.example.test/v1/hermes-gateway",
            "access_token": "token-yaml",
            "home_channel": "dest-yaml",
        },
        {"extra": {}},
    )

    assert extra == {
        "api_base_url": "https://burnbar.example.test/v1/hermes-gateway",
        "access_token": "token-yaml",
        "home_channel": "dest-yaml",
    }
    assert _burnbar.os.environ["BURNBAR_API_BASE_URL"] == "https://burnbar.example.test/v1/hermes-gateway"


def test_adapter_init_reads_env_and_extra(monkeypatch):
    monkeypatch.setenv("BURNBAR_ACCESS_TOKEN", "env-token")
    config = PlatformConfig(
        enabled=True,
        extra={
            "api_base_url": "https://burnbar.example.test/v1/hermes-gateway/",
            "home_channel": "dest-extra",
        },
    )

    adapter = BurnBarAdapter(config)

    assert adapter._api_base == "https://burnbar.example.test/v1/hermes-gateway"
    assert adapter._token == "env-token"
    assert adapter._home_channel == "dest-extra"
    assert adapter.MAX_MESSAGE_LENGTH == MAX_MESSAGE_LENGTH


def test_handle_burnbar_event_dispatches_message_event():
    adapter = BurnBarAdapter(
        PlatformConfig(enabled=True, extra={"access_token": "tok", "home_channel": "dest-home"})
    )
    adapter.handle_message = AsyncMock()

    _run(
        adapter._handle_burnbar_event(
            {
                "id": "evt_1",
                "sequence": 1,
                "destinationId": "dest_1",
                "senderId": "user_1",
                "senderDisplayName": "Alberto",
                "threadId": "thread_1",
                "text": "hello",
            }
        )
    )

    event = adapter.handle_message.await_args.args[0]
    assert event.text == "hello"
    assert event.message_id == "evt_1"
    assert event.source.chat_id == "dest_1"
    assert event.source.user_id == "user_1"
    assert event.source.thread_id == "thread_1"


def test_send_posts_message_to_burnbar():
    adapter = BurnBarAdapter(PlatformConfig(enabled=True, extra={"access_token": "tok"}))
    response = _response(payload={"message": {"id": "msg_1"}})
    adapter._client = MagicMock()
    adapter._client.post = AsyncMock(return_value=response)

    result = _run(adapter.send("dest_1", "hello", reply_to="evt_1", metadata={"thread_id": "thread_1"}))

    assert result.success is True
    assert result.message_id == "msg_1"
    payload = adapter._client.post.await_args.kwargs["json"]
    assert payload["destinationId"] == "dest_1"
    assert payload["threadId"] == "thread_1"
    assert payload["replyToEventId"] == "evt_1"
    assert payload["text"] == "hello"
    assert payload["attachmentIds"] == []


def test_standalone_send_uploads_attachments(tmp_path):
    media_path = tmp_path / "artifact.txt"
    media_path.write_text("report")

    pconfig = PlatformConfig(
        enabled=True,
        extra={
            "access_token": "tok",
            "api_base_url": "https://burnbar.example.test/v1/hermes-gateway",
            "home_channel": "dest-home",
        },
    )
    init_response = _response(payload={"attachment": {"id": "att_1"}, "uploadURL": "https://upload.test/att_1"})
    send_response = _response(payload={"message": {"id": "msg_1"}})
    mock_client = MagicMock()
    mock_client.post = AsyncMock(side_effect=[init_response, send_response])
    mock_client.put = AsyncMock(return_value=_response())
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch.object(_burnbar, "httpx") as mock_httpx:
        mock_httpx.AsyncClient.return_value = mock_client
        result = _run(
            _burnbar._standalone_send(
                pconfig,
                None,
                "finished",
                thread_id="thread_1",
                media_files=[(str(media_path), False)],
            )
        )

    assert result["success"] is True
    assert result["chat_id"] == "dest-home"
    assert result["message_id"] == "msg_1"
    assert result["attachment_ids"] == ["att_1"]
    assert mock_client.put.await_args.kwargs["content"] == b"report"
    send_payload = mock_client.post.await_args_list[1].kwargs["json"]
    assert send_payload["attachmentIds"] == ["att_1"]
    assert send_payload["threadId"] == "thread_1"


def test_register_calls_register_platform():
    ctx = MagicMock()
    register(ctx)

    kwargs = ctx.register_platform.call_args.kwargs
    assert kwargs["name"] == "burnbar"
    assert kwargs["label"] == "BurnBar Cloud"
    assert kwargs["required_env"] == ["BURNBAR_ACCESS_TOKEN"]
    assert kwargs["allowed_users_env"] == "BURNBAR_ALLOWED_USERS"
    assert kwargs["allow_all_env"] == "BURNBAR_ALLOW_ALL_USERS"
    assert kwargs["cron_deliver_env_var"] == "BURNBAR_HOME_CHANNEL"
    assert kwargs["max_message_length"] == MAX_MESSAGE_LENGTH
    assert callable(kwargs["setup_fn"])
    assert callable(kwargs["env_enablement_fn"])
    assert callable(kwargs["apply_yaml_config_fn"])
    assert callable(kwargs["standalone_sender_fn"])
    assert "BurnBar Cloud" in kwargs["platform_hint"]


def test_adapter_factory_returns_burnbar_adapter():
    ctx = MagicMock()
    register(ctx)
    factory = ctx.register_platform.call_args.kwargs["adapter_factory"]
    adapter = factory(PlatformConfig(enabled=True, extra={"access_token": "tok"}))
    assert isinstance(adapter, BurnBarAdapter)
