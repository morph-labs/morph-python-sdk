import random
import socket
import types


def _make_test_instance():
    from morphcloud.api import Instance, InstanceNetworking, InstanceRefs, InstanceStatus, ResourceSpec

    inst = Instance.model_construct(  # type: ignore[attr-defined]
        id="morphvm_test",
        created=0,
        status=InstanceStatus.READY,
        spec=ResourceSpec(vcpus=1, memory=512, disk_size=1024),
        refs=InstanceRefs(snapshot_id="snap_test", image_id="img_test"),
        networking=InstanceNetworking(internal_ip=None, http_services=[]),
    )
    inst._api = types.SimpleNamespace(_client=types.SimpleNamespace(api_key="test_api_key"))  # type: ignore[attr-defined]
    return inst


def _install_fake_paramiko(monkeypatch, *, connect_impl):
    """
    Install a stub `paramiko` module so Instance.ssh_connect() can be tested without
    depending on the real paramiko implementation or a real SSH server.
    """

    class SSHException(Exception):
        pass

    class AutoAddPolicy:
        pass

    class _Transport:
        def __init__(self):
            self.keepalive = None

        def set_keepalive(self, secs: int):
            self.keepalive = secs

    class SSHClient:
        def __init__(self):
            self._transport = _Transport()

        def set_missing_host_key_policy(self, policy):
            return None

        def connect(self, *args, **kwargs):
            return connect_impl(*args, **kwargs)

        def get_transport(self):
            return self._transport

        def close(self):
            return None

    fake_paramiko = types.SimpleNamespace(
        SSHException=SSHException,
        AutoAddPolicy=AutoAddPolicy,
        SSHClient=SSHClient,
    )
    monkeypatch.setitem(__import__("sys").modules, "paramiko", fake_paramiko)


def test_ssh_connect_retries_and_sets_timeouts(monkeypatch):
    import morphcloud.api as api

    inst = _make_test_instance()

    # Avoid RSA key generation / entropy issues in unit tests.
    monkeypatch.setattr(api, "_dummy_key", lambda: object())

    # Deterministic jitter and no real sleeping.
    sleep_calls = []
    monkeypatch.setattr(random, "random", lambda: 0.0)
    monkeypatch.setattr(api.time, "sleep", lambda s: sleep_calls.append(s))

    attempts = {"n": 0}
    connect_kwargs = []

    def connect_impl(*args, **kwargs):
        attempts["n"] += 1
        connect_kwargs.append(kwargs)
        if attempts["n"] < 4:
            raise socket.timeout("timed out")
        return None

    _install_fake_paramiko(monkeypatch, connect_impl=connect_impl)

    monkeypatch.setenv("MORPH_SSH_TOTAL_TIMEOUT_SECS", "60")
    monkeypatch.setenv("MORPH_SSH_CONNECT_TIMEOUT_SECS", "1.5")
    monkeypatch.setenv("MORPH_SSH_BANNER_TIMEOUT_SECS", "2.5")
    monkeypatch.setenv("MORPH_SSH_AUTH_TIMEOUT_SECS", "3.5")
    monkeypatch.setenv("MORPH_SSH_RETRY_BASE_SLEEP_SECS", "0.2")
    monkeypatch.setenv("MORPH_SSH_RETRY_MAX_SLEEP_SECS", "1.0")
    monkeypatch.setenv("MORPH_SSH_RETRY_LOG_EVERY", "0")

    client = inst.ssh_connect()
    assert client is not None

    # 3 failures + 1 success
    assert attempts["n"] == 4
    assert len(sleep_calls) == 3

    # Ensure we always pass explicit SSH timeouts to paramiko.
    for kw in connect_kwargs:
        assert kw["timeout"] == 1.5
        assert kw["banner_timeout"] == 2.5
        assert kw["auth_timeout"] == 3.5

    # Backoff should be bounded and non-decreasing here.
    assert all(0.0 <= s <= 1.0 for s in sleep_calls)
    assert sleep_calls == sorted(sleep_calls)


def test_ssh_connect_times_out(monkeypatch):
    import morphcloud.api as api

    inst = _make_test_instance()
    monkeypatch.setattr(api, "_dummy_key", lambda: object())
    monkeypatch.setattr(random, "random", lambda: 0.0)

    # Fake clock so "time passes" without sleeping.
    class Clock:
        def __init__(self):
            self.now = 0.0

        def time(self):
            return self.now

        def sleep(self, secs: float):
            self.now += max(0.0, float(secs))

    clock = Clock()
    monkeypatch.setattr(api.time, "time", clock.time)
    monkeypatch.setattr(api.time, "sleep", clock.sleep)

    def connect_impl(*args, **kwargs):
        raise socket.timeout("timed out")

    _install_fake_paramiko(monkeypatch, connect_impl=connect_impl)

    monkeypatch.setenv("MORPH_SSH_TOTAL_TIMEOUT_SECS", "1.0")
    monkeypatch.setenv("MORPH_SSH_RETRY_BASE_SLEEP_SECS", "0.5")
    monkeypatch.setenv("MORPH_SSH_RETRY_MAX_SLEEP_SECS", "1.0")
    monkeypatch.setenv("MORPH_SSH_RETRY_LOG_EVERY", "0")

    try:
        inst.ssh_connect()
        assert False, "Expected TimeoutError"
    except TimeoutError as e:
        msg = str(e)
        assert "SSH connect timed out" in msg
        assert "instance_id=morphvm_test" in msg
