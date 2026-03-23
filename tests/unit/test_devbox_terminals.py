from morphcloud.devbox.terminals import (
    build_tmux_attach_command,
    sanitize_tmux_session_name,
    sh_quote,
)


def test_build_tmux_attach_command_empty_session_is_empty():
    assert build_tmux_attach_command("") == ""
    assert build_tmux_attach_command("   ") == ""


def test_build_tmux_attach_command_without_initial_command():
    assert build_tmux_attach_command("session") == "tmux new-session -A -s 'session'"


def test_build_tmux_attach_command_with_initial_command():
    assert (
        build_tmux_attach_command("session", "echo hi")
        == "tmux new-session -A -s 'session' 'echo hi'"
    )


def test_build_tmux_attach_command_quotes_single_quotes():
    session = "s's"
    cmd = "echo 'hi'"
    assert (
        build_tmux_attach_command(session, cmd)
        == f"tmux new-session -A -s {sh_quote(session)} {sh_quote(cmd)}"
    )


def test_sanitize_tmux_session_name_matches_frontend_behavior():
    assert sanitize_tmux_session_name("hello world") == "hello_world"
    assert sanitize_tmux_session_name("a/b") == "a_b"
    assert sanitize_tmux_session_name("   ") == ""
