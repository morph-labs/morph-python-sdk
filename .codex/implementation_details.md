# Implementation Details

## Status

The SDK plugin uninstall path now handles current `uv` correctly. `uv pip uninstall` does not accept pip's `-y` flag, so the installer now omits `-y` only when the resolved backend command is `uv pip`. The regular pip path still emits `python -m pip uninstall -y <package>`.

The plugin install verifier now falls back to a fresh Python process when
in-process `importlib.metadata.entry_points()` misses the newly installed plugin
entry point. This fixes installs performed after the current CLI process has
already discovered entry points, while preserving the existing in-process fast
path and load failure behavior.

The uv-backed installer now passes `--python <sys.executable>` to `uv pip`
install and uninstall commands. That prevents plugin installs from targeting a
stale `VIRTUAL_ENV` or failing when the CLI is running from a virtualenv but the
environment variable is absent.

As of 2026-06-23, the user-facing plugin commands also support explicit target
selection. `morphcloud plugin install`, `upgrade`, and `uninstall` accept
`--python <executable>` or `--venv <path>`. The selected Python is passed to
package install/uninstall and to post-install entry-point/help verification, so
users running from `uv run` can choose the exact environment instead of relying
on implicit `sys.executable` targeting.

## Verification Evidence

- `UV_CACHE_DIR=/tmp/uv-cache uv run pytest tests/unit/test_plugin_installer.py tests/unit/test_cli_plugins.py -q` passed with `64 passed`.
- `UV_CACHE_DIR=/tmp/uv-cache uv run ruff check morphcloud/plugins/cli.py morphcloud/plugins/installer.py tests/unit/test_cli_plugins.py tests/unit/test_plugin_installer.py` passed.
- `UV_CACHE_DIR=/tmp/uv-cache uv run black --check morphcloud/plugins/cli.py morphcloud/plugins/installer.py tests/unit/test_cli_plugins.py tests/unit/test_plugin_installer.py` passed.
- `git diff --check` passed.
- Local production EFS smoke passed in a throwaway venv with `VIRTUAL_ENV`
  unset: `morphcloud plugin install efs` installed
  `morphcloud-efs-client==0.3.0`, exposed the `efs` entry point, and
  `morphcloud efs --help` ran.
- `UV_CACHE_DIR=/tmp/uv-cache-intro-loop-27770329382 uv run morphcloud plugin uninstall intro` succeeded.
- `UV_CACHE_DIR=/tmp/uv-cache-intro-loop-27770329382 uv run morphcloud plugin install intro` succeeded and installed `morphcloud-intro-client==0.1.5` from production simple-index.

## QnA Self-Check

- Functionality: The exact reinstall loop works with the real SEELE-scoped plugin, and explicit target selection is covered for install, upgrade, uninstall, and verification.
- Completeness: The SDK-side uninstall compatibility issue, same-process entry-point verification miss, and target-environment ambiguity are fixed and tested.
- Consistency: The change stays in the existing installer helper and uses existing pytest coverage.
- Clarity: No new install behavior or package resolution behavior was introduced.
- Confidence: 9/10 for the SDK plugin install/uninstall fixes.
