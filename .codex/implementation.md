# Implementation Checklist

Source objective: CRP/private plugin install loop verification.

## Completed

- [x] Fixed `morphcloud plugin uninstall` when the installer backend is `uv pip`.
- [x] Preserved `-y` for regular `python -m pip uninstall` so non-uv uninstall remains non-interactive.
- [x] Targeted `uv pip` installs/uninstalls at `sys.executable` with `--python` so plugin installs mutate the active CLI environment even when `VIRTUAL_ENV` is missing or stale.
- [x] Added unit tests for uv-backed and pip-backed uninstall command construction.
- [x] Added fresh-process CLI entry-point verification fallback after plugin install, covering installs that happen after the current process has already scanned entry points.
- [x] Verified focused plugin installer and plugin CLI tests.
- [x] Verified real prod loop: uninstall `intro`, then reinstall `morphcloud-intro-client==0.1.5` from the SEELE-scoped simple-index catalog.
- [x] Verified real prod global EFS install locally in a throwaway venv with `VIRTUAL_ENV` unset.
- [x] Added explicit plugin install targets: `morphcloud plugin install|upgrade|uninstall` now accept `--python` and `--venv`, forward the resolved Python to install/uninstall and verification, and keep ambiguous `uv run` installs actionable.

## Still Left

- [ ] Final intro visual acceptance remains in `morphcloud-intro-client`, not this SDK repo.
- [ ] Re-run the EFS global plugin workflow smoke against the pushed SDK branch after these target-selection changes are pushed.
