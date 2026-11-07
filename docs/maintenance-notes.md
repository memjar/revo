# Maintenance notes

## Restore `npx` for Git hooks

The current environment has Node and npm installed, but no `npx` executable on `PATH` (`node` 20.18.3, `npm` 10.9.2). Reinstall or repair the Node/npm installation so the `npx` shim is available, then run the normal Revo pre-commit hooks on future commits.

Until fixed, do not assume a commit made with `HUSKY=0` has passed the repository's automated checks.
