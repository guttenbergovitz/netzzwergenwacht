# 0025. Developer experience and operational tooling

## Status

Accepted

## Context

`Taskfile.yml` currently exposes nine engineering tasks (`fmt`, `lint`, `test`, `doc`,
`check`, `build`, `audit`, `clean`) and nothing operational. There is no task to prepare
dependencies, no environment diagnostic, no development launch path and no local
installation path.

Environment verification is scattered and implicit: Chromium is discovered through
`NZW_CHROMIUM_BIN`, axe through `NZW_AXE_BIN`, Node and the CDP WebSocket client are
assumed to exist, and `.github/workflows/ci.yml` installs `ws` with
`npm install --no-save ws` although the harness actually uses the global `WebSocket`
provided by Node 22+. An operator has no single command that answers "is this machine
able to run what I am about to run?".

## Decision

1. **The Taskfile is the primary entrypoint.** Tasks are grouped and named for
   operational use: `setup`, `doctor`, `dev`, `tui`, `run`, `build`, `install`,
   `uninstall`, `fmt`, `fmt:check`, `lint`, `doc`, `test`, `test:browser`,
   `test:integration`, `check`, `check:all`, `audit`, `clean`, plus argument-forwarding
   conveniences (`task check:target -- <url>`, `task investigate -- <url>`,
   `task patrol -- <url>`). Existing task names are preserved so documented commands
   keep working.
2. **Detection lives in Rust, not in shell.** `nzw doctor` is the single implementation
   of environment verification; `task doctor` and `task setup` delegate to it. Scripts
   do not re-implement executable discovery, and the TUI does not either.
3. **`nzw doctor [--format json]`** reports, without performing network calls or audits:
   binary version and build profile, Rust toolchain (development only), Node ≥22,
   Chromium launch eligibility, Lighthouse, axe-core, configuration discovery and
   schema validity, provider credential *availability* by name, patrol memory directory,
   report destination and terminal capabilities. Each row states one of available,
   unavailable, unsupported or configurable, and versions are printed only when they
   were actually read.
4. **`task setup` is idempotent and non-invasive.** It verifies the toolchain, reports
   missing instruments with platform-specific installation guidance, and never runs
   `sudo`, never installs global packages and never rewrites the user's environment. It
   performs no network installation of language runtimes.
5. **Runtime dependencies are declared, not assumed.** Node 22+ with its built-in
   `WebSocket` and `fetch` is the documented requirement; the `ws` installation is
   removed from CI because it is not used. The browser harness keeps using only Node
   built-ins, so no JavaScript lockfile is required and no global npm state is mutated.
6. **Two clearly separated "check" meanings.** `nzw check <url>` runs a diagnostic
   audit; `task check` runs the engineering quality gate. `task check:target -- <url>`
   runs the diagnostic through the task runner. The distinction is stated in the
   Taskfile descriptions and the README.
7. **Installation is reproducible.** `cargo install --path . --locked` installs the
   `nzw` binary; `task install` wraps it and `task uninstall` removes the same named
   binary. Release binaries are documented only if a release workflow actually produces
   them.
8. **CI parity.** The browser job keeps running the ignored suites with a real Chromium
   and `NZW_ALLOW_UNSAFE_BROWSER_SANDBOX=1` scoped to that job. `check:all` mirrors the
   full gate locally, including the release build.

## Consequences

- A new contributor can go from clone to a running workbench with three commands, and a
  failed step explains what to install.
- Doctor output becomes a contract that tests can assert on, and its JSON form supports
  future automation without a second implementation.
- Removing the unused `ws` install reduces CI surface; if a Node dependency is ever
  genuinely required it must be pinned in a manifest rather than installed ad hoc.
- The Taskfile grows, but each task remains a thin wrapper over a command that also works
  standalone.
