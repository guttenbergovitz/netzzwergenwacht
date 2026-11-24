# Engineering and Git Conventions

Standards for code, documentation, branching, and commits in NetzZwergenWacht.

## Language and in-code documentation

- All documentation, comments, docstrings, error messages, and commit messages use **British English (`en-GB`)** — avoid Americanisms (for example: *optimise*, *behaviour*, *defence*, *colour*, *licence*, *normalise*, *artefact*, *initialise*).
- Keep prose plain and direct.
- In-code documentation should explain **purpose, invariants, and trade-offs** so both developers and LLMs understand *why* a piece of code exists and what guarantees it upholds. Do not narrate trivial mechanics that are already obvious from the code.

## Rust coding standards

### Error handling

- Do not use `.unwrap()` or `.expect()` in production paths as a shortcut (`clippy::unwrap_used` and `clippy::expect_used` are denied).
- Propagate errors explicitly via `Result` and `?`, using well-typed domain errors at module boundaries.
- Never coerce a failed, skipped, or unavailable measurement into `0` or a passing check; use `Measurement<T>`.
- Tests may use `.unwrap()` / `.expect()` freely (allowed via `clippy.toml`).

### Ownership and allocations

- Avoid gratuitous `.clone()` calls, unnecessary `Arc<Mutex<_>>`, or `Box<dyn ...>` introduced merely to appease the borrow checker.
- Prefer borrowing (`&T`, `&[u8]`, `Cow<'_, str>`) and clear ownership transfer. Clone only when the ownership model genuinely requires it or when working with cheap, intentional handles (such as `bytes::Bytes` or `Arc` for shared immutable snapshots).

### Architecture and types

- Maintain strict boundaries between `domain`, `collection` (HTTP/TLS/browser/adapters), `analysis` (deterministic Zwerge), `persistence`, `intelligence` (optional AI), and `cli`.
- Analysers must consume `&EvidenceSnapshot` and must never perform uncontrolled network I/O.
- Use explicit domain types (newtypes, enums) to make invalid states unrepresentable instead of passing raw strings, integers, or generic JSON maps across layers.
- Keep dependencies minimal and justified. Every external crate must earn its place.

### Tooling and lints

- Format all code with `rustfmt` (`cargo fmt --all`).
- Treat `clippy` warnings seriously (`cargo clippy --all-targets --locked -- -D warnings`), including `missing_docs`, `pedantic`, `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `dbg_macro`, and `clone_on_ref_ptr`.
- Practise test-driven development (TDD): define expected behaviour, edge cases, and failure modes in tests alongside or before implementation.

## Local quality gate

Run the same checks as CI before every commit:

```bash
task check      # fmt:check, lint, doc (-D warnings), and test
```

Without Task:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo test --all-targets --locked
```

## Branching and releases (Git Flow + SemVer)

NetzZwergenWacht uses **Git Flow** with **Semantic Versioning (`MAJOR.MINOR.PATCH`)**:

- `main` — release-ready history (currently preserving the frozen Python reference until `rewrite/rust` is approved for merge).
- `develop` — integration branch for upcoming releases.
- `rewrite/rust` — active Rust rewrite branch.
- `feature/<short-name>` — branched from `develop` (or `rewrite/rust` during the rewrite), merged back into its parent.
- `release/<version>` / `hotfix/<short-name>` — release preparation and urgent fixes.

## Commit messages (Conventional Commits)

All commits must follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<optional-scope>): <imperative summary>

<optional body explaining why and any notable trade-offs>
```

Allowed types: `feat`, `fix`, `refactor`, `perf`, `docs`, `test`, `build`, `ci`, `chore`.
- **Atomic commits:** Each commit should represent one cohesive, reviewable change.
- **Subject line:** Imperative mood, lowercase, no trailing full stop, under 72 characters.
- **Scope:** Concise module or area name (`domain`, `collect`, `analysis`, `cli`, `adr`, `docs`, `rust`).
