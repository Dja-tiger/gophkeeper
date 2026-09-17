# Working on GophKeeper

Deliver the requested behavior through implementation, verification and documentation. Resolve routine choices independently; ask only when missing information changes the outcome. User instructions override repository guidance within applicable system constraints.

Use ordinary branch names such as `feature/sync` and `fix/auth`; never include assistant, model or AI branding in branch names.

Read `docs/architecture.md` for service boundaries, `docs/security.md` for cryptography or authentication changes, and `docs/requirements.md` for acceptance scope. Do not load every document for unrelated edits.

Never log plaintext secrets, passwords or session tokens. Preserve owner isolation and optimistic concurrency. Use standard cryptographic libraries. Do not weaken tests or omit application packages to meet coverage.

Local tests use disposable fixtures and have no production access. Run affected tests and fix regressions without repeated approval. Before delivering application changes run `make check`; integration tests require a disposable PostgreSQL database via `GOPHKEEPER_TEST_DATABASE_URL`. Avoid repeating unchanged successful checks.

Keep package and exported Go API documentation current. Report measured results and distinguish local verification from remote CI. Keep communication concise and in Russian. Do not claim unsupported features are complete.
