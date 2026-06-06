# AGENTS.md

This file gives coding agents the repo-specific commands, conventions, and caveats for working in this project.

## Instruction Sources
- No existing `AGENTS.md` was present at the repo root when this file was created.
- No Cursor rules were found in `.cursor/rules/`.
- No `.cursorrules` file was found.
- No Copilot instructions were found in `.github/copilot-instructions.md`.

## Project Snapshot
- App: WeDo, a mobile-first shared shopping/todo web app.
- Backend: FastAPI + SQLAlchemy + SQLite in `main.py`.
- Frontend: Vite + Alpine.js + RxDB in `src/main.js` with UI markup/styles in `index.html`.
- Tests: pytest backend suite in `tests/test_main.py`.
- Runtime build: frontend compiles to `dist/`, which FastAPI serves.

## Layout
- `main.py`: FastAPI app, models, auth, sync, security headers, SPA serving.
- `src/main.js`: Alpine app state, RxDB setup, replication, routing, UI actions.
- `index.html`: primary HTML and CSS for the frontend.
- `tests/test_main.py`: backend integration tests via `TestClient`.
- `public/`: static assets for Vite/PWA.
- `data/`: SQLite database files.
- `dist/`: generated frontend bundle; do not hand-edit.

## Environment Setup
```bash
docker compose -f docker-compose.dev.yml up --build
```

- Development is container-first; local Node/Python environments are optional.
- `requirements.txt` is runtime-only and is what the Docker image installs.
- `requirements-dev.txt` includes pytest/httpx for local backend tests.

## Daily Commands
- Containerized dev app: `docker compose -f docker-compose.dev.yml up --build`
- Backend tests in container: `./test.sh`
- Frontend E2E tests in container: `./test-e2e.sh`
- Frontend dev server, if running locally: `npm run dev`
- Backend dev server, if running locally: `ENV=development uvicorn main:app --reload --port 8080`
- Dockerized local run: `docker compose up -d --build`
- Frontend production build: `npm run build`
- Preview built frontend: `npm run preview`

## Test Commands
```bash
./test.sh
./test.sh tests/test_main.py
./test.sh tests/test_main.py::test_healthz
./test.sh tests/test_main.py -k "sync and pull"
./test-e2e.sh
```

- Backend tests are pytest only.
- Frontend browser coverage uses Playwright in the `e2e` Compose profile.
- Playwright reports are generated under `playwright-report/` and `test-results/`, both ignored.
- Prefer single-test or `-k` invocations while iterating on backend changes.
- Do not run multiple pytest commands in parallel; tests share `data/test_wedo_test.db` and can interfere with each other.

## Lint and Format
- There is no checked-in ESLint, Prettier, Ruff, Black, mypy, or Makefile target.
- Do not claim lint passed unless you added and ran a real lint configuration.
- For frontend changes, `npm run build` is the main automated sanity check.
- For backend changes, `pytest` is the main automated sanity check.
- Keep formatting consistent with surrounding code; avoid whole-file reformatting.

## Verified Behavior
- `npm run build` succeeds in the current tree.
- `./test.sh tests/test_main.py::test_healthz` succeeds.
- `./test.sh tests/test_main.py::test_login_success_sets_hardened_cookie` succeeds.
- `./test.sh` succeeds when run sequentially.
- `./test-e2e.sh` succeeds when Docker can pull `mcr.microsoft.com/playwright:v1.60.0-noble`.
- If you touch auth, test bootstrapping, or seeding, re-run the full suite sequentially.

## Backend Conventions
- Backend code is centralized in `main.py`; keep changes localized unless a split is clearly worth it.
- Use FastAPI dependencies for auth and DB access instead of threading state manually.
- Prefer small helpers for validation, timestamps, cookies, serialization, and auth checks.
- Use `snake_case` for functions and locals, `PascalCase` for classes, and `UPPER_SNAKE_CASE` for constants.
- Keep request and sync payload models in Pydantic classes near related route logic.
- Annotate helper return types and important locals; prefer concrete container types like `list[...]` and `dict[str, Any]`.
- Use `Optional`, `Any`, and `cast()` only where SQLAlchemy or framework typing genuinely needs them.
- Preserve the existing SQLAlchemy style: `declarative_base()`, `SessionLocal`, `db.query(...)`, explicit `commit()`.
- Reuse UTC helpers such as `utcnow`, `serialize_datetime`, and `parse_datetime`.

## Python Imports and Formatting
- Group imports as stdlib, blank line, third-party, blank line, local.
- Within a group, keep ordering readable and roughly alphabetical.
- Use 4-space indentation and double-quoted strings, matching `main.py`.
- Wrap long calls with hanging indents instead of backslashes.
- Keep blank lines between top-level constants, helpers, classes, and route handlers.
- Avoid mass reformatting; make the smallest readable edit.

## API and Data Rules
- Mutating endpoints call `enforce_allowed_origin(request)`; keep that on new write routes.
- Authenticated endpoints use `Depends(get_current_user)` and typically `Depends(get_db)`.
- Validate user input through shared cleaners or new focused helpers before persistence.
- Raise `HTTPException` with specific status codes and short, stable details for expected client errors.
- Soft-delete lists and todos with `deleted` and `_deleted` tombstones; do not hard-delete synced records.
- Whenever a record changes, update `updated_at`.
- When creating synced records, preserve or derive `created_at` carefully.
- Maintain list ownership and auth isolation across CRUD and sync paths.

## Transactions and Error Handling
- Commit only after a coherent unit of work completes.
- On multi-step write flows, rollback in `except` and re-raise, as in `sync_push`.
- Catch broad exceptions only for cleanup or user-facing fallback paths.
- Ignore cleanup failures only when the existing code already treats them as non-fatal.
- Prefer user-safe error messages over leaking raw exceptions into API responses.

## Frontend Conventions
- Frontend logic lives in `src/main.js`; markup and CSS live in `index.html`.
- Use plain ES modules, Alpine state, and RxDB; do not introduce TypeScript or a new framework casually.
- Use `camelCase` for functions/state and `UPPER_SNAKE_CASE` for module constants.
- Keep imports at the top; external packages first and virtual modules last when added.
- Use 4-space indentation, single-quoted strings, and semicolons, matching `src/main.js`.
- Prefer small pure helpers like `createId`, `nowIso`, `sortTodos`, and `parsePath` for shared logic.
- Keep Alpine state mutations inside the `app()` data object methods.
- Reuse existing fields like `error`, `syncError`, `loading`, and `syncing` for user-visible state.
- Clean up listeners, subscriptions, and database handles in reset or teardown paths.

## Frontend Networking and Sync
- Use the shared `request()` helper for fetch calls so auth reset behavior stays consistent.
- Send JSON with `credentials: 'same-origin'`.
- Keep pull and push replication settings aligned unless the protocol changes.
- Preserve `_deleted` tombstone semantics in client documents.
- After local RxDB mutations, call `waitForSync()` where the current UX expects server convergence.
- If you change sync payload shapes, update both FastAPI handlers and RxDB replication code together.

## HTML and CSS Notes
- `index.html` is hand-authored and sizable; do not replace it with a new framework build step casually.
- Keep the mobile-first layout intact and preserve existing CSS custom properties.
- Avoid unnecessary inline-style churn; stay consistent with the current lightweight pattern.
- Edit `index.html`, `src/main.js`, and `public/`; never patch generated files in `dist/` by hand.

## Testing Conventions
- Tests live in `tests/test_main.py` and use function-scoped pytest fixtures.
- Keep test names descriptive: `test_<behavior>`.
- Reuse helpers like `login(...)` for auth-related coverage.
- Assert both HTTP status codes and important payload, cookie, or header details.
- For auth and session behavior, verify database state when relevant.
- Set `ENV=test` before importing `main` in any new backend test module.

## Safe Change Strategy
- When changing auth, sessions, CORS, or sync logic, update backend code, frontend call sites, and tests in the same patch.
- When changing schema fields, update SQLAlchemy models, serializers, request models, RxDB schemas, and affected tests together.
- Keep compatibility helpers in place unless you also handle migration for existing SQLite data.
- Prefer additive, focused changes over broad refactors; the repo is intentionally simple and centralized.

## What Not To Assume
- There is currently no checked-in lint script.
- There is currently no frontend test suite.
- There are no repo-level Cursor rules in `.cursor/rules/`.
- There is no `.cursorrules` file.
- There is no `.github/copilot-instructions.md` file.
- Do not invent hidden conventions; follow the code that is actually here.

## If You Add Tooling or Rules
- Add the script or config to the repo in the same change.
- Document the new command or rule in this file.
- Prefer small, explicit tooling additions over heavy framework churn.
