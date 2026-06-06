import asyncio
import json
import os
from datetime import timedelta
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

os.environ["ENV"] = "test"

import main as main_module

from main import (  # noqa: E402
    AGENT_API_SECRET,
    ADMIN_AGENT_API_SECRET,
    APP_ENV,
    INVALIDATION_BROKER,
    Base,
    CORS_ALLOW_ORIGINS,
    INITIAL_USERNAMES,
    LOGIN_ATTEMPTS,
    LOGIN_BLOCK_DURATION,
    MAX_LOGIN_ATTEMPTS,
    MIN_PASSWORD_LENGTH,
    REMEMBER_ME_SESSION_TTL,
    SESSION_COOKIE_NAME,
    SESSION_COOKIE_SECURE,
    SessionLocal,
    SessionModel,
    TodoModel,
    User,
    ListModel,
    ListShareModel,
    app,
    engine,
    ensure_schema_compatibility,
    get_cookie_settings_for_request,
    get_password_hash,
    hash_session_id,
    seed_db,
    sync_invalidation_stream,
    utcnow,
    verify_password,
)


@pytest.fixture(scope="function")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True, scope="function")
def setup_db():
    LOGIN_ATTEMPTS.clear()
    with INVALIDATION_BROKER._lock:
        INVALIDATION_BROKER._versions.clear()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    seed_db()
    yield


def ensure_password_configured(username: str, password: str) -> None:
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    if user is not None and not cast(Any, user).hashed_password:
        cast(Any, user).hashed_password = get_password_hash(password)
    if user is not None:
        cast(Any, user).password_change_required = False
        db.commit()
    db.close()


def get_test_password(username: str) -> str:
    return {
        "frenchfaso": "pass12345",
        "clearpunch": "pass23456",
    }[username]


def set_password(client: TestClient, password: str, headers=None):
    request_headers = headers or {}
    return client.post(
        "/api/auth/set-password",
        json={"password": password},
        headers=request_headers,
    )


def login(
    client: TestClient,
    username: str = "frenchfaso",
    password: str = "pass12345",
    remember_me: bool = False,
    headers=None,
    prepare: bool = True,
):
    request_headers = headers or {}
    if prepare:
        ensure_password_configured(username, get_test_password(username))
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password, "remember_me": remember_me},
        headers=request_headers,
    )


def agent_headers(username: str = "frenchfaso", secret: str = AGENT_API_SECRET) -> dict[str, str]:
    return {
        "X-Agent-Secret": secret,
        "X-Acting-Username": username,
    }


def admin_agent_headers(secret: str = ADMIN_AGENT_API_SECRET) -> dict[str, str]:
    return {
        "X-Agent-Admin-Secret": secret,
    }


def test_login_success_sets_hardened_cookie(client):
    response = login(client)

    assert response.status_code == 200
    assert SESSION_COOKIE_NAME in response.cookies
    cookie_header = response.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie_header
    assert "SameSite=lax" in cookie_header
    if SESSION_COOKIE_SECURE:
        assert "Secure" in cookie_header


def test_production_http_login_rejects_insecure_transport(client):
    original_secure = main_module.SESSION_COOKIE_SECURE
    main_module.SESSION_COOKIE_SECURE = True
    try:
        response = login(client)

        assert response.status_code == 403
        assert response.json() == {"detail": "HTTPS required"}
    finally:
        main_module.SESSION_COOKIE_SECURE = original_secure


def test_production_forwarded_https_keeps_secure_cookie():
    original_secure = main_module.SESSION_COOKIE_SECURE
    main_module.SESSION_COOKIE_SECURE = True
    try:
        request = Request(
            {
                "type": "http",
                "scheme": "http",
                "method": "GET",
                "path": "/",
                "headers": [(b"x-forwarded-proto", b"https")],
                "query_string": b"",
                "server": ("testserver", 80),
                "client": ("127.0.0.1", 50000),
            }
        )

        assert get_cookie_settings_for_request(request)["secure"] is True
    finally:
        main_module.SESSION_COOKIE_SECURE = original_secure


def test_production_forwarded_https_requires_trusted_proxy():
    original_secure = main_module.SESSION_COOKIE_SECURE
    main_module.SESSION_COOKIE_SECURE = True
    try:
        request = Request(
            {
                "type": "http",
                "scheme": "http",
                "method": "GET",
                "path": "/",
                "headers": [(b"x-forwarded-proto", b"https")],
                "query_string": b"",
                "server": ("testserver", 80),
                "client": ("198.51.100.10", 50000),
            }
        )

        with pytest.raises(main_module.HTTPException) as exc_info:
            get_cookie_settings_for_request(request)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == "HTTPS required"
    finally:
        main_module.SESSION_COOKIE_SECURE = original_secure


def test_login_failure(client):
    response = login(client, password="wrong")

    assert response.status_code == 401
    assert SESSION_COOKIE_NAME not in response.cookies


def test_login_unknown_user_uses_same_failure_path(client):
    response = login(client, username="missing", password="pass12345", prepare=False)

    assert response.status_code == 401


def test_login_rate_limit_blocks_after_repeated_failures(client):
    for _ in range(MAX_LOGIN_ATTEMPTS):
        response = login(client, password="wrong")
        assert response.status_code == 401

    blocked = login(client, password="wrong")

    assert blocked.status_code == 429
    assert blocked.json()["detail"] == "Too many login attempts"


def test_successful_login_clears_rate_limit_state(client):
    login(client, password="wrong")

    response = login(client)

    assert response.status_code == 200
    assert LOGIN_ATTEMPTS == {}


def test_remember_me_behavior_sets_max_age_and_longer_server_expiry(client):
    response = login(client, remember_me=True)
    raw_session_id = response.cookies[SESSION_COOKIE_NAME]

    assert response.status_code == 200
    cookie_header = response.headers.get("set-cookie", "")
    assert "Max-Age=" in cookie_header

    db = SessionLocal()
    session = db.query(SessionModel).filter(SessionModel.session_id == hash_session_id(raw_session_id)).first()
    assert session is not None
    db_session = cast(Any, session)
    assert db_session.session_id != raw_session_id
    assert db_session.expires_at - db_session.created_at >= REMEMBER_ME_SESSION_TTL - timedelta(minutes=1)
    db.close()


def test_session_expiry_invalidates_protected_requests(client):
    response = login(client)
    session_id = response.cookies[SESSION_COOKIE_NAME]

    db = SessionLocal()
    session = db.query(SessionModel).filter(SessionModel.session_id == hash_session_id(session_id)).first()
    assert session is not None
    db_session = cast(Any, session)
    db_session.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    db.close()

    protected = client.get("/api/lists")

    assert protected.status_code == 401


def test_auth_me_returns_current_user(client):
    login(client)

    response = client.get("/api/auth/me")

    assert response.status_code == 200
    assert response.json() == {
        "id": "initial1",
        "username": "frenchfaso",
        "password_setup_required": False,
    }


def test_logout_clears_cookie_and_session(client):
    response = login(client)
    session_id = response.cookies[SESSION_COOKIE_NAME]

    logout_response = client.post("/api/auth/logout")

    assert logout_response.status_code == 200
    assert SESSION_COOKIE_NAME not in client.cookies
    cookie_header = logout_response.headers.get("set-cookie", "")
    assert f"{SESSION_COOKIE_NAME}=" in cookie_header

    db = SessionLocal()
    session = db.query(SessionModel).filter(SessionModel.session_id == hash_session_id(session_id)).first()
    db.close()
    assert session is None


def test_legacy_plaintext_sessions_are_migrated_to_hashes(client):
    db = SessionLocal()
    db.add(
        SessionModel(
            session_id="legacy-session",
            user_id="initial1",
            created_at=utcnow(),
            expires_at=utcnow() + timedelta(hours=1),
        )
    )
    db.commit()
    db.close()

    ensure_schema_compatibility()

    db = SessionLocal()
    legacy_session = db.query(SessionModel).filter(SessionModel.session_id == "legacy-session").first()
    migrated_session = db.query(SessionModel).filter(SessionModel.session_id == hash_session_id("legacy-session")).first()
    db.close()

    assert legacy_session is None
    assert migrated_session is not None

    client.cookies.set(SESSION_COOKIE_NAME, "legacy-session")
    response = client.get("/api/auth/me")

    assert response.status_code == 200
    assert response.json()["username"] == "frenchfaso"


def test_logout_over_http_rejects_insecure_transport(client):
    original_secure = main_module.SESSION_COOKIE_SECURE
    main_module.SESSION_COOKIE_SECURE = True
    try:
        db = SessionLocal()
        session = SessionModel(
            session_id="session-test",
            user_id="initial1",
            created_at=utcnow(),
            expires_at=utcnow() + timedelta(hours=1),
        )
        db.add(session)
        db.commit()
        db.close()

        client.cookies.set(SESSION_COOKIE_NAME, "session-test")

        logout_response = client.post("/api/auth/logout")

        assert logout_response.status_code == 403
        assert logout_response.json() == {"detail": "HTTPS required"}

        db = SessionLocal()
        session = db.query(SessionModel).filter(SessionModel.session_id == "session-test").first()
        db.close()
        assert session is not None
    finally:
        main_module.SESSION_COOKIE_SECURE = original_secure


def test_unauthenticated_access(client):
    response = client.get("/api/lists")

    assert response.status_code == 401


def test_mutation_rejects_untrusted_origin(client):
    login(client)

    response = client.post(
        "/api/lists",
        json={"id": "l1", "name": "My List"},
        headers={"origin": "https://evil.example"},
    )

    assert response.status_code == 403


def test_login_rejects_malformed_origin(client):
    response = login(client, headers={"origin": "javascript:alert(1)"})

    assert response.status_code == 403


def test_allowed_origin_login_succeeds(client):
    response = login(client, headers={"origin": CORS_ALLOW_ORIGINS[0]})

    assert response.status_code == 200


def test_seed_db_creates_initial_users_without_passwords():
    db = SessionLocal()
    users = db.query(User).order_by(User.username).all()
    db.close()

    assert [cast(Any, user).username for user in users] == sorted(INITIAL_USERNAMES)
    assert all(cast(Any, user).hashed_password == "" for user in users)
    assert all(cast(Any, user).password_change_required is True for user in users)


def test_production_seed_does_not_create_passwordless_initial_users(monkeypatch):
    monkeypatch.setattr(main_module, "APP_ENV", "production")
    monkeypatch.delenv("WEDO_INITIAL_PASSWORD", raising=False)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    seed_db()

    db = SessionLocal()
    users = db.query(User).all()
    db.close()
    assert users == []


def test_production_seed_uses_initial_password_as_temporary_password(monkeypatch):
    monkeypatch.setattr(main_module, "APP_ENV", "production")
    monkeypatch.setenv("WEDO_INITIAL_PASSWORD", "temporary-pass-123")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    seed_db()

    db = SessionLocal()
    users = db.query(User).order_by(User.username).all()
    db.close()

    assert [cast(Any, user).username for user in users] == sorted(INITIAL_USERNAMES)
    assert all(verify_password("temporary-pass-123", cast(Any, user).hashed_password) for user in users)
    assert all(cast(Any, user).password_change_required is True for user in users)


def test_first_login_without_password_requires_password_setup(client):
    response = login(client, password="", prepare=False)

    assert response.status_code == 200
    assert response.json() == {"message": "Logged in", "password_setup_required": True}

    me_response = client.get("/api/auth/me")

    assert me_response.status_code == 200
    assert me_response.json() == {
        "id": "initial1",
        "username": "frenchfaso",
        "password_setup_required": True,
    }


def test_password_setup_hashes_password_and_unlocks_access(client):
    login_response = login(client, password="", prepare=False)

    assert login_response.status_code == 200

    set_password_response = set_password(client, "newpass123")

    assert set_password_response.status_code == 200
    assert set_password_response.json() == {
        "id": "initial1",
        "username": "frenchfaso",
        "password_setup_required": False,
    }

    db = SessionLocal()
    user = db.query(User).filter(User.username == "frenchfaso").first()
    assert user is not None
    hashed_password = cast(Any, user).hashed_password
    assert hashed_password != "newpass123"
    assert verify_password("newpass123", hashed_password) is True
    assert cast(Any, user).password_change_required is False
    db.close()

    lists_response = client.get("/api/lists")

    assert lists_response.status_code == 200
    assert lists_response.json() == []


def test_protected_routes_are_blocked_until_password_is_set(client):
    login_response = login(client, password="", prepare=False)

    assert login_response.status_code == 200

    lists_response = client.get("/api/lists")
    pull_response = client.post("/api/sync/pull", json={"collection": "lists", "limit": 10})

    assert lists_response.status_code == 403
    assert lists_response.json() == {"detail": "Password setup required"}
    assert pull_response.status_code == 403
    assert pull_response.json() == {"detail": "Password setup required"}


def test_password_setup_rejects_short_passwords(client):
    login(client, password="", prepare=False)

    response = set_password(client, "short")

    assert response.status_code == 422
    assert response.json() == {"detail": f"Password must be at least {MIN_PASSWORD_LENGTH} characters"}


def test_password_setup_rejects_blank_and_too_long_passwords(client):
    login(client, password="", prepare=False)

    blank_response = set_password(client, "   ")
    too_long_response = set_password(client, "x" * 201)

    assert blank_response.status_code == 422
    assert blank_response.json() == {"detail": "Password cannot be blank"}
    assert too_long_response.status_code == 422
    assert too_long_response.json() == {"detail": "Password is too long"}


def test_password_setup_rejects_untrusted_origin(client):
    login(client, password="", prepare=False)

    response = set_password(client, "newpass123", headers={"origin": "https://evil.example"})

    assert response.status_code == 403
    assert response.json() == {"detail": "Origin not allowed"}


def test_logout_rejects_untrusted_origin_and_keeps_session(client):
    login(client)

    logout_response = client.post("/api/auth/logout", headers={"origin": "https://evil.example"})
    me_response = client.get("/api/auth/me")

    assert logout_response.status_code == 403
    assert logout_response.json() == {"detail": "Origin not allowed"}
    assert me_response.status_code == 200


def test_api_responses_include_security_headers(client):
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"


def test_spa_path_traversal_falls_back_to_index(client):
    response = client.get("/..%2Fmain.py")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-cache"
    assert "<!DOCTYPE html>" in response.text
    assert "from datetime import UTC" not in response.text


def test_unknown_api_get_returns_404_instead_of_spa(client):
    response = client.get("/api/not-a-real-route")

    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}


def test_sync_push_rejects_excessive_row_batch(client):
    login(client)

    rows = [
        {
            "assumedMasterState": None,
            "newDocumentState": {
                "id": f"l_{index}",
                "owner_id": "ignored",
                "name": f"List {index}",
                "archived": False,
                "created_at": "2026-03-13T12:00:00.000000Z",
                "updated_at": "2026-03-13T12:00:00.000000Z",
                "_deleted": False,
            },
        }
        for index in range(101)
    ]

    response = client.post("/api/sync/push", json={"collection": "lists", "rows": rows})

    assert response.status_code == 422


def test_sync_push_rejects_invalid_list_document_types(client):
    login(client)

    response = client.post(
        "/api/sync/push",
        json={
            "collection": "lists",
            "rows": [
                {
                    "assumedMasterState": None,
                    "newDocumentState": {
                        "id": "l_bad",
                        "name": "Bad List",
                        "archived": "false",
                        "_deleted": False,
                    },
                }
            ],
        },
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid list document"}


def test_sync_push_rejects_invalid_todo_document_types(client):
    login(client)

    response = client.post(
        "/api/sync/push",
        json={
            "collection": "todos",
            "rows": [
                {
                    "assumedMasterState": None,
                    "newDocumentState": {
                        "id": "t_bad",
                        "list_id": "l_bad",
                        "title": "Bad Todo",
                        "done": "false",
                        "_deleted": False,
                    },
                }
            ],
        },
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid todo document"}


def test_sync_pull_rejects_invalid_checkpoint_timestamp(client):
    login(client)

    response = client.post(
        "/api/sync/pull",
        json={
            "collection": "lists",
            "limit": 10,
            "checkpoint": {"id": "l1", "updated_at": "not-a-date"},
        },
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid checkpoint updated_at"}


def test_sync_push_rejects_invalid_document_timestamp(client):
    login(client)

    response = client.post(
        "/api/sync/push",
        json={
            "collection": "lists",
            "rows": [
                {
                    "assumedMasterState": None,
                    "newDocumentState": {
                        "id": "l_bad_date",
                        "name": "Bad Date",
                        "archived": False,
                        "created_at": "not-a-date",
                        "_deleted": False,
                    },
                }
            ],
        },
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid created_at"}


def test_crud_lists_and_blank_name_rejection(client):
    login(client)

    create_response = client.post("/api/lists", json={"id": "l1", "name": "My List"})
    assert create_response.status_code == 200

    duplicate_response = client.post("/api/lists", json={"id": "l1", "name": "Other"})
    assert duplicate_response.status_code == 409

    blank_name_response = client.put("/api/lists/l1", json={"name": "   "})
    assert blank_name_response.status_code == 422

    rename_response = client.put("/api/lists/l1", json={"name": "New Name", "archived": True})
    assert rename_response.status_code == 200
    assert rename_response.json() == {"id": "l1", "name": "New Name", "archived": True}

    lists_response = client.get("/api/lists")
    assert lists_response.status_code == 200
    assert lists_response.json() == [
        {
            "id": "l1",
            "name": "New Name",
            "archived": True,
            "access_role": "owner",
            "shared_with_count": 0,
            "owner_username": "frenchfaso",
        }
    ]

    delete_response = client.delete("/api/lists/l1")
    assert delete_response.status_code == 200
    assert client.get("/api/lists").json() == []


def test_delete_list_cascades_todos(client):
    login(client)
    client.post("/api/lists", json={"id": "l1", "name": "My List"})
    client.post("/api/todos", json={"id": "t1", "list_id": "l1", "title": "Buy milk"})

    response = client.delete("/api/lists/l1")

    assert response.status_code == 200
    assert client.get("/api/todos").json() == []

    db = SessionLocal()
    deleted_list = db.query(ListModel).filter(ListModel.id == "l1").first()
    deleted_todo = db.query(TodoModel).filter(TodoModel.id == "t1").first()
    assert deleted_list is not None
    assert deleted_todo is not None
    db_list = cast(Any, deleted_list)
    db_todo = cast(Any, deleted_todo)
    assert db_list.deleted is True
    assert db_todo.deleted is True
    db.close()


def test_crud_todos_and_done_to_undone_transition(client):
    login(client)
    client.post("/api/lists", json={"id": "l1", "name": "My List"})

    create_response = client.post("/api/todos", json={"id": "t1", "list_id": "l1", "title": "Buy milk"})
    assert create_response.status_code == 200

    duplicate_response = client.post("/api/todos", json={"id": "t1", "list_id": "l1", "title": "Copy"})
    assert duplicate_response.status_code == 409

    done_response = client.put("/api/todos/t1", json={"title": "Buy almond milk", "done": True})
    assert done_response.status_code == 200
    assert done_response.json()["done"] is True

    undone_response = client.put("/api/todos/t1", json={"done": False})
    assert undone_response.status_code == 200
    assert undone_response.json() == {
        "id": "t1",
        "list_id": "l1",
        "title": "Buy almond milk",
        "done": False,
    }

    blank_title_response = client.put("/api/todos/t1", json={"title": "   "})
    assert blank_title_response.status_code == 422

    delete_response = client.delete("/api/todos/t1")
    assert delete_response.status_code == 200
    assert client.get("/api/todos").json() == []


def test_create_todo_requires_owned_list(client):
    login(client, username="clearpunch", password="pass23456")

    response = client.post("/api/todos", json={"id": "t1", "list_id": "missing", "title": "Nope"})

    assert response.status_code == 404


def test_auth_isolation_for_lists_and_todos(client):
    login(client)
    client.post("/api/lists", json={"id": "l_user1", "name": "User 1 List"})
    client.post("/api/todos", json={"id": "t_user1", "list_id": "l_user1", "title": "Secret"})
    client.post("/api/auth/logout")

    login(client, username="clearpunch", password="pass23456")

    lists_response = client.get("/api/lists")
    todos_response = client.get("/api/todos")
    rename_response = client.put("/api/lists/l_user1", json={"name": "Hacked"})
    todo_response = client.put("/api/todos/t_user1", json={"done": True})

    assert lists_response.json() == []
    assert todos_response.json() == []
    assert rename_response.status_code == 404
    assert todo_response.status_code == 404


def test_owner_can_share_and_revoke_list_access(client):
    login(client)
    client.post("/api/lists", json={"id": "l_share", "name": "Shared List"})

    share_response = client.post("/api/lists/l_share/shares", json={"username": "clearpunch"})

    assert share_response.status_code == 200
    assert share_response.json()["username"] == "clearpunch"

    shares_response = client.get("/api/lists/l_share/shares")
    assert shares_response.status_code == 200
    assert shares_response.json()["members"] == [
        {
            "user_id": "initial2",
            "username": "clearpunch",
            "created_at": share_response.json()["created_at"],
        }
    ]

    revoke_response = client.delete("/api/lists/l_share/shares/initial2")
    assert revoke_response.status_code == 200

    db = SessionLocal()
    share = db.query(ListShareModel).filter(ListShareModel.list_id == "l_share", ListShareModel.user_id == "initial2").first()
    assert share is not None
    assert cast(Any, share).deleted is True
    db.close()


def test_shared_user_sees_shared_list_and_can_crud_todos_only(client):
    login(client)
    client.post("/api/lists", json={"id": "l_shared", "name": "Groceries"})
    client.post("/api/lists/l_shared/shares", json={"username": "clearpunch"})
    client.post("/api/todos", json={"id": "t_owner", "list_id": "l_shared", "title": "Milk"})
    client.post("/api/auth/logout")

    login(client, username="clearpunch", password="pass23456")

    lists_response = client.get("/api/lists")
    assert lists_response.status_code == 200
    assert lists_response.json() == [
        {
            "id": "l_shared",
            "name": "Groceries",
            "archived": False,
            "access_role": "shared",
            "shared_with_count": 0,
            "owner_username": "frenchfaso",
        }
    ]

    todos_response = client.get("/api/todos")
    assert todos_response.status_code == 200
    assert todos_response.json() == [{"id": "t_owner", "list_id": "l_shared", "title": "Milk", "done": False}]

    create_todo = client.post("/api/todos", json={"id": "t_shared", "list_id": "l_shared", "title": "Bread"})
    assert create_todo.status_code == 200

    update_todo = client.put("/api/todos/t_shared", json={"title": "Bread slices", "done": True})
    assert update_todo.status_code == 200
    assert update_todo.json()["done"] is True

    delete_todo = client.delete("/api/todos/t_shared")
    assert delete_todo.status_code == 200

    rename_list = client.put("/api/lists/l_shared", json={"name": "New Name"})
    delete_list = client.delete("/api/lists/l_shared")
    share_list = client.post("/api/lists/l_shared/shares", json={"username": "frenchfaso"})

    assert rename_list.status_code == 404
    assert delete_list.status_code == 404
    assert share_list.status_code == 404


def test_shared_user_cannot_view_share_management(client):
    login(client)
    client.post("/api/lists", json={"id": "l_shared_manage", "name": "Chores"})
    client.post("/api/lists/l_shared_manage/shares", json={"username": "clearpunch"})
    client.post("/api/auth/logout")

    login(client, username="clearpunch", password="pass23456")

    response = client.get("/api/lists/l_shared_manage/shares")

    assert response.status_code == 404


def test_admin_agent_routes_require_admin_secret(client):
    missing_secret = client.post("/api/agent/admin/users", json={"username": "mario"})
    wrong_secret = client.post(
        "/api/agent/admin/users",
        json={"username": "mario"},
        headers=admin_agent_headers(secret="wrong-secret"),
    )
    regular_agent_secret = client.post(
        "/api/agent/admin/users",
        json={"username": "mario"},
        headers={"X-Agent-Admin-Secret": AGENT_API_SECRET},
    )

    assert missing_secret.status_code == 401
    assert missing_secret.json() == {"detail": "Invalid admin agent secret"}
    assert wrong_secret.status_code == 401
    assert wrong_secret.json() == {"detail": "Invalid admin agent secret"}
    assert regular_agent_secret.status_code == 401
    assert regular_agent_secret.json() == {"detail": "Invalid admin agent secret"}


def test_agent_routes_return_503_when_secret_is_not_configured(client):
    original_agent_secret = main_module.AGENT_API_SECRET
    original_admin_secret = main_module.ADMIN_AGENT_API_SECRET
    main_module.AGENT_API_SECRET = ""
    main_module.ADMIN_AGENT_API_SECRET = ""
    try:
        agent_response = client.post(
            "/api/agent/lists",
            json={"name": "Agent List"},
            headers=agent_headers(),
        )
        admin_response = client.post(
            "/api/agent/admin/users",
            json={"username": "mario"},
            headers=admin_agent_headers(),
        )

        assert agent_response.status_code == 503
        assert agent_response.json() == {"detail": "Agent API not configured"}
        assert admin_response.status_code == 503
        assert admin_response.json() == {"detail": "Admin agent API not configured"}
    finally:
        main_module.AGENT_API_SECRET = original_agent_secret
        main_module.ADMIN_AGENT_API_SECRET = original_admin_secret


def test_admin_agent_create_user_returns_temporary_password_and_requires_change(client):
    create_response = client.post(
        "/api/agent/admin/users",
        json={"username": "mario"},
        headers=admin_agent_headers(),
    )

    assert create_response.status_code == 200
    payload = create_response.json()
    assert payload["id"].startswith("user_")
    assert payload["username"] == "mario"
    assert len(payload["temporary_password"]) >= MIN_PASSWORD_LENGTH
    assert payload["password_setup_required"] is True

    db = SessionLocal()
    user = db.query(User).filter(User.username == "mario").first()
    assert user is not None
    db_user = cast(Any, user)
    assert db_user.hashed_password != payload["temporary_password"]
    assert verify_password(payload["temporary_password"], db_user.hashed_password) is True
    assert db_user.password_change_required is True
    db.close()

    login_response = login(
        client,
        username="mario",
        password=payload["temporary_password"],
        prepare=False,
    )
    assert login_response.status_code == 200
    assert login_response.json() == {"message": "Logged in", "password_setup_required": True}

    blocked_response = client.get("/api/lists")
    assert blocked_response.status_code == 403

    set_password_response = set_password(client, "mario-final-password")
    assert set_password_response.status_code == 200
    assert set_password_response.json()["password_setup_required"] is False
    assert client.get("/api/lists").status_code == 200

    client.post("/api/auth/logout")
    final_login_response = login(
        client,
        username="mario",
        password="mario-final-password",
        prepare=False,
    )
    assert final_login_response.status_code == 200
    assert final_login_response.json()["password_setup_required"] is False


def test_admin_agent_create_user_rejects_duplicate_username(client):
    first_response = client.post(
        "/api/agent/admin/users",
        json={"username": "mario"},
        headers=admin_agent_headers(),
    )
    duplicate_response = client.post(
        "/api/agent/admin/users",
        json={"username": "mario"},
        headers=admin_agent_headers(),
    )

    assert first_response.status_code == 200
    assert duplicate_response.status_code == 409
    assert duplicate_response.json() == {"detail": "User already exists"}


def test_admin_agent_reset_password_returns_temporary_password_and_invalidates_sessions(client):
    login_response = login(client)
    assert login_response.status_code == 200

    reset_response = client.post(
        "/api/agent/admin/users/frenchfaso/reset-password",
        headers=admin_agent_headers(),
    )

    assert reset_response.status_code == 200
    payload = reset_response.json()
    assert payload["id"] == "initial1"
    assert payload["username"] == "frenchfaso"
    assert len(payload["temporary_password"]) >= MIN_PASSWORD_LENGTH
    assert payload["password_setup_required"] is True

    old_session_response = client.get("/api/auth/me")
    assert old_session_response.status_code == 401

    old_password_response = login(client, password="pass12345", prepare=False)
    assert old_password_response.status_code == 401

    temporary_login_response = login(
        client,
        password=payload["temporary_password"],
        prepare=False,
    )
    assert temporary_login_response.status_code == 200
    assert temporary_login_response.json()["password_setup_required"] is True

    db = SessionLocal()
    user = db.query(User).filter(User.username == "frenchfaso").first()
    assert user is not None
    assert cast(Any, user).password_change_required is True
    db.close()


def test_admin_agent_reset_password_returns_404_for_missing_user(client):
    response = client.post(
        "/api/agent/admin/users/missing/reset-password",
        headers=admin_agent_headers(),
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}


def test_agent_routes_require_secret_and_acting_user(client):
    missing_secret = client.post("/api/agent/lists", json={"name": "Agent List"}, headers={"X-Acting-Username": "frenchfaso"})
    wrong_secret = client.post(
        "/api/agent/lists",
        json={"name": "Agent List"},
        headers=agent_headers(secret="wrong-secret"),
    )
    missing_acting_user = client.post(
        "/api/agent/lists",
        json={"name": "Agent List"},
        headers={"X-Agent-Secret": AGENT_API_SECRET},
    )
    missing_user = client.post(
        "/api/agent/lists",
        json={"name": "Agent List"},
        headers=agent_headers(username="missing"),
    )

    assert missing_secret.status_code == 401
    assert missing_secret.json() == {"detail": "Invalid agent secret"}
    assert wrong_secret.status_code == 401
    assert wrong_secret.json() == {"detail": "Invalid agent secret"}
    assert missing_acting_user.status_code == 422
    assert missing_acting_user.json() == {"detail": "Acting username is required"}
    assert missing_user.status_code == 404
    assert missing_user.json() == {"detail": "Acting user not found"}


def test_agent_create_list_generates_id_when_missing(client):
    response = client.post("/api/agent/lists", json={"name": "Agent List"}, headers=agent_headers())

    assert response.status_code == 200
    payload = response.json()
    assert payload["id"].startswith("list_")
    assert payload["name"] == "Agent List"
    assert payload["archived"] is False

    db = SessionLocal()
    created = db.query(ListModel).filter(ListModel.id == payload["id"]).first()
    assert created is not None
    assert cast(Any, created).owner_id == "initial1"
    db.close()


def test_agent_create_list_validates_supplied_id(client):
    blank_id = client.post("/api/agent/lists", json={"id": "   ", "name": "Agent List"}, headers=agent_headers())
    custom_id = client.post("/api/agent/lists", json={"id": "agent_list_1", "name": "Agent List"}, headers=agent_headers())

    assert blank_id.status_code == 422
    assert blank_id.json() == {"detail": "list id cannot be blank"}
    assert custom_id.status_code == 200
    assert custom_id.json()["id"] == "agent_list_1"


def test_agent_routes_share_add_and_remove_items(client):
    create_list_response = client.post(
        "/api/agent/lists",
        json={"id": "agent_list", "name": "Agent Shared List"},
        headers=agent_headers(),
    )
    assert create_list_response.status_code == 200

    share_response = client.post(
        "/api/agent/lists/agent_list/shares",
        json={"username": "clearpunch"},
        headers=agent_headers(),
    )
    assert share_response.status_code == 200
    assert share_response.json()["username"] == "clearpunch"

    create_item_response = client.post(
        "/api/agent/lists/agent_list/items",
        json={"title": "Bread"},
        headers=agent_headers(username="clearpunch"),
    )
    assert create_item_response.status_code == 200
    item_payload = create_item_response.json()
    assert item_payload["id"].startswith("todo_")
    assert item_payload["list_id"] == "agent_list"
    assert item_payload["title"] == "Bread"
    assert item_payload["done"] is False

    delete_response = client.delete(
        f"/api/agent/lists/agent_list/items/{item_payload['id']}",
        headers=agent_headers(username="clearpunch"),
    )
    assert delete_response.status_code == 200
    assert delete_response.json() == {"message": "Deleted"}

    db = SessionLocal()
    share = db.query(ListShareModel).filter(ListShareModel.list_id == "agent_list", ListShareModel.user_id == "initial2").first()
    todo = db.query(TodoModel).filter(TodoModel.id == item_payload["id"]).first()
    assert share is not None
    assert todo is not None
    assert cast(Any, share).deleted is False
    assert cast(Any, todo).deleted is True
    db.close()


def test_agent_update_item_reuses_todo_edit_rules(client):
    client.post(
        "/api/agent/lists",
        json={"id": "agent_edit_list", "name": "Agent Edit List"},
        headers=agent_headers(),
    )
    client.post(
        "/api/agent/lists/agent_edit_list/shares",
        json={"username": "clearpunch"},
        headers=agent_headers(),
    )
    client.post(
        "/api/agent/lists/agent_edit_list/items",
        json={"id": "agent_edit_item", "title": "Buy milk"},
        headers=agent_headers(),
    )

    update_response = client.put(
        "/api/agent/lists/agent_edit_list/items/agent_edit_item",
        json={"title": "Buy milk 🥛", "done": True},
        headers=agent_headers(username="clearpunch"),
    )

    assert update_response.status_code == 200
    assert update_response.json() == {
        "id": "agent_edit_item",
        "list_id": "agent_edit_list",
        "title": "Buy milk 🥛",
        "done": True,
    }

    db = SessionLocal()
    todo = db.query(TodoModel).filter(TodoModel.id == "agent_edit_item").first()
    assert todo is not None
    db_todo = cast(Any, todo)
    assert db_todo.title == "Buy milk 🥛"
    assert db_todo.done is True
    db.close()


def test_agent_update_item_validates_list_access_and_blank_title(client):
    client.post(
        "/api/agent/lists",
        json={"id": "agent_update_guard", "name": "Guarded Edit List"},
        headers=agent_headers(),
    )
    client.post(
        "/api/agent/lists/agent_update_guard/items",
        json={"id": "agent_update_item", "title": "Milk"},
        headers=agent_headers(),
    )

    wrong_list_response = client.put(
        "/api/agent/lists/another_list/items/agent_update_item",
        json={"title": "Bread"},
        headers=agent_headers(),
    )
    blank_title_response = client.put(
        "/api/agent/lists/agent_update_guard/items/agent_update_item",
        json={"title": "   "},
        headers=agent_headers(),
    )

    assert wrong_list_response.status_code == 404
    assert blank_title_response.status_code == 422
    assert blank_title_response.json() == {"detail": "todo title cannot be blank"}


def test_agent_delete_item_requires_matching_list_access(client):
    client.post(
        "/api/agent/lists",
        json={"id": "agent_list_guard", "name": "Guarded List"},
        headers=agent_headers(),
    )
    client.post(
        "/api/agent/lists/agent_list_guard/items",
        json={"id": "agent_item_guard", "title": "Milk"},
        headers=agent_headers(),
    )

    wrong_list_response = client.delete(
        "/api/agent/lists/another_list/items/agent_item_guard",
        headers=agent_headers(),
    )

    assert wrong_list_response.status_code == 404

def test_sync_pull_returns_documents_and_checkpoint(client):
    login(client)

    client.post("/api/lists", json={"id": "l1", "name": "Groceries"})
    client.post("/api/lists", json={"id": "l2", "name": "Hardware"})

    pull_response = client.post("/api/sync/pull", json={"collection": "lists", "limit": 1})

    assert pull_response.status_code == 200
    payload = pull_response.json()
    assert len(payload["documents"]) == 1
    assert payload["documents"][0]["name"] in {"Groceries", "Hardware"}
    assert payload["checkpoint"]["id"] == payload["documents"][0]["id"]
    assert payload["checkpoint"]["updated_at"] == payload["documents"][0]["updated_at"]


def test_sync_pull_uses_checkpoint_ordering(client):
    login(client)

    client.post("/api/lists", json={"id": "l1", "name": "Groceries"})
    first_pull = client.post("/api/sync/pull", json={"collection": "lists", "limit": 1})
    first_payload = first_pull.json()
    client.post("/api/lists", json={"id": "l2", "name": "Hardware"})

    second_pull = client.post(
        "/api/sync/pull",
        json={
            "collection": "lists",
            "limit": 10,
            "checkpoint": first_payload["checkpoint"],
        },
    )

    assert second_pull.status_code == 200
    second_payload = second_pull.json()
    ids = [document["id"] for document in second_payload["documents"]]
    assert "l1" not in ids
    assert "l2" in ids


def test_sync_invalidation_stream_emits_resync_event_for_user():
    db = SessionLocal()
    user = db.query(User).filter(User.username == "frenchfaso").first()
    assert user is not None
    user_id = str(cast(Any, user).id)

    async def collect_event():
        response = await sync_invalidation_stream(user_id=user_id)
        body_iterator = cast(Any, response.body_iterator).__aiter__()
        next_chunk = asyncio.create_task(anext(body_iterator))
        await asyncio.sleep(0.05)
        INVALIDATION_BROKER.publish({user_id})
        chunk = await asyncio.wait_for(next_chunk, timeout=1)
        aclose = getattr(body_iterator, "aclose", None)
        if callable(aclose):
            await cast(Any, aclose)()
        return response, chunk

    response, chunk = asyncio.run(collect_event())
    db.close()

    assert response.media_type == "text/event-stream"
    assert response.headers["X-Accel-Buffering"] == "no"
    assert json.loads(chunk.removeprefix("data: ").strip())["type"] == "RESYNC"


def test_agent_and_share_mutations_publish_user_invalidations(client):
    login(client)
    create_list_response = client.post("/api/lists", json={"id": "l_inv", "name": "Invalidate Me"})
    assert create_list_response.status_code == 200

    owner_version_before_share = INVALIDATION_BROKER.get_version("initial1")
    collaborator_version_before_share = INVALIDATION_BROKER.get_version("initial2")

    share_response = client.post("/api/lists/l_inv/shares", json={"username": "clearpunch"})

    assert share_response.status_code == 200
    assert INVALIDATION_BROKER.get_version("initial1") > owner_version_before_share
    assert INVALIDATION_BROKER.get_version("initial2") > collaborator_version_before_share

    owner_version_before_agent = INVALIDATION_BROKER.get_version("initial1")
    collaborator_version_before_agent = INVALIDATION_BROKER.get_version("initial2")

    agent_item_response = client.post(
        "/api/agent/lists/l_inv/items",
        json={"id": "t_inv", "title": "Server-side item"},
        headers=agent_headers(username="clearpunch"),
    )

    assert agent_item_response.status_code == 200
    assert INVALIDATION_BROKER.get_version("initial1") > owner_version_before_agent
    assert INVALIDATION_BROKER.get_version("initial2") > collaborator_version_before_agent


def test_sync_push_creates_and_updates_list_documents(client):
    login(client)

    create_response = client.post(
        "/api/sync/push",
        json={
            "collection": "lists",
            "rows": [
                {
                    "assumedMasterState": None,
                    "newDocumentState": {
                        "id": "l_sync",
                        "owner_id": "ignored",
                        "name": "Synced List",
                        "archived": False,
                        "created_at": "2026-03-13T12:00:00.000000Z",
                        "updated_at": "2026-03-13T12:00:00.000000Z",
                        "_deleted": False,
                    },
                }
            ],
        },
    )

    assert create_response.status_code == 200
    assert create_response.json() == []

    db = SessionLocal()
    created = db.query(ListModel).filter(ListModel.id == "l_sync").first()
    assert created is not None
    db_list = cast(Any, created)
    assert db_list.owner_id == "initial1"
    assert db_list.name == "Synced List"

    assumed_master = {
        "id": "l_sync",
        "owner_id": db_list.owner_id,
        "name": db_list.name,
        "archived": db_list.archived,
        "created_at": db_list.created_at.isoformat() + "Z",
        "updated_at": db_list.updated_at.isoformat() + "Z",
        "_deleted": db_list.deleted,
    }
    db.close()

    update_response = client.post(
        "/api/sync/push",
        json={
            "collection": "lists",
            "rows": [
                {
                    "assumedMasterState": assumed_master,
                    "newDocumentState": {
                        **assumed_master,
                        "name": "Renamed Sync List",
                    },
                }
            ],
        },
    )

    assert update_response.status_code == 200
    assert update_response.json() == []

    db = SessionLocal()
    updated = db.query(ListModel).filter(ListModel.id == "l_sync").first()
    assert updated is not None
    assert cast(Any, updated).name == "Renamed Sync List"
    db.close()


def test_sync_push_returns_conflict_when_master_is_newer(client):
    login(client)
    client.post("/api/lists", json={"id": "l1", "name": "Original"})

    db = SessionLocal()
    list_row = db.query(ListModel).filter(ListModel.id == "l1").first()
    assert list_row is not None
    db_list = cast(Any, list_row)
    stale_assumed = {
        "id": db_list.id,
        "owner_id": db_list.owner_id,
        "name": db_list.name,
        "archived": db_list.archived,
        "created_at": db_list.created_at.isoformat() + "Z",
        "updated_at": db_list.updated_at.isoformat() + "Z",
        "_deleted": db_list.deleted,
    }
    db_list.name = "Server Changed"
    db_list.updated_at = utcnow()
    db.commit()
    db.close()

    push_response = client.post(
        "/api/sync/push",
        json={
            "collection": "lists",
            "rows": [
                {
                    "assumedMasterState": stale_assumed,
                    "newDocumentState": {
                        **stale_assumed,
                        "name": "Client Changed",
                    },
                }
            ],
        },
    )

    assert push_response.status_code == 200
    conflicts = push_response.json()
    assert len(conflicts) == 1
    assert conflicts[0]["name"] == "Server Changed"


def test_sync_pull_includes_deleted_tombstones(client):
    login(client)
    client.post("/api/lists", json={"id": "l1", "name": "Groceries"})
    client.delete("/api/lists/l1")

    pull_response = client.post("/api/sync/pull", json={"collection": "lists", "limit": 10})

    assert pull_response.status_code == 200
    documents = pull_response.json()["documents"]
    deleted_doc = next(document for document in documents if document["id"] == "l1")
    assert deleted_doc["_deleted"] is True


def test_sync_push_list_tombstone_cascades_child_todo_tombstones(client):
    login(client)

    create_list_response = client.post(
        "/api/sync/push",
        json={
            "collection": "lists",
            "rows": [
                {
                    "assumedMasterState": None,
                    "newDocumentState": {
                        "id": "l_sync_delete",
                        "owner_id": "ignored",
                        "name": "Delete Me",
                        "archived": False,
                        "created_at": "2026-03-13T12:00:00.000000Z",
                        "updated_at": "2026-03-13T12:00:00.000000Z",
                        "_deleted": False,
                    },
                }
            ],
        },
    )
    assert create_list_response.status_code == 200

    create_todo_response = client.post(
        "/api/sync/push",
        json={
            "collection": "todos",
            "rows": [
                {
                    "assumedMasterState": None,
                    "newDocumentState": {
                        "id": "t_sync_delete",
                        "list_id": "l_sync_delete",
                        "title": "Child todo",
                        "done": False,
                        "created_at": "2026-03-13T12:00:00.000000Z",
                        "updated_at": "2026-03-13T12:00:00.000000Z",
                        "_deleted": False,
                    },
                }
            ],
        },
    )
    assert create_todo_response.status_code == 200

    db = SessionLocal()
    list_row = db.query(ListModel).filter(ListModel.id == "l_sync_delete").first()
    assert list_row is not None
    db_list = cast(Any, list_row)
    assumed_master = {
        "id": db_list.id,
        "owner_id": db_list.owner_id,
        "name": db_list.name,
        "archived": db_list.archived,
        "created_at": db_list.created_at.isoformat() + "Z",
        "updated_at": db_list.updated_at.isoformat() + "Z",
        "_deleted": db_list.deleted,
    }
    db.close()

    delete_response = client.post(
        "/api/sync/push",
        json={
            "collection": "lists",
            "rows": [
                {
                    "assumedMasterState": assumed_master,
                    "newDocumentState": {
                        **assumed_master,
                        "_deleted": True,
                    },
                }
            ],
        },
    )

    assert delete_response.status_code == 200
    todo_pull = client.post("/api/sync/pull", json={"collection": "todos", "limit": 20})
    assert todo_pull.status_code == 200
    deleted_todo = next(document for document in todo_pull.json()["documents"] if document["id"] == "t_sync_delete")
    assert deleted_todo["_deleted"] is True


def test_sync_push_todo_requires_accessible_parent_list(client):
    login(client)

    push_response = client.post(
        "/api/sync/push",
        json={
            "collection": "todos",
            "rows": [
                {
                    "assumedMasterState": None,
                    "newDocumentState": {
                        "id": "t_missing",
                        "list_id": "missing",
                        "title": "Nope",
                        "done": False,
                        "created_at": "2026-03-13T12:00:00.000000Z",
                        "updated_at": "2026-03-13T12:00:00.000000Z",
                        "_deleted": False,
                    },
                }
            ],
        },
    )

    assert push_response.status_code == 409
    assert push_response.json()["detail"] == "Todo list is not accessible"


def test_sync_push_rejects_live_todo_for_deleted_parent_list(client):
    login(client)
    client.post("/api/lists", json={"id": "l1", "name": "Groceries"})
    client.delete("/api/lists/l1")

    push_response = client.post(
        "/api/sync/push",
        json={
            "collection": "todos",
            "rows": [
                {
                    "assumedMasterState": None,
                    "newDocumentState": {
                        "id": "t_deleted_parent",
                        "list_id": "l1",
                        "title": "Should fail",
                        "done": False,
                        "created_at": "2026-03-13T12:00:00.000000Z",
                        "updated_at": "2026-03-13T12:00:00.000000Z",
                        "_deleted": False,
                    },
                }
            ],
        },
    )

    assert push_response.status_code == 409
    assert push_response.json()["detail"] == "Todo list is not accessible"


def test_sync_isolation_only_returns_current_users_documents(client):
    login(client)
    client.post("/api/lists", json={"id": "l_user1", "name": "User 1 List"})
    client.post("/api/auth/logout")
    login(client, username="clearpunch", password="pass23456")
    client.post("/api/lists", json={"id": "l_user2", "name": "User 2 List"})

    pull_response = client.post("/api/sync/pull", json={"collection": "lists", "limit": 20})

    assert pull_response.status_code == 200
    ids = [document["id"] for document in pull_response.json()["documents"]]
    assert "l_user2" in ids
    assert "l_user1" not in ids


def test_sync_pull_includes_shared_list_and_todos_for_collaborator(client):
    login(client)
    client.post("/api/lists", json={"id": "l_sync_shared", "name": "Party"})
    client.post("/api/todos", json={"id": "t_sync_shared", "list_id": "l_sync_shared", "title": "Drinks"})
    client.post("/api/lists/l_sync_shared/shares", json={"username": "clearpunch"})
    client.post("/api/auth/logout")

    login(client, username="clearpunch", password="pass23456")

    list_pull = client.post("/api/sync/pull", json={"collection": "lists", "limit": 20})
    todo_pull = client.post("/api/sync/pull", json={"collection": "todos", "limit": 20})

    assert list_pull.status_code == 200
    assert todo_pull.status_code == 200

    list_doc = next(document for document in list_pull.json()["documents"] if document["id"] == "l_sync_shared")
    todo_doc = next(document for document in todo_pull.json()["documents"] if document["id"] == "t_sync_shared")

    assert list_doc["access_role"] == "shared"
    assert list_doc["owner_username"] == "frenchfaso"
    assert list_doc["_deleted"] is False
    assert todo_doc["_deleted"] is False


def test_sync_pull_emits_tombstone_when_share_is_revoked(client):
    login(client)
    client.post("/api/lists", json={"id": "l_revoke", "name": "Trip"})
    client.post("/api/todos", json={"id": "t_revoke", "list_id": "l_revoke", "title": "Passport"})
    client.post("/api/lists/l_revoke/shares", json={"username": "clearpunch"})
    client.post("/api/auth/logout")

    login(client, username="clearpunch", password="pass23456")
    initial_list_pull = client.post("/api/sync/pull", json={"collection": "lists", "limit": 20})
    initial_todo_pull = client.post("/api/sync/pull", json={"collection": "todos", "limit": 20})
    list_checkpoint = next(document for document in initial_list_pull.json()["documents"] if document["id"] == "l_revoke")
    todo_checkpoint = next(document for document in initial_todo_pull.json()["documents"] if document["id"] == "t_revoke")
    client.post("/api/auth/logout")

    login(client)
    client.delete("/api/lists/l_revoke/shares/initial2")
    client.post("/api/auth/logout")

    login(client, username="clearpunch", password="pass23456")

    list_pull = client.post(
        "/api/sync/pull",
        json={
            "collection": "lists",
            "limit": 20,
            "checkpoint": {"id": list_checkpoint["id"], "updated_at": list_checkpoint["updated_at"]},
        },
    )
    todo_pull = client.post(
        "/api/sync/pull",
        json={
            "collection": "todos",
            "limit": 20,
            "checkpoint": {"id": todo_checkpoint["id"], "updated_at": todo_checkpoint["updated_at"]},
        },
    )

    revoked_list = next(document for document in list_pull.json()["documents"] if document["id"] == "l_revoke")
    revoked_todo = next(document for document in todo_pull.json()["documents"] if document["id"] == "t_revoke")

    assert revoked_list["_deleted"] is True
    assert revoked_todo["_deleted"] is True


def test_sync_push_allows_shared_user_to_manage_todos_but_not_lists(client):
    login(client)
    client.post("/api/lists", json={"id": "l_sync_acl", "name": "Kitchen"})
    client.post("/api/lists/l_sync_acl/shares", json={"username": "clearpunch"})
    client.post("/api/auth/logout")

    login(client, username="clearpunch", password="pass23456")

    todo_push = client.post(
        "/api/sync/push",
        json={
            "collection": "todos",
            "rows": [
                {
                    "assumedMasterState": None,
                    "newDocumentState": {
                        "id": "t_shared_sync",
                        "list_id": "l_sync_acl",
                        "title": "Plates",
                        "done": False,
                        "created_at": "2026-03-13T12:00:00.000000Z",
                        "updated_at": "2026-03-13T12:00:00.000000Z",
                        "_deleted": False,
                    },
                }
            ],
        },
    )

    assert todo_push.status_code == 200
    assert todo_push.json() == []

    list_push = client.post(
        "/api/sync/push",
        json={
            "collection": "lists",
            "rows": [
                {
                    "assumedMasterState": None,
                    "newDocumentState": {
                        "id": "l_sync_acl",
                        "owner_id": "initial1",
                        "name": "Hacked",
                        "archived": False,
                        "access_role": "shared",
                        "shared_with_count": 0,
                        "owner_username": "frenchfaso",
                        "created_at": "2026-03-13T12:00:00.000000Z",
                        "updated_at": "2026-03-13T12:00:00.000000Z",
                        "_deleted": False,
                    },
                }
            ],
        },
    )

    assert list_push.status_code == 409
    assert list_push.json()["detail"] == "List already exists"


def test_sync_push_rejects_unsupported_collection(client):
    login(client)

    push_response = client.post("/api/sync/push", json={"collection": "wat", "rows": []})
    pull_response = client.post("/api/sync/pull", json={"collection": "wat", "limit": 10})

    assert push_response.status_code == 422
    assert pull_response.status_code == 422


def test_healthz(client):
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_test_environment_is_active():
    assert APP_ENV == "test"
    assert LOGIN_BLOCK_DURATION.total_seconds() > 0
