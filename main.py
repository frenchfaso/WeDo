import asyncio
from datetime import UTC, datetime, timedelta
import hashlib
from ipaddress import ip_address
import json
import os
from pathlib import Path
import secrets
from threading import Condition, Lock
from typing import Any, Optional, cast
from urllib.parse import urlsplit

import bcrypt
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, ValidationError
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, and_, create_engine, event, func, inspect, or_, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

APP_ENV = os.getenv("ENV", "production").lower()
IS_TEST_ENV = APP_ENV == "test"
IS_DEVELOPMENT_ENV = APP_ENV == "development"
DIST_DIR = Path(__file__).resolve().parent / "dist"
MAX_SYNC_PUSH_ROWS = 100
SSE_KEEPALIVE_INTERVAL_SECONDS = 15


class UserInvalidationBroker:
    def __init__(self) -> None:
        self._lock = Lock()
        self._condition = Condition(self._lock)
        self._versions: dict[str, int] = {}

    def get_version(self, user_id: str) -> int:
        with self._lock:
            return self._versions.get(user_id, 0)

    def publish(self, user_ids: set[str]) -> None:
        if not user_ids:
            return

        with self._condition:
            for user_id in user_ids:
                self._versions[user_id] = self._versions.get(user_id, 0) + 1
            self._condition.notify_all()

    def wait_for_change(self, user_id: str, last_seen_version: int, timeout_seconds: float) -> int:
        with self._condition:
            self._condition.wait_for(
                lambda: self._versions.get(user_id, 0) > last_seen_version,
                timeout=timeout_seconds,
            )
            return self._versions.get(user_id, 0)


def normalize_origin(origin: str) -> Optional[str]:
    normalized = origin.strip()
    if not normalized:
        return None

    parsed = urlsplit(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return None
    if parsed.path not in {"", "/"}:
        return None
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def load_allowed_origins() -> tuple[str, ...]:
    default_origins = (
        "http://localhost:8080,http://127.0.0.1:8080,"
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:4173,http://127.0.0.1:4173"
        if IS_TEST_ENV or IS_DEVELOPMENT_ENV
        else ""
    )
    configured_origins = os.getenv("WEDO_CORS_ORIGINS", default_origins)
    normalized_origins: list[str] = []

    for raw_origin in configured_origins.split(","):
        raw_origin = raw_origin.strip()
        if not raw_origin:
            continue
        normalized_origin = normalize_origin(raw_origin)
        if normalized_origin is None:
            raise RuntimeError(f"Invalid WEDO_CORS_ORIGINS entry: {raw_origin}")
        normalized_origins.append(normalized_origin)

    return tuple(dict.fromkeys(normalized_origins))


def normalize_ip(value: str) -> Optional[str]:
    normalized = value.strip()
    if not normalized:
        return None

    try:
        return str(ip_address(normalized))
    except ValueError:
        return None


def is_running_in_container() -> bool:
    return Path("/.dockerenv").exists()


def decode_ipv4_gateway(hex_value: str) -> Optional[str]:
    if len(hex_value) != 8:
        return None

    try:
        return str(ip_address(bytes.fromhex(hex_value)[::-1]))
    except ValueError:
        return None


def detect_default_gateway_ip() -> Optional[str]:
    route_file = Path("/proc/net/route")
    if not route_file.exists():
        return None

    try:
        lines = route_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue

        destination = parts[1]
        gateway = parts[2]
        if destination != "00000000":
            continue

        normalized_gateway = decode_ipv4_gateway(gateway)
        if normalized_gateway is not None:
            return normalized_gateway

    return None


def load_trusted_proxy_ips() -> frozenset[str]:
    trusted_ips = {"127.0.0.1", "::1"}
    configured_ips = os.getenv("TRUSTED_PROXY_IPS", "")

    for raw_ip in configured_ips.split(","):
        raw_ip = raw_ip.strip()
        if not raw_ip:
            continue

        normalized_ip = normalize_ip(raw_ip)
        if normalized_ip is None:
            raise RuntimeError(f"Invalid TRUSTED_PROXY_IPS entry: {raw_ip}")
        trusted_ips.add(normalized_ip)

    if is_running_in_container():
        default_gateway_ip = detect_default_gateway_ip()
        if default_gateway_ip is not None:
            trusted_ips.add(default_gateway_ip)

    return frozenset(trusted_ips)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/wedo.db")
if IS_TEST_ENV:
    DATABASE_URL = os.getenv("TEST_DATABASE_URL", "sqlite:///./data/test_wedo_test.db")

CORS_ALLOW_ORIGINS = load_allowed_origins()
TRUSTED_PROXY_IPS = load_trusted_proxy_ips()
AGENT_API_SECRET = os.getenv("WEDO_AGENT_API_SECRET", "test-agent-secret" if IS_TEST_ENV else "")
ADMIN_AGENT_API_SECRET = os.getenv("WEDO_ADMIN_AGENT_API_SECRET", "test-admin-agent-secret" if IS_TEST_ENV else "")
SESSION_COOKIE_NAME = "session_id"
SESSION_ID_HASH_PREFIX = "sha256:"
SESSION_COOKIE_SECURE = APP_ENV == "production"
DEFAULT_SESSION_TTL = timedelta(hours=12)
REMEMBER_ME_SESSION_TTL = timedelta(days=30)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW = timedelta(minutes=5)
LOGIN_BLOCK_DURATION = timedelta(minutes=5)
INITIAL_USERNAMES = ("frenchfaso", "clearpunch")
MIN_PASSWORD_LENGTH = 8
LOGIN_ATTEMPTS: dict[str, dict[str, Any]] = {}
LOGIN_ATTEMPT_LOCK = Lock()
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "base-uri 'self'; "
        "connect-src 'self'; "
        "font-src 'self' data:; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "img-src 'self' data: blob:; "
        "manifest-src 'self'; "
        "object-src 'none'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "worker-src 'self' blob:"
    ),
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}

os.makedirs("./data", exist_ok=True)

IS_SQLITE_DATABASE = DATABASE_URL.startswith("sqlite")
sqlalchemy_connect_args = {"check_same_thread": False, "timeout": 30} if IS_SQLITE_DATABASE else {}
engine = create_engine(DATABASE_URL, connect_args=sqlalchemy_connect_args, pool_pre_ping=True)

if IS_SQLITE_DATABASE:
    @event.listens_for(engine, "connect")
    def configure_sqlite_connection(dbapi_connection, connection_record):
        del connection_record
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.execute("PRAGMA busy_timeout = 30000")
            cursor.execute("PRAGMA journal_mode = WAL")
            cursor.execute("PRAGMA synchronous = NORMAL")
        finally:
            cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    password_change_required = Column(Boolean, default=False, nullable=False)


class SessionModel(Base):
    __tablename__ = "sessions"

    session_id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"))
    created_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)


class ListModel(Base):
    __tablename__ = "lists"

    id = Column(String, primary_key=True, index=True)
    owner_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    archived = Column(Boolean, default=False, nullable=False)
    deleted = Column(Boolean, default=False, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False)


class ListShareModel(Base):
    __tablename__ = "list_shares"

    id = Column(String, primary_key=True, index=True)
    list_id = Column(String, ForeignKey("lists.id"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    deleted = Column(Boolean, default=False, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False)


class TodoModel(Base):
    __tablename__ = "todos"

    id = Column(String, primary_key=True, index=True)
    list_id = Column(String, ForeignKey("lists.id"), nullable=False, index=True)
    title = Column(String, nullable=False)
    done = Column(Boolean, default=False, nullable=False)
    deleted = Column(Boolean, default=False, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False)


Base.metadata.create_all(bind=engine)
INVALIDATION_BROKER = UserInvalidationBroker()


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def hash_session_id(session_id: str) -> str:
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    return f"{SESSION_ID_HASH_PREFIX}{digest}"


def normalize_stored_session_id(session_id: str) -> str:
    if session_id.startswith(SESSION_ID_HASH_PREFIX):
        return session_id
    return hash_session_id(session_id)


def ensure_schema_compatibility() -> None:
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    now = utcnow()
    now_sql = serialize_datetime(now)

    with engine.begin() as connection:
        if "users" in table_names:
            user_columns = {column["name"] for column in inspector.get_columns("users")}
            if "password_change_required" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN password_change_required BOOLEAN DEFAULT 0"))
            connection.execute(text("UPDATE users SET password_change_required = COALESCE(password_change_required, 0)"))
            connection.execute(
                text(
                    "UPDATE users "
                    "SET password_change_required = 1 "
                    "WHERE hashed_password IS NULL OR hashed_password = ''"
                )
            )

        if "sessions" in table_names:
            session_columns = {column["name"] for column in inspector.get_columns("sessions")}
            if "created_at" not in session_columns:
                connection.execute(text("ALTER TABLE sessions ADD COLUMN created_at DATETIME"))
            if "expires_at" not in session_columns:
                connection.execute(text("ALTER TABLE sessions ADD COLUMN expires_at DATETIME"))
            session_rows = connection.execute(text("SELECT session_id FROM sessions")).mappings().all()
            for session_row in session_rows:
                stored_session_id = str(session_row["session_id"])
                normalized_session_id = normalize_stored_session_id(stored_session_id)
                if normalized_session_id != stored_session_id:
                    connection.execute(
                        text("UPDATE sessions SET session_id = :new_session_id WHERE session_id = :old_session_id"),
                        {
                            "new_session_id": normalized_session_id,
                            "old_session_id": stored_session_id,
                        },
                    )
            connection.execute(text("UPDATE sessions SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)"))
            connection.execute(
                text(
                    "UPDATE sessions "
                    "SET expires_at = COALESCE(expires_at, DATETIME(CURRENT_TIMESTAMP, '+30 days'))"
                )
            )

        if "lists" in table_names:
            list_columns = {column["name"] for column in inspector.get_columns("lists")}
            if "deleted" not in list_columns:
                connection.execute(text("ALTER TABLE lists ADD COLUMN deleted BOOLEAN DEFAULT 0"))
            connection.execute(text("UPDATE lists SET deleted = COALESCE(deleted, 0)"))
            connection.execute(
                text("UPDATE lists SET created_at = COALESCE(created_at, :now), updated_at = COALESCE(updated_at, :now)"),
                {"now": now_sql},
            )

        if "list_shares" not in table_names:
            connection.execute(
                text(
                    "CREATE TABLE list_shares ("
                    "id VARCHAR NOT NULL PRIMARY KEY, "
                    "list_id VARCHAR NOT NULL, "
                    "user_id VARCHAR NOT NULL, "
                    "deleted BOOLEAN DEFAULT 0 NOT NULL, "
                    "updated_at DATETIME NOT NULL, "
                    "created_at DATETIME NOT NULL, "
                    "FOREIGN KEY(list_id) REFERENCES lists (id), "
                    "FOREIGN KEY(user_id) REFERENCES users (id)"
                    ")"
                )
            )
            connection.execute(text("CREATE INDEX ix_list_shares_id ON list_shares (id)"))
            connection.execute(text("CREATE INDEX ix_list_shares_list_id ON list_shares (list_id)"))
            connection.execute(text("CREATE INDEX ix_list_shares_user_id ON list_shares (user_id)"))
        else:
            share_columns = {column["name"] for column in inspector.get_columns("list_shares")}
            if "deleted" not in share_columns:
                connection.execute(text("ALTER TABLE list_shares ADD COLUMN deleted BOOLEAN DEFAULT 0"))
            connection.execute(text("UPDATE list_shares SET deleted = COALESCE(deleted, 0)"))
            connection.execute(
                text(
                    "UPDATE list_shares "
                    "SET created_at = COALESCE(created_at, :now), updated_at = COALESCE(updated_at, :now)"
                ),
                {"now": now_sql},
            )

        if "todos" in table_names:
            todo_columns = {column["name"] for column in inspector.get_columns("todos")}
            if "deleted" not in todo_columns:
                connection.execute(text("ALTER TABLE todos ADD COLUMN deleted BOOLEAN DEFAULT 0"))
            connection.execute(text("UPDATE todos SET deleted = COALESCE(deleted, 0)"))
            connection.execute(
                text("UPDATE todos SET created_at = COALESCE(created_at, :now), updated_at = COALESCE(updated_at, :now)"),
                {"now": now_sql},
            )


def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except ValueError:
        return False


DUMMY_PASSWORD_HASH = get_password_hash("wedo-dummy-password")


def serialize_datetime(value: datetime) -> str:
    return value.replace(tzinfo=UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_datetime(value: str, field_name: str = "timestamp") -> datetime:
    try:
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {field_name}") from exc
    if parsed.tzinfo is None:
        return parsed
    return parsed.astimezone(UTC).replace(tzinfo=None)


def parse_optional_datetime(value: Optional[str], default: datetime, field_name: str = "timestamp") -> datetime:
    if not value:
        return default
    return parse_datetime(value, field_name=field_name)


def clean_required_text(value: str, field_name: str, max_length: int = 200) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise HTTPException(status_code=422, detail=f"{field_name} cannot be blank")
    if len(cleaned) > max_length:
        raise HTTPException(status_code=422, detail=f"{field_name} is too long")
    return cleaned


def clean_optional_text(value: Optional[str], field_name: str, max_length: int = 200) -> Optional[str]:
    if value is None:
        return None
    return clean_required_text(value, field_name, max_length=max_length)


def get_session_ttl(remember_me: bool) -> timedelta:
    return REMEMBER_ME_SESSION_TTL if remember_me else DEFAULT_SESSION_TTL


def delete_expired_sessions(db: Session) -> None:
    deleted_sessions = (
        db.query(SessionModel)
        .filter(SessionModel.expires_at.is_not(None), SessionModel.expires_at <= utcnow())
        .delete(synchronize_session=False)
    )
    if deleted_sessions:
        db.commit()


def get_cookie_settings() -> dict[str, Any]:
    return {
        "httponly": True,
        "path": "/",
        "samesite": "lax",
        "secure": SESSION_COOKIE_SECURE,
    }


def is_request_secure(request: Request) -> bool:
    client_host = request.client.host if request.client else ""
    normalized_client_host = normalize_ip(client_host)
    if normalized_client_host in TRUSTED_PROXY_IPS:
        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        if forwarded_proto:
            return forwarded_proto.split(",")[-1].strip().lower() == "https"

    return request.url.scheme == "https"


def enforce_secure_transport(request: Request) -> None:
    if SESSION_COOKIE_SECURE and not is_request_secure(request):
        raise HTTPException(status_code=403, detail="HTTPS required")


def get_cookie_settings_for_request(request: Request) -> dict[str, Any]:
    enforce_secure_transport(request)
    return get_cookie_settings()


def create_session(db: Session, user_id: str, remember_me: bool) -> tuple[str, datetime]:
    session_id = secrets.token_hex(32)
    stored_session_id = hash_session_id(session_id)
    created_at = utcnow()
    expires_at = created_at + get_session_ttl(remember_me)
    db.add(
        SessionModel(
            session_id=stored_session_id,
            user_id=user_id,
            created_at=created_at,
            expires_at=expires_at,
        )
    )
    db.commit()
    return session_id, expires_at


def delete_user_sessions(db: Session, user_id: str) -> None:
    db.query(SessionModel).filter(SessionModel.user_id == user_id).delete(synchronize_session=False)


def is_seed_user_enabled() -> bool:
    return os.getenv("SEED_DEFAULT_USER", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def get_seed_credentials() -> tuple[Optional[str], Optional[str]]:
    username = os.getenv("SEED_DEFAULT_USERNAME", "user").strip()
    default_password = "pass" if APP_ENV in {"development", "test"} else ""
    password = os.getenv("SEED_DEFAULT_PASSWORD", default_password)
    if not username or not password:
        return None, None
    return username, password


def get_initial_password() -> Optional[str]:
    password = os.getenv("WEDO_INITIAL_PASSWORD", "")
    if not password:
        return None
    if not password.strip():
        raise RuntimeError("WEDO_INITIAL_PASSWORD cannot be blank")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise RuntimeError(f"WEDO_INITIAL_PASSWORD must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > 200:
        raise RuntimeError("WEDO_INITIAL_PASSWORD is too long")
    return password


def get_login_attempt_key(request: Request, username: str) -> str:
    client_host = request.client.host if request.client else "unknown"
    return f"{client_host}:{username.lower()}"


def check_login_rate_limit(request: Request, username: str) -> None:
    key = get_login_attempt_key(request, username)
    now = utcnow()
    with LOGIN_ATTEMPT_LOCK:
        entry = LOGIN_ATTEMPTS.get(key)
        if not entry:
            return
        if entry["window_started_at"] + LOGIN_ATTEMPT_WINDOW <= now:
            LOGIN_ATTEMPTS.pop(key, None)
            return
        blocked_until = entry.get("blocked_until")
        if blocked_until and blocked_until > now:
            raise HTTPException(status_code=429, detail="Too many login attempts")
        if blocked_until and blocked_until <= now:
            LOGIN_ATTEMPTS.pop(key, None)


def record_failed_login(request: Request, username: str) -> None:
    key = get_login_attempt_key(request, username)
    now = utcnow()
    with LOGIN_ATTEMPT_LOCK:
        entry = LOGIN_ATTEMPTS.get(key)
        if not entry or entry["window_started_at"] + LOGIN_ATTEMPT_WINDOW <= now:
            entry = {"count": 0, "window_started_at": now, "blocked_until": None}
            LOGIN_ATTEMPTS[key] = entry
        entry["count"] += 1
        if entry["count"] >= MAX_LOGIN_ATTEMPTS:
            entry["blocked_until"] = now + LOGIN_BLOCK_DURATION


def clear_failed_logins(request: Request, username: str) -> None:
    key = get_login_attempt_key(request, username)
    with LOGIN_ATTEMPT_LOCK:
        LOGIN_ATTEMPTS.pop(key, None)


def has_password_configured(user: User) -> bool:
    db_user = cast(Any, user)
    return bool(cast(Optional[str], db_user.hashed_password))


def is_password_change_required(user: User) -> bool:
    db_user = cast(Any, user)
    return bool(db_user.password_change_required) or not has_password_configured(user)


def validate_new_password(password: str) -> str:
    if not password.strip():
        raise HTTPException(status_code=422, detail="Password cannot be blank")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=422, detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > 200:
        raise HTTPException(status_code=422, detail="Password is too long")
    return password


def require_password_ready(user: User) -> User:
    if is_password_change_required(user):
        raise HTTPException(status_code=403, detail="Password setup required")
    return user


def generate_temporary_password() -> str:
    return secrets.token_urlsafe(18)


def create_user_with_temporary_password(db: Session, username: str) -> tuple[User, str]:
    cleaned_username = clean_required_text(username, "username", max_length=120)
    if db.query(User).filter(User.username == cleaned_username).first():
        raise HTTPException(status_code=409, detail="User already exists")

    temporary_password = generate_temporary_password()
    user = User(
        id=f"user_{secrets.token_hex(12)}",
        username=cleaned_username,
        hashed_password=get_password_hash(temporary_password),
        password_change_required=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user, temporary_password


def reset_user_temporary_password(db: Session, user: User) -> str:
    temporary_password = generate_temporary_password()
    db_user = cast(Any, user)
    db_user.hashed_password = get_password_hash(temporary_password)
    db_user.password_change_required = True
    delete_user_sessions(db, str(db_user.id))
    db.commit()
    return temporary_password


def clean_optional_generated_id(value: Optional[str], field_name: str, prefix: str, max_length: int = 120) -> str:
    if value is None:
        return f"{prefix}_{secrets.token_hex(12)}"
    return clean_required_text(value, field_name, max_length=max_length)


def enforce_allowed_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if not origin:
        return
    normalized_origin = normalize_origin(origin)
    if normalized_origin is None:
        raise HTTPException(status_code=403, detail="Origin not allowed")

    host = request.headers.get("host", "").strip().lower()
    same_origin = bool(host) and urlsplit(normalized_origin).netloc == host
    if same_origin or normalized_origin in CORS_ALLOW_ORIGINS:
        return
    raise HTTPException(status_code=403, detail="Origin not allowed")


def add_response_headers(response: Response, headers: dict[str, str]) -> None:
    for header_name, header_value in headers.items():
        response.headers.setdefault(header_name, header_value)


def build_static_headers(path: Path) -> dict[str, str]:
    headers = dict(SECURITY_HEADERS)
    if path.name in {"index.html", "manifest.webmanifest", "sw.js"}:
        headers["Cache-Control"] = "no-cache"
    else:
        headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return headers


def seed_db() -> None:
    db = SessionLocal()
    created = False
    initial_password = get_initial_password() if APP_ENV == "production" else None

    for index, username in enumerate(INITIAL_USERNAMES, start=1):
        user = db.query(User).filter(User.username == username).first()
        if user:
            continue
        if APP_ENV == "production":
            if initial_password is None:
                continue
            db.add(
                User(
                    id=f"initial{index}",
                    username=username,
                    hashed_password=get_password_hash(initial_password),
                    password_change_required=True,
                )
            )
        else:
            db.add(User(id=f"initial{index}", username=username, hashed_password="", password_change_required=True))
        created = True

    if is_seed_user_enabled():
        username, password = get_seed_credentials()
        if username and password:
            user = db.query(User).filter(User.username == username).first()
            if not user:
                db.add(
                    User(
                        id="seed1",
                        username=username,
                        hashed_password=get_password_hash(password),
                        password_change_required=False,
                    )
                )
                created = True

    if created:
        db.commit()
    db.close()


def serialize_list(list_model: ListModel) -> dict[str, Any]:
    db_list = cast(Any, list_model)
    return {
        "id": db_list.id,
        "owner_id": db_list.owner_id,
        "name": db_list.name,
        "archived": bool(db_list.archived),
        "created_at": serialize_datetime(cast(datetime, db_list.created_at)),
        "updated_at": serialize_datetime(cast(datetime, db_list.updated_at)),
        "_deleted": bool(db_list.deleted),
    }


def serialize_list_for_user(
    list_model: ListModel,
    access_role: str,
    shared_with_count: int,
    effective_updated_at: datetime,
    owner_username: str,
    deleted_override: Optional[bool] = None,
) -> dict[str, Any]:
    document = serialize_list(list_model)
    document["access_role"] = access_role
    document["shared_with_count"] = shared_with_count
    document["owner_username"] = owner_username
    document["updated_at"] = serialize_datetime(effective_updated_at)
    if deleted_override is not None:
        document["_deleted"] = deleted_override
    if access_role == "shared":
        document["archived"] = False
    return document


def serialize_todo(todo_model: TodoModel) -> dict[str, Any]:
    db_todo = cast(Any, todo_model)
    return {
        "id": db_todo.id,
        "list_id": db_todo.list_id,
        "title": db_todo.title,
        "done": bool(db_todo.done),
        "created_at": serialize_datetime(cast(datetime, db_todo.created_at)),
        "updated_at": serialize_datetime(cast(datetime, db_todo.updated_at)),
        "_deleted": bool(db_todo.deleted),
    }


def serialize_todo_for_user(
    todo_model: TodoModel,
    effective_updated_at: datetime,
    deleted_override: Optional[bool] = None,
) -> dict[str, Any]:
    document = serialize_todo(todo_model)
    document["updated_at"] = serialize_datetime(effective_updated_at)
    if deleted_override is not None:
        document["_deleted"] = deleted_override
    return document


def get_owned_list(db: Session, user_id: str, list_id: str, include_deleted: bool = True) -> Optional[ListModel]:
    query = db.query(ListModel).filter(ListModel.id == list_id, ListModel.owner_id == user_id)
    if not include_deleted:
        query = query.filter(ListModel.deleted.is_(False))
    return cast(Optional[ListModel], query.first())


def get_active_share(db: Session, list_id: str, user_id: str) -> Optional[ListShareModel]:
    return cast(
        Optional[ListShareModel],
        db.query(ListShareModel)
        .filter(ListShareModel.list_id == list_id, ListShareModel.user_id == user_id, ListShareModel.deleted.is_(False))
        .first(),
    )


def get_any_share(db: Session, list_id: str, user_id: str) -> Optional[ListShareModel]:
    return cast(
        Optional[ListShareModel],
        db.query(ListShareModel)
        .filter(ListShareModel.list_id == list_id, ListShareModel.user_id == user_id)
        .first(),
    )


def is_list_owner(list_model: ListModel, user_id: str) -> bool:
    return cast(str, cast(Any, list_model).owner_id) == user_id


def get_accessible_list(db: Session, user_id: str, list_id: str, include_deleted: bool = True) -> Optional[ListModel]:
    query = (
        db.query(ListModel)
        .outerjoin(
            ListShareModel,
            and_(
                ListShareModel.list_id == ListModel.id,
                ListShareModel.user_id == user_id,
                ListShareModel.deleted.is_(False),
            ),
        )
        .filter(ListModel.id == list_id)
        .filter(or_(ListModel.owner_id == user_id, ListShareModel.id.is_not(None)))
    )
    if not include_deleted:
        query = query.filter(ListModel.deleted.is_(False))
    return cast(Optional[ListModel], query.first())


def get_accessible_todo(db: Session, user_id: str, todo_id: str) -> Optional[TodoModel]:
    return cast(
        Optional[TodoModel],
        db.query(TodoModel)
        .join(ListModel, TodoModel.list_id == ListModel.id)
        .outerjoin(
            ListShareModel,
            and_(
                ListShareModel.list_id == ListModel.id,
                ListShareModel.user_id == user_id,
                ListShareModel.deleted.is_(False),
            ),
        )
        .filter(TodoModel.id == todo_id)
        .filter(or_(ListModel.owner_id == user_id, ListShareModel.id.is_not(None)))
        .first(),
    )


def get_list_effective_state(db: Session, user_id: str, list_model: ListModel) -> Optional[dict[str, Any]]:
    db_list = cast(Any, list_model)
    list_updated_at = cast(datetime, db_list.updated_at)

    if db_list.owner_id == user_id:
        shared_with_count = int(
            db.query(func.count(ListShareModel.id))
            .filter(ListShareModel.list_id == db_list.id, ListShareModel.deleted.is_(False))
            .scalar()
            or 0
        )
        latest_share_updated_at = cast(
            Optional[datetime],
            db.query(func.max(ListShareModel.updated_at)).filter(ListShareModel.list_id == db_list.id).scalar(),
        )
        effective_updated_at = max(list_updated_at, latest_share_updated_at) if latest_share_updated_at else list_updated_at
        return {
            "access_role": "owner",
            "shared_with_count": shared_with_count,
            "effective_updated_at": effective_updated_at,
            "deleted": bool(db_list.deleted),
        }

    share = get_any_share(db, db_list.id, user_id)
    if share is None:
        return None
    db_share = cast(Any, share)
    share_updated_at = cast(datetime, db_share.updated_at)
    effective_updated_at = max(list_updated_at, share_updated_at)
    return {
        "access_role": "shared",
        "shared_with_count": 0,
        "effective_updated_at": effective_updated_at,
        "deleted": bool(db_list.deleted) or bool(db_share.deleted),
    }


def get_todo_effective_state(db: Session, user_id: str, todo_model: TodoModel) -> Optional[dict[str, Any]]:
    db_todo = cast(Any, todo_model)
    list_model = cast(Optional[ListModel], db.query(ListModel).filter(ListModel.id == db_todo.list_id).first())
    if list_model is None:
        return None

    db_list = cast(Any, list_model)
    todo_updated_at = cast(datetime, db_todo.updated_at)
    effective_updated_at = max(todo_updated_at, cast(datetime, db_list.updated_at))

    if db_list.owner_id == user_id:
        return {
            "effective_updated_at": effective_updated_at,
            "deleted": bool(db_todo.deleted),
        }

    share = get_any_share(db, db_list.id, user_id)
    if share is None:
        return None
    db_share = cast(Any, share)
    effective_updated_at = max(effective_updated_at, cast(datetime, db_share.updated_at))
    return {
        "effective_updated_at": effective_updated_at,
        "deleted": bool(db_todo.deleted) or bool(db_share.deleted),
    }


def list_all_accessible_list_documents(db: Session, user_id: str) -> list[dict[str, Any]]:
    accessible_lists = (
        db.query(ListModel)
        .outerjoin(
            ListShareModel,
            and_(ListShareModel.list_id == ListModel.id, ListShareModel.user_id == user_id),
        )
        .filter(or_(ListModel.owner_id == user_id, ListShareModel.id.is_not(None)))
        .all()
    )

    documents: list[dict[str, Any]] = []
    for item in accessible_lists:
        effective_state = get_list_effective_state(db, user_id, item)
        if effective_state is None:
            continue
        documents.append(
            serialize_list_for_user(
                item,
                str(effective_state["access_role"]),
                int(effective_state["shared_with_count"]),
                cast(datetime, effective_state["effective_updated_at"]),
                get_username_by_user_id(db, cast(str, cast(Any, item).owner_id)),
                deleted_override=bool(effective_state["deleted"]),
            )
        )
    return documents


def list_all_accessible_todo_documents(db: Session, user_id: str) -> list[dict[str, Any]]:
    accessible_todos = (
        db.query(TodoModel)
        .join(ListModel, TodoModel.list_id == ListModel.id)
        .outerjoin(
            ListShareModel,
            and_(ListShareModel.list_id == ListModel.id, ListShareModel.user_id == user_id),
        )
        .filter(or_(ListModel.owner_id == user_id, ListShareModel.id.is_not(None)))
        .all()
    )

    documents: list[dict[str, Any]] = []
    for item in accessible_todos:
        effective_state = get_todo_effective_state(db, user_id, item)
        if effective_state is None:
            continue
        documents.append(
            serialize_todo_for_user(
                item,
                cast(datetime, effective_state["effective_updated_at"]),
                deleted_override=bool(effective_state["deleted"]),
            )
        )
    return documents


def filter_documents_after_checkpoint(
    documents: list[dict[str, Any]], checkpoint: Optional["SyncCheckpoint"]
) -> list[dict[str, Any]]:
    ordered_documents = sorted(documents, key=lambda document: (str(document["updated_at"]), str(document["id"])))
    if checkpoint is None:
        return ordered_documents

    checkpoint_key = (checkpoint.updated_at, checkpoint.id)
    return [
        document
        for document in ordered_documents
        if (str(document["updated_at"]), str(document["id"])) > checkpoint_key
    ]


def list_share_members(db: Session, list_id: str) -> list[dict[str, str]]:
    share_rows = (
        db.query(ListShareModel, User.username)
        .join(User, User.id == ListShareModel.user_id)
        .filter(ListShareModel.list_id == list_id, ListShareModel.deleted.is_(False))
        .order_by(User.username)
        .all()
    )
    members: list[dict[str, str]] = []
    for share_model, username in share_rows:
        db_share = cast(Any, share_model)
        members.append(
            {
                "user_id": db_share.user_id,
                "username": str(username),
                "created_at": serialize_datetime(cast(datetime, db_share.created_at)),
            }
        )
    return members


def get_username_by_user_id(db: Session, user_id: str) -> str:
    username = cast(Optional[str], db.query(User.username).filter(User.id == user_id).scalar())
    return username or ""


def get_active_shared_user_ids(db: Session, list_id: str) -> set[str]:
    rows = (
        db.query(ListShareModel.user_id)
        .filter(ListShareModel.list_id == list_id, ListShareModel.deleted.is_(False))
        .all()
    )
    return {str(user_id) for user_id, in rows}


def get_list_audience_user_ids(db: Session, list_model: ListModel) -> set[str]:
    db_list = cast(Any, list_model)
    return {str(db_list.owner_id), *get_active_shared_user_ids(db, str(db_list.id))}


def get_list_audience_user_ids_by_id(db: Session, list_id: str) -> set[str]:
    list_model = cast(Optional[ListModel], db.query(ListModel).filter(ListModel.id == list_id).first())
    if list_model is None:
        return set()
    return get_list_audience_user_ids(db, list_model)


def validate_sync_collection(collection: str) -> str:
    if collection not in {"lists", "todos"}:
        raise HTTPException(status_code=422, detail="Unsupported collection")
    return collection


def is_conflict(real_updated_at: datetime, assumed_master_state: Optional[dict[str, Any]]) -> bool:
    if assumed_master_state is None:
        return True
    assumed_updated_at = assumed_master_state.get("updated_at")
    if not assumed_updated_at:
        return True
    return parse_datetime(str(assumed_updated_at), field_name="assumed master updated_at") != real_updated_at


def apply_checkpoint_filter(query: Any, model: Any, checkpoint: Optional["SyncCheckpoint"]) -> Any:
    if checkpoint is None:
        return query
    checkpoint_updated_at = parse_datetime(checkpoint.updated_at, field_name="checkpoint updated_at")
    return query.filter(
        or_(
            model.updated_at > checkpoint_updated_at,
            and_(model.updated_at == checkpoint_updated_at, model.id > checkpoint.id),
        )
    )


class LoginData(BaseModel):
    username: str
    password: str
    remember_me: bool = False


class PasswordSetupData(BaseModel):
    password: str


class ListCreate(BaseModel):
    id: str
    name: str


class ListShareCreate(BaseModel):
    username: str


class ListUpdate(BaseModel):
    name: Optional[str] = None
    archived: Optional[bool] = None


class TodoCreate(BaseModel):
    id: str
    list_id: str
    title: str


class TodoUpdate(BaseModel):
    title: Optional[str] = None
    done: Optional[bool] = None


class AgentListCreate(BaseModel):
    id: Optional[str] = None
    name: str


class AgentListShareCreate(BaseModel):
    username: str


class AgentListItemCreate(BaseModel):
    id: Optional[str] = None
    title: str


class AgentListItemUpdate(BaseModel):
    title: Optional[str] = None
    done: Optional[bool] = None


class AgentUserCreate(BaseModel):
    username: str


class ListSyncDocument(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: StrictStr
    name: StrictStr
    archived: StrictBool = False
    created_at: Optional[StrictStr] = None
    deleted: StrictBool = Field(default=False, alias="_deleted")


class TodoSyncDocument(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: StrictStr
    list_id: Optional[StrictStr] = None
    title: StrictStr
    done: StrictBool = False
    created_at: Optional[StrictStr] = None
    deleted: StrictBool = Field(default=False, alias="_deleted")


class SyncCheckpoint(BaseModel):
    updated_at: str
    id: str


class SyncPullRequest(BaseModel):
    collection: str
    checkpoint: Optional[SyncCheckpoint] = None
    limit: int = Field(default=50, ge=1, le=100)


class SyncPushRow(BaseModel):
    assumedMasterState: Optional[dict[str, Any]] = None
    newDocumentState: dict[str, Any]


class SyncPushRequest(BaseModel):
    collection: str
    rows: list[SyncPushRow] = Field(default_factory=list, max_length=MAX_SYNC_PUSH_ROWS)


def parse_sync_list_document(document: dict[str, Any]) -> ListSyncDocument:
    try:
        return ListSyncDocument.model_validate(document)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="Invalid list document") from exc


def parse_sync_todo_document(document: dict[str, Any]) -> TodoSyncDocument:
    try:
        return TodoSyncDocument.model_validate(document)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="Invalid todo document") from exc


ensure_schema_compatibility()
seed_db()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(CORS_ALLOW_ORIGINS),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def harden_responses(request: Request, call_next):
    response = await call_next(request)
    add_response_headers(response, SECURITY_HEADERS)
    if request.url.path.startswith("/api/") or request.url.path == "/healthz":
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Pragma", "no-cache")
    if APP_ENV == "production":
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return response


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request, db: Session = Depends(get_db)):
    enforce_secure_transport(request)
    delete_expired_sessions(db)
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    session = db.query(SessionModel).filter(SessionModel.session_id == hash_session_id(session_id)).first()
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db_session = cast(Any, session)
    session_expires_at = cast(datetime, db_session.expires_at)
    if session_expires_at <= utcnow():
        db.delete(db_session)
        db.commit()
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = db.query(User).filter(User.id == db_session.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def get_current_app_user(user: User = Depends(get_current_user)):
    return require_password_ready(user)


def get_current_app_user_id(request: Request) -> str:
    db = SessionLocal()
    try:
        user = get_current_user(request, db)
        app_user = require_password_ready(user)
        return str(cast(Any, app_user).id)
    finally:
        db.close()


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    cleaned_username = clean_required_text(username, "username", max_length=120)
    return cast(Optional[User], db.query(User).filter(User.username == cleaned_username).first())


def get_agent_user(
    x_agent_secret: Optional[str] = Header(default=None, alias="X-Agent-Secret"),
    x_acting_username: Optional[str] = Header(default=None, alias="X-Acting-Username"),
    db: Session = Depends(get_db),
):
    if not AGENT_API_SECRET:
        raise HTTPException(status_code=503, detail="Agent API not configured")
    if x_agent_secret is None or not secrets.compare_digest(x_agent_secret, AGENT_API_SECRET):
        raise HTTPException(status_code=401, detail="Invalid agent secret")
    if x_acting_username is None:
        raise HTTPException(status_code=422, detail="Acting username is required")
    user = get_user_by_username(db, x_acting_username)
    if user is None:
        raise HTTPException(status_code=404, detail="Acting user not found")
    return user


def get_admin_agent(
    x_agent_admin_secret: Optional[str] = Header(default=None, alias="X-Agent-Admin-Secret"),
):
    if not ADMIN_AGENT_API_SECRET:
        raise HTTPException(status_code=503, detail="Admin agent API not configured")
    if x_agent_admin_secret is None or not secrets.compare_digest(x_agent_admin_secret, ADMIN_AGENT_API_SECRET):
        raise HTTPException(status_code=401, detail="Invalid admin agent secret")
    return True


def create_list_record(db: Session, owner_id: str, name: str, list_id: Optional[str] = None) -> ListModel:
    resolved_list_id = clean_optional_generated_id(list_id, "list id", prefix="list")
    cleaned_name = clean_required_text(name, "list name")
    if db.query(ListModel).filter(ListModel.id == resolved_list_id).first():
        raise HTTPException(status_code=409, detail="List already exists")
    now = utcnow()
    new_list = ListModel(
        id=resolved_list_id,
        owner_id=owner_id,
        name=cleaned_name,
        archived=False,
        deleted=False,
        created_at=now,
        updated_at=now,
    )
    db.add(new_list)
    db.commit()
    db.refresh(new_list)
    INVALIDATION_BROKER.publish({owner_id})
    return new_list


def create_list_share_record(db: Session, owner_id: str, list_id: str, username: str) -> tuple[User, datetime]:
    cleaned_list_id = clean_required_text(list_id, "list id", max_length=120)
    lst = get_owned_list(db, owner_id, cleaned_list_id, include_deleted=False)
    if not lst:
        raise HTTPException(status_code=404)

    target_user = get_user_by_username(db, username)
    if target_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    db_target_user = cast(Any, target_user)
    if db_target_user.id == owner_id:
        raise HTTPException(status_code=422, detail="Owner already has access")

    existing_share = get_any_share(db, cleaned_list_id, db_target_user.id)
    if existing_share is not None and not cast(bool, cast(Any, existing_share).deleted):
        raise HTTPException(status_code=409, detail="User already has access")

    now = utcnow()
    if existing_share is not None:
        db_share = cast(Any, existing_share)
        db_share.deleted = False
        db_share.updated_at = now
        created_at = cast(datetime, db_share.created_at)
    else:
        created_at = now
        db.add(
            ListShareModel(
                id=f"share_{cleaned_list_id}_{db_target_user.id}",
                list_id=cleaned_list_id,
                user_id=db_target_user.id,
                deleted=False,
                created_at=created_at,
                updated_at=now,
            )
        )

    cast(Any, lst).updated_at = now
    db.commit()
    INVALIDATION_BROKER.publish({owner_id, str(db_target_user.id)})
    return target_user, created_at


def create_todo_record(db: Session, user_id: str, list_id: str, title: str, todo_id: Optional[str] = None) -> TodoModel:
    cleaned_list_id = clean_required_text(list_id, "list id", max_length=120)
    lst = get_accessible_list(db, user_id, cleaned_list_id, include_deleted=False)
    if not lst:
        raise HTTPException(status_code=404)
    resolved_todo_id = clean_optional_generated_id(todo_id, "todo id", prefix="todo")
    cleaned_title = clean_required_text(title, "todo title")
    if db.query(TodoModel).filter(TodoModel.id == resolved_todo_id).first():
        raise HTTPException(status_code=409, detail="Todo already exists")
    now = utcnow()
    todo = TodoModel(
        id=resolved_todo_id,
        list_id=cleaned_list_id,
        title=cleaned_title,
        done=False,
        deleted=False,
        created_at=now,
        updated_at=now,
    )
    db.add(todo)
    db.commit()
    db.refresh(todo)
    INVALIDATION_BROKER.publish(get_list_audience_user_ids_by_id(db, cleaned_list_id))
    return todo


def delete_todo_record(db: Session, user_id: str, todo_id: str, expected_list_id: Optional[str] = None) -> None:
    cleaned_todo_id = clean_required_text(todo_id, "todo id", max_length=120)
    todo = get_accessible_todo(db, user_id, cleaned_todo_id)
    if not todo:
        raise HTTPException(status_code=404)
    db_todo = cast(Any, todo)
    if expected_list_id is not None and db_todo.list_id != clean_required_text(expected_list_id, "list id", max_length=120):
        raise HTTPException(status_code=404)
    if db_todo.deleted:
        raise HTTPException(status_code=404)
    db_todo.deleted = True
    db_todo.updated_at = utcnow()
    audience_user_ids = get_list_audience_user_ids_by_id(db, str(db_todo.list_id))
    db.commit()
    INVALIDATION_BROKER.publish(audience_user_ids)


def update_todo_record(
    db: Session,
    user_id: str,
    todo_id: str,
    title: Optional[str] = None,
    done: Optional[bool] = None,
    expected_list_id: Optional[str] = None,
) -> TodoModel:
    cleaned_todo_id = clean_required_text(todo_id, "todo id", max_length=120)
    todo = get_accessible_todo(db, user_id, cleaned_todo_id)
    if not todo:
        raise HTTPException(status_code=404)
    db_todo = cast(Any, todo)
    if expected_list_id is not None and db_todo.list_id != clean_required_text(expected_list_id, "list id", max_length=120):
        raise HTTPException(status_code=404)
    if db_todo.deleted:
        raise HTTPException(status_code=404)

    cleaned_title = clean_optional_text(title, "todo title")
    if cleaned_title is not None:
        db_todo.title = cleaned_title
    if done is not None:
        db_todo.done = done

    db_todo.updated_at = utcnow()
    audience_user_ids = get_list_audience_user_ids_by_id(db, str(db_todo.list_id))
    db.commit()
    INVALIDATION_BROKER.publish(audience_user_ids)
    return cast(TodoModel, db_todo)


@app.post("/api/auth/login")
def login(data: LoginData, request: Request, response: Response, db: Session = Depends(get_db)):
    enforce_allowed_origin(request)
    enforce_secure_transport(request)
    delete_expired_sessions(db)
    username = data.username.strip()
    check_login_rate_limit(request, username)
    user = db.query(User).filter(User.username == username).first()
    if not user:
        verify_password(data.password, DUMMY_PASSWORD_HASH)
        record_failed_login(request, username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    db_user = cast(Any, user)
    hashed_password = cast(str, db_user.hashed_password)
    if hashed_password:
        if not verify_password(data.password, hashed_password):
            record_failed_login(request, username)
            raise HTTPException(status_code=401, detail="Invalid credentials")
    elif APP_ENV == "production" or data.password.strip():
        record_failed_login(request, username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    clear_failed_logins(request, username)
    session_id, expires_at = create_session(db, db_user.id, data.remember_me)
    max_age = int((expires_at - utcnow()).total_seconds()) if data.remember_me else None
    response.set_cookie(key=SESSION_COOKIE_NAME, value=session_id, max_age=max_age, **get_cookie_settings_for_request(request))
    return {"message": "Logged in", "password_setup_required": is_password_change_required(user)}


@app.get("/api/auth/me")
def get_me(user: User = Depends(get_current_user)):
    db_user = cast(Any, user)
    return {
        "id": db_user.id,
        "username": db_user.username,
        "password_setup_required": is_password_change_required(user),
    }


@app.post("/api/auth/set-password")
def set_password(
    data: PasswordSetupData,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce_allowed_origin(request)
    db_user = cast(Any, user)
    if not is_password_change_required(user):
        raise HTTPException(status_code=409, detail="Password already configured")
    db_user.hashed_password = get_password_hash(validate_new_password(data.password))
    db_user.password_change_required = False
    db.commit()
    return {
        "id": db_user.id,
        "username": db_user.username,
        "password_setup_required": False,
    }


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    enforce_allowed_origin(request)
    enforce_secure_transport(request)
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        db.query(SessionModel).filter(SessionModel.session_id == hash_session_id(session_id)).delete()
        db.commit()
    response.delete_cookie(key=SESSION_COOKIE_NAME, **get_cookie_settings_for_request(request))
    return {"message": "Logged out"}


@app.get("/api/lists")
def get_lists(user: User = Depends(get_current_app_user), db: Session = Depends(get_db)):
    db_user = cast(Any, user)
    accessible_lists = (
        db.query(ListModel)
        .outerjoin(
            ListShareModel,
            and_(
                ListShareModel.list_id == ListModel.id,
                ListShareModel.user_id == db_user.id,
                ListShareModel.deleted.is_(False),
            ),
        )
        .filter(ListModel.deleted.is_(False))
        .filter(or_(ListModel.owner_id == db_user.id, ListShareModel.id.is_not(None)))
        .order_by(ListModel.created_at, ListModel.id)
        .all()
    )
    response: list[dict[str, Any]] = []
    for item in accessible_lists:
        effective_state = get_list_effective_state(db, db_user.id, item)
        if effective_state is None or bool(effective_state["deleted"]):
            continue
        db_item = cast(Any, item)
        response.append(
            {
                "id": db_item.id,
                "name": db_item.name,
                "archived": bool(db_item.archived) if effective_state["access_role"] == "owner" else False,
                "access_role": str(effective_state["access_role"]),
                "shared_with_count": int(effective_state["shared_with_count"]),
                "owner_username": get_username_by_user_id(db, str(db_item.owner_id)),
            }
        )
    return response


@app.post("/api/lists")
def create_list(data: ListCreate, request: Request, user: User = Depends(get_current_app_user), db: Session = Depends(get_db)):
    enforce_allowed_origin(request)
    db_user = cast(Any, user)
    new_list = create_list_record(db, db_user.id, data.name, data.id)
    return {"id": new_list.id, "name": new_list.name, "archived": new_list.archived}


@app.put("/api/lists/{list_id}")
def update_list(list_id: str, data: ListUpdate, request: Request, user: User = Depends(get_current_app_user), db: Session = Depends(get_db)):
    enforce_allowed_origin(request)
    db_user = cast(Any, user)
    lst = get_owned_list(db, db_user.id, list_id, include_deleted=False)
    if not lst:
        raise HTTPException(status_code=404)
    db_list = cast(Any, lst)
    name = clean_optional_text(data.name, "list name")
    if name is not None:
        db_list.name = name
    if data.archived is not None:
        db_list.archived = data.archived
    db_list.updated_at = utcnow()
    db.commit()
    INVALIDATION_BROKER.publish(get_list_audience_user_ids(db, lst))
    return {"id": db_list.id, "name": db_list.name, "archived": db_list.archived}


@app.get("/api/lists/{list_id}/shares")
def get_list_shares(list_id: str, user: User = Depends(get_current_app_user), db: Session = Depends(get_db)):
    db_user = cast(Any, user)
    lst = get_owned_list(db, db_user.id, list_id, include_deleted=False)
    if not lst:
        raise HTTPException(status_code=404)
    return {"members": list_share_members(db, list_id)}


@app.post("/api/lists/{list_id}/shares")
def create_list_share(
    list_id: str,
    data: ListShareCreate,
    request: Request,
    user: User = Depends(get_current_app_user),
    db: Session = Depends(get_db),
):
    enforce_allowed_origin(request)
    db_user = cast(Any, user)
    target_user, created_at = create_list_share_record(db, db_user.id, list_id, data.username)
    db_target_user = cast(Any, target_user)
    return {
        "user_id": db_target_user.id,
        "username": db_target_user.username,
        "created_at": serialize_datetime(created_at),
    }


@app.delete("/api/lists/{list_id}/shares/{user_id}")
def delete_list_share(
    list_id: str,
    user_id: str,
    request: Request,
    user: User = Depends(get_current_app_user),
    db: Session = Depends(get_db),
):
    enforce_allowed_origin(request)
    db_user = cast(Any, user)
    lst = get_owned_list(db, db_user.id, list_id, include_deleted=False)
    if not lst:
        raise HTTPException(status_code=404)

    share = get_active_share(db, list_id, user_id)
    if share is None:
        raise HTTPException(status_code=404)

    now = utcnow()
    db_share = cast(Any, share)
    db_share.deleted = True
    db_share.updated_at = now
    cast(Any, lst).updated_at = now
    db.commit()
    INVALIDATION_BROKER.publish({db_user.id, user_id})
    return {"message": "Access revoked"}


@app.delete("/api/lists/{list_id}")
def delete_list(list_id: str, request: Request, user: User = Depends(get_current_app_user), db: Session = Depends(get_db)):
    enforce_allowed_origin(request)
    db_user = cast(Any, user)
    lst = get_owned_list(db, db_user.id, list_id, include_deleted=False)
    if not lst:
        raise HTTPException(status_code=404)
    now = utcnow()
    db_list = cast(Any, lst)
    audience_user_ids = get_list_audience_user_ids(db, lst)
    db_list.deleted = True
    db_list.updated_at = now
    todos = db.query(TodoModel).filter(TodoModel.list_id == list_id, TodoModel.deleted.is_(False)).all()
    for todo in todos:
        db_todo = cast(Any, todo)
        db_todo.deleted = True
        db_todo.updated_at = now
    db.commit()
    INVALIDATION_BROKER.publish(audience_user_ids)
    return {"message": "Deleted"}


@app.get("/api/todos")
def get_todos(user: User = Depends(get_current_app_user), db: Session = Depends(get_db)):
    db_user = cast(Any, user)
    todos = (
        db.query(TodoModel)
        .join(ListModel, TodoModel.list_id == ListModel.id)
        .outerjoin(
            ListShareModel,
            and_(
                ListShareModel.list_id == ListModel.id,
                ListShareModel.user_id == db_user.id,
                ListShareModel.deleted.is_(False),
            ),
        )
        .filter(TodoModel.deleted.is_(False), ListModel.deleted.is_(False))
        .filter(or_(ListModel.owner_id == db_user.id, ListShareModel.id.is_not(None)))
        .order_by(TodoModel.created_at, TodoModel.id)
        .all()
    )
    return [{"id": item.id, "list_id": item.list_id, "title": item.title, "done": item.done} for item in todos]


@app.post("/api/todos")
def create_todo(data: TodoCreate, request: Request, user: User = Depends(get_current_app_user), db: Session = Depends(get_db)):
    enforce_allowed_origin(request)
    db_user = cast(Any, user)
    todo = create_todo_record(db, db_user.id, data.list_id, data.title, data.id)
    return {"id": todo.id, "list_id": todo.list_id, "title": todo.title, "done": todo.done}


@app.put("/api/todos/{todo_id}")
def update_todo(todo_id: str, data: TodoUpdate, request: Request, user: User = Depends(get_current_app_user), db: Session = Depends(get_db)):
    enforce_allowed_origin(request)
    db_user = cast(Any, user)
    todo = update_todo_record(db, db_user.id, todo_id, title=data.title, done=data.done)
    return {"id": todo.id, "list_id": todo.list_id, "title": todo.title, "done": todo.done}


@app.delete("/api/todos/{todo_id}")
def delete_todo(todo_id: str, request: Request, user: User = Depends(get_current_app_user), db: Session = Depends(get_db)):
    enforce_allowed_origin(request)
    db_user = cast(Any, user)
    delete_todo_record(db, db_user.id, todo_id)
    return {"message": "Deleted"}


@app.post("/api/agent/admin/users")
def agent_admin_create_user(
    data: AgentUserCreate,
    admin_agent: bool = Depends(get_admin_agent),
    db: Session = Depends(get_db),
):
    del admin_agent
    user, temporary_password = create_user_with_temporary_password(db, data.username)
    db_user = cast(Any, user)
    return {
        "id": db_user.id,
        "username": db_user.username,
        "temporary_password": temporary_password,
        "password_setup_required": True,
    }


@app.post("/api/agent/admin/users/{username}/reset-password")
def agent_admin_reset_user_password(
    username: str,
    admin_agent: bool = Depends(get_admin_agent),
    db: Session = Depends(get_db),
):
    del admin_agent
    user = get_user_by_username(db, username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    temporary_password = reset_user_temporary_password(db, user)
    db_user = cast(Any, user)
    return {
        "id": db_user.id,
        "username": db_user.username,
        "temporary_password": temporary_password,
        "password_setup_required": True,
    }


@app.post("/api/agent/lists")
def agent_create_list(data: AgentListCreate, user: User = Depends(get_agent_user), db: Session = Depends(get_db)):
    db_user = cast(Any, user)
    new_list = create_list_record(db, db_user.id, data.name, data.id)
    return {"id": new_list.id, "name": new_list.name, "archived": new_list.archived}


@app.post("/api/agent/lists/{list_id}/shares")
def agent_create_list_share(
    list_id: str,
    data: AgentListShareCreate,
    user: User = Depends(get_agent_user),
    db: Session = Depends(get_db),
):
    db_user = cast(Any, user)
    target_user, created_at = create_list_share_record(db, db_user.id, list_id, data.username)
    db_target_user = cast(Any, target_user)
    return {
        "user_id": db_target_user.id,
        "username": db_target_user.username,
        "created_at": serialize_datetime(created_at),
    }


@app.post("/api/agent/lists/{list_id}/items")
def agent_create_list_item(
    list_id: str,
    data: AgentListItemCreate,
    user: User = Depends(get_agent_user),
    db: Session = Depends(get_db),
):
    db_user = cast(Any, user)
    todo = create_todo_record(db, db_user.id, list_id, data.title, data.id)
    return {"id": todo.id, "list_id": todo.list_id, "title": todo.title, "done": todo.done}


@app.delete("/api/agent/lists/{list_id}/items/{item_id}")
def agent_delete_list_item(
    list_id: str,
    item_id: str,
    user: User = Depends(get_agent_user),
    db: Session = Depends(get_db),
):
    db_user = cast(Any, user)
    delete_todo_record(db, db_user.id, item_id, expected_list_id=list_id)
    return {"message": "Deleted"}


@app.put("/api/agent/lists/{list_id}/items/{item_id}")
def agent_update_list_item(
    list_id: str,
    item_id: str,
    data: AgentListItemUpdate,
    user: User = Depends(get_agent_user),
    db: Session = Depends(get_db),
):
    db_user = cast(Any, user)
    todo = update_todo_record(db, db_user.id, item_id, title=data.title, done=data.done, expected_list_id=list_id)
    return {"id": todo.id, "list_id": todo.list_id, "title": todo.title, "done": todo.done}


@app.post("/api/sync/pull")
def sync_pull(payload: SyncPullRequest, user: User = Depends(get_current_app_user), db: Session = Depends(get_db)):
    db_user = cast(Any, user)
    collection = validate_sync_collection(payload.collection)
    if payload.checkpoint is not None:
        parse_datetime(payload.checkpoint.updated_at, field_name="checkpoint updated_at")
    serialized_documents: list[dict[str, Any]] = []
    if collection == "lists":
        serialized_documents = list_all_accessible_list_documents(db, db_user.id)
        serialized_documents = filter_documents_after_checkpoint(serialized_documents, payload.checkpoint)[: payload.limit]
    elif collection == "todos":
        serialized_documents = list_all_accessible_todo_documents(db, db_user.id)
        serialized_documents = filter_documents_after_checkpoint(serialized_documents, payload.checkpoint)[: payload.limit]
    if serialized_documents:
        last_document = serialized_documents[-1]
        checkpoint: Optional[dict[str, str]] = {
            "updated_at": str(last_document["updated_at"]),
            "id": str(last_document["id"]),
        }
    elif payload.checkpoint is not None:
        checkpoint = payload.checkpoint.model_dump()
    else:
        checkpoint = None

    return {"documents": serialized_documents, "checkpoint": checkpoint}


@app.get("/api/sync/invalidation")
async def sync_invalidation_stream(user_id: str = Depends(get_current_app_user_id)):

    async def event_stream():
        last_seen_version = INVALIDATION_BROKER.get_version(user_id)
        while True:
            next_version = await asyncio.to_thread(
                INVALIDATION_BROKER.wait_for_change,
                user_id,
                last_seen_version,
                SSE_KEEPALIVE_INTERVAL_SECONDS,
            )
            if next_version > last_seen_version:
                last_seen_version = next_version
                yield f"data: {json.dumps({'type': 'RESYNC'})}\n\n"
            else:
                yield ": keepalive\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/sync/push")
def sync_push(
    payload: SyncPushRequest,
    request: Request,
    user: User = Depends(get_current_app_user),
    db: Session = Depends(get_db),
):
    enforce_allowed_origin(request)
    db_user = cast(Any, user)
    collection = validate_sync_collection(payload.collection)
    conflicts: list[dict[str, Any]] = []
    invalidated_user_ids: set[str] = set()
    try:
        for row in payload.rows:
            new_state = row.newDocumentState
            now = utcnow()

            if collection == "lists":
                list_document = parse_sync_list_document(new_state)
                list_id = clean_required_text(list_document.id, "list id", max_length=120)
                existing_any = cast(Optional[ListModel], db.query(ListModel).filter(ListModel.id == list_id).first())
                existing_any_db = cast(Any, existing_any) if existing_any is not None else None
                if existing_any_db is not None and existing_any_db.owner_id != db_user.id:
                    raise HTTPException(status_code=409, detail="List already exists")

                if existing_any_db is not None:
                    effective_state = get_list_effective_state(db, db_user.id, cast(ListModel, existing_any_db))
                    real_updated_at = cast(datetime, effective_state["effective_updated_at"]) if effective_state else cast(datetime, existing_any_db.updated_at)
                else:
                    real_updated_at = now

                if existing_any_db is not None and is_conflict(real_updated_at, row.assumedMasterState):
                    effective_state = get_list_effective_state(db, db_user.id, cast(ListModel, existing_any_db))
                    conflicts.append(
                        serialize_list_for_user(
                            cast(ListModel, existing_any_db),
                            str(effective_state["access_role"]) if effective_state else "owner",
                            int(effective_state["shared_with_count"]) if effective_state else 0,
                            cast(datetime, effective_state["effective_updated_at"]) if effective_state else cast(datetime, existing_any_db.updated_at),
                            get_username_by_user_id(db, cast(str, existing_any_db.owner_id)),
                            deleted_override=bool(effective_state["deleted"]) if effective_state else bool(existing_any_db.deleted),
                        )
                    )
                    continue

                created_at = parse_optional_datetime(
                    list_document.created_at,
                    cast(datetime, existing_any_db.created_at) if existing_any_db is not None else now,
                    field_name="created_at",
                )
                name = clean_required_text(list_document.name, "list name")
                archived = list_document.archived
                deleted = list_document.deleted

                if existing_any_db is not None:
                    existing_any_db.name = name
                    existing_any_db.archived = archived
                    existing_any_db.deleted = deleted
                    existing_any_db.owner_id = db_user.id
                    existing_any_db.updated_at = now
                    invalidated_user_ids.update(get_list_audience_user_ids(db, cast(ListModel, existing_any_db)))
                else:
                    db.add(
                        ListModel(
                            id=list_id,
                            owner_id=db_user.id,
                            name=name,
                            archived=archived,
                            deleted=deleted,
                            created_at=created_at,
                            updated_at=now,
                        )
                    )
                    invalidated_user_ids.add(str(db_user.id))

                if deleted:
                    child_todos = db.query(TodoModel).filter(TodoModel.list_id == list_id, TodoModel.deleted.is_(False)).all()
                    for todo in child_todos:
                        db_todo = cast(Any, todo)
                        db_todo.deleted = True
                        db_todo.updated_at = now

            elif collection == "todos":
                todo_document = parse_sync_todo_document(new_state)
                todo_id = clean_required_text(todo_document.id, "todo id", max_length=120)
                existing_owned = get_accessible_todo(db, db_user.id, todo_id)
                existing_any = cast(Optional[TodoModel], db.query(TodoModel).filter(TodoModel.id == todo_id).first())
                existing_any_db = cast(Any, existing_any) if existing_any is not None else None
                existing_owned_db = cast(Any, existing_owned) if existing_owned is not None else None
                if existing_any_db is not None and existing_owned_db is None:
                    raise HTTPException(status_code=409, detail="Todo already exists")

                if existing_owned_db is not None:
                    effective_state = get_todo_effective_state(db, db_user.id, cast(TodoModel, existing_owned_db))
                    real_updated_at = cast(datetime, effective_state["effective_updated_at"]) if effective_state else cast(datetime, existing_owned_db.updated_at)
                else:
                    real_updated_at = now

                if existing_owned_db is not None and is_conflict(real_updated_at, row.assumedMasterState):
                    effective_state = get_todo_effective_state(db, db_user.id, cast(TodoModel, existing_owned_db))
                    conflicts.append(
                        serialize_todo_for_user(
                            cast(TodoModel, existing_owned_db),
                            cast(datetime, effective_state["effective_updated_at"]) if effective_state else cast(datetime, existing_owned_db.updated_at),
                            deleted_override=bool(effective_state["deleted"]) if effective_state else bool(existing_owned_db.deleted),
                        )
                    )
                    continue

                list_id = clean_required_text(
                    todo_document.list_id or (existing_owned_db.list_id if existing_owned_db is not None else ""),
                    "list id",
                    max_length=120,
                )
                if existing_owned_db is not None and list_id != existing_owned_db.list_id:
                    raise HTTPException(status_code=409, detail="Todo list_id cannot be changed")

                parent_list = get_accessible_list(db, db_user.id, list_id, include_deleted=True)
                if not parent_list:
                    raise HTTPException(status_code=409, detail="Todo list is not accessible")
                db_parent_list = cast(Any, parent_list)
                if db_parent_list.deleted and not todo_document.deleted:
                    raise HTTPException(status_code=409, detail="Todo list is not accessible")

                created_at = parse_optional_datetime(
                    todo_document.created_at,
                    cast(datetime, existing_owned_db.created_at) if existing_owned_db is not None else now,
                    field_name="created_at",
                )
                title = clean_required_text(todo_document.title, "todo title")
                done = todo_document.done
                deleted = todo_document.deleted

                if existing_owned_db is not None:
                    existing_owned_db.title = title
                    existing_owned_db.done = done
                    existing_owned_db.deleted = deleted
                    existing_owned_db.updated_at = now
                    invalidated_user_ids.update(get_list_audience_user_ids_by_id(db, list_id))
                else:
                    db.add(
                        TodoModel(
                            id=todo_id,
                            list_id=list_id,
                            title=title,
                            done=done,
                            deleted=deleted,
                            created_at=created_at,
                            updated_at=now,
                        )
                    )
                    invalidated_user_ids.update(get_list_audience_user_ids_by_id(db, list_id))

        db.commit()
    except Exception:
        db.rollback()
        raise

    INVALIDATION_BROKER.publish(invalidated_user_ids)

    return conflicts


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/api")
@app.get("/api/{full_path:path}")
def unknown_api_route(full_path: str = ""):
    del full_path
    raise HTTPException(status_code=404, detail="Not found")


@app.get("/{full_path:path}")
def serve_spa(full_path: str):
    candidate_path = (DIST_DIR / full_path).resolve() if full_path else DIST_DIR / "index.html"
    if full_path and candidate_path.is_file() and DIST_DIR in candidate_path.parents:
        return FileResponse(candidate_path, headers=build_static_headers(candidate_path))

    index_path = DIST_DIR / "index.html"
    return FileResponse(index_path, headers=build_static_headers(index_path))
