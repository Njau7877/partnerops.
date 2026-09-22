# ============================================================
# PARTNEROPS 5.0 COMMERCIAL CONTROL
# SINGLE-SOURCE-OF-TRUTH APPLICATION
# ============================================================
#
# Streamlit commercial operations platform for:
#   - Telecom / ISP / OSP
#   - Logistics / Delivery
#   - Field Service / Contractors
#   - Distribution / FMCG
#   - Banking / Fintech / Agents
#   - Energy / Utilities
#   - Insurance
#   - Construction
#   - Healthcare
#
# INCLUDED:
#   Security / Authentication / RBAC
#   Multi-tenancy
#   Industry entitlements
#   Customer-scoped access links
#   Expiring access tokens
#   Audit logging
#   Data-quality gate
#   Partner performance intelligence
#   Risk scoring
#   Predictive risk
#   Anomaly detection
#   Trend analysis
#   Performance snapshots
#   Recovery action management
#   Intervention effectiveness
#   Commercial recovery valuation
#   Executive intelligence
#   Customer reporting
#   Excel export
#   Integration architecture
#   Telecom OSS connector
#   Field Service / FSM connector
#   FMCG / ERP connector
#   Fintech connector
#   Utility connector
#   Human-in-the-loop external actions
#
# IMPORTANT:
# External integrations are intentionally STUB/READY-FOR-CONFIGURATION.
# No real customer system is claimed to be connected until credentials,
# endpoints and deployment configuration are supplied.
# ============================================================

import os
import io
import json
import hmac
import hashlib
import secrets
import sqlite3
import logging
import zipfile
from difflib import SequenceMatcher
from datetime import datetime, date, timedelta, timezone
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

import pandas as pd
import streamlit as st

try:
    from PIL import Image
except Exception:
    Image = None

try:
    import pdfplumber
except Exception:
    pdfplumber = None

try:
    import pytesseract
except Exception:
    pytesseract = None

try:
    from docx import Document
except Exception:
    Document = None


# ============================================================
# 1. APPLICATION CONFIGURATION
# ============================================================

PLATFORM_NAME = "PartnerOps"
APP_VERSION = "5.2.0 Security & Production Hardened"


def get_config_value(name, default=None):
    """Read configuration from Streamlit Secrets first, then environment variables."""
    try:
        value = st.secrets.get(name)
        if value is not None:
            return str(value)
    except Exception:
        pass

    value = os.getenv(name)
    if value is not None:
        return str(value)

    return default


DB_FILE = get_config_value("PARTNEROPS_DB", "partnerops.db")
BASE_URL = str(
    get_config_value(
        "PARTNEROPS_BASE_URL",
        "https://partnerops-rpeqjfrqr4cujvyazrvbvs.streamlit.app",
    )
).rstrip("/")

try:
    MAX_UPLOAD_MB = int(get_config_value("PARTNEROPS_MAX_UPLOAD_MB", "25"))
except (TypeError, ValueError):
    MAX_UPLOAD_MB = 25

MAX_UPLOAD_MB = max(1, min(MAX_UPLOAD_MB, 200))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

# Defensive processing limits. These protect the Streamlit process from
# unexpectedly expensive uploads even when the raw file is below the byte limit.
try:
    MAX_UPLOAD_ROWS = int(get_config_value("PARTNEROPS_MAX_UPLOAD_ROWS", "250000"))
except (TypeError, ValueError):
    MAX_UPLOAD_ROWS = 250000
MAX_UPLOAD_ROWS = max(1000, min(MAX_UPLOAD_ROWS, 1000000))

try:
    MAX_UPLOAD_COLUMNS = int(get_config_value("PARTNEROPS_MAX_UPLOAD_COLUMNS", "250"))
except (TypeError, ValueError):
    MAX_UPLOAD_COLUMNS = 250
MAX_UPLOAD_COLUMNS = max(20, min(MAX_UPLOAD_COLUMNS, 1000))

MAX_UPLOAD_CELLS = MAX_UPLOAD_ROWS * MAX_UPLOAD_COLUMNS
MAX_ZIP_MEMBERS = 5000
MAX_ZIP_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_IMAGE_PIXELS = 50_000_000
MAX_PDF_PAGES = 250
SESSION_IDLE_MINUTES = 60
SESSION_MAX_MINUTES = 12 * 60

SUPPORTED_UPLOAD_TYPES = [
    "csv", "xlsx", "xls", "json", "txt",
    "pdf", "docx", "png", "jpg", "jpeg",
]

ACCESS_SECRET = get_config_value(
    "PARTNEROPS_ACCESS_SECRET",
    "CHANGE_THIS_PARTNEROPS_SECRET_BEFORE_PRODUCTION",
)

INITIAL_ADMIN_PASSWORD = get_config_value(
    "PARTNEROPS_INITIAL_ADMIN_PASSWORD",
    "CHANGE_THIS_ADMIN_PASSWORD",
)

PRODUCTION_MODE = str(
    get_config_value("PARTNEROPS_PRODUCTION", "false")
).lower() == "true"

PBKDF2_ITERATIONS = 210_000

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PartnerOps")


st.set_page_config(
    page_title="PartnerOps",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# 2. SECURITY BOOTSTRAP
# ============================================================

def security_configuration_ok():
    unsafe_secret = (
        not ACCESS_SECRET
        or ACCESS_SECRET == "CHANGE_THIS_PARTNEROPS_SECRET_BEFORE_PRODUCTION"
        or len(ACCESS_SECRET) < 32
    )

    unsafe_password = (
        not INITIAL_ADMIN_PASSWORD
        or INITIAL_ADMIN_PASSWORD == "CHANGE_THIS_ADMIN_PASSWORD"
    )

    return not unsafe_secret and not unsafe_password


if PRODUCTION_MODE and not security_configuration_ok():
    st.error(
        "PartnerOps is configured for production but secure secrets have not "
        "been configured. Set PARTNEROPS_ACCESS_SECRET and "
        "PARTNEROPS_INITIAL_ADMIN_PASSWORD."
    )
    st.stop()


# ============================================================
# 3. INDUSTRY CONFIGURATION
# ============================================================

INDUSTRIES = {
    "Telecom / ISP / OSP": {
        "description": "Partner performance, field operations and network delivery.",
        "primary_kpi": "output",
        "target": 90,
        "higher_is_better": [
            "output",
            "completed",
            "productivity",
            "quality",
            "delivery_rate",
            "completion_rate",
            "success_rate",
            "fulfillment_rate",
        ],
        "lower_is_better": [
            "pending",
            "failure_rate",
            "backlog",
            "aging",
        ],
        "weights": {
            "output": 0.30,
            "productivity": 0.20,
            "quality": 0.20,
            "completion_rate": 0.15,
            "pending": 0.15,
        },
    },

    "Logistics / Delivery": {
        "description": "Delivery, route and fulfillment partner control.",
        "primary_kpi": "delivery_rate",
        "target": 90,
        "higher_is_better": [
            "output",
            "completed",
            "productivity",
            "quality",
            "delivery_rate",
            "completion_rate",
            "success_rate",
            "fulfillment_rate",
        ],
        "lower_is_better": [
            "pending",
            "failure_rate",
            "backlog",
            "aging",
        ],
        "weights": {
            "delivery_rate": 0.35,
            "productivity": 0.20,
            "quality": 0.20,
            "pending": 0.15,
            "failure_rate": 0.10,
        },
    },

    "Field Service / Contractors": {
        "description": "Contractor and field workforce performance.",
        "primary_kpi": "completion_rate",
        "target": 90,
        "higher_is_better": [
            "output",
            "completed",
            "productivity",
            "quality",
            "delivery_rate",
            "completion_rate",
            "success_rate",
        ],
        "lower_is_better": [
            "pending",
            "failure_rate",
            "backlog",
            "aging",
        ],
        "weights": {
            "completion_rate": 0.35,
            "productivity": 0.25,
            "quality": 0.20,
            "pending": 0.10,
            "aging": 0.10,
        },
    },

    "Distribution / FMCG": {
        "description": "Distribution, route-to-market and fulfillment control.",
        "primary_kpi": "fulfillment_rate",
        "target": 92,
        "higher_is_better": [
            "output",
            "completed",
            "productivity",
            "quality",
            "delivery_rate",
            "fulfillment_rate",
        ],
        "lower_is_better": [
            "pending",
            "failure_rate",
            "backlog",
            "aging",
        ],
        "weights": {
            "fulfillment_rate": 0.35,
            "productivity": 0.20,
            "quality": 0.20,
            "pending": 0.15,
            "failure_rate": 0.10,
        },
    },

    "Banking / Fintech / Agents": {
        "description": "Agent, merchant and transaction partner operations.",
        "primary_kpi": "success_rate",
        "target": 95,
        "higher_is_better": [
            "output",
            "completed",
            "productivity",
            "quality",
            "success_rate",
            "completion_rate",
        ],
        "lower_is_better": [
            "pending",
            "failure_rate",
            "backlog",
            "aging",
        ],
        "weights": {
            "success_rate": 0.40,
            "quality": 0.20,
            "productivity": 0.15,
            "failure_rate": 0.15,
            "pending": 0.10,
        },
    },

    "Energy / Utilities": {
        "description": "Utility operations, maintenance and service delivery.",
        "primary_kpi": "completion_rate",
        "target": 90,
        "higher_is_better": [
            "output",
            "completed",
            "productivity",
            "quality",
            "completion_rate",
            "success_rate",
        ],
        "lower_is_better": [
            "pending",
            "failure_rate",
            "backlog",
            "aging",
        ],
        "weights": {
            "completion_rate": 0.30,
            "quality": 0.20,
            "productivity": 0.20,
            "pending": 0.15,
            "aging": 0.15,
        },
    },

    "Insurance": {
        "description": "Claims, agents and service partner performance.",
        "primary_kpi": "completion_rate",
        "target": 90,
        "higher_is_better": [
            "output",
            "completed",
            "productivity",
            "quality",
            "completion_rate",
            "success_rate",
        ],
        "lower_is_better": [
            "pending",
            "failure_rate",
            "backlog",
            "aging",
        ],
        "weights": {
            "completion_rate": 0.30,
            "quality": 0.25,
            "productivity": 0.20,
            "pending": 0.15,
            "aging": 0.10,
        },
    },

    "Construction": {
        "description": "Contractor, project and site delivery operations.",
        "primary_kpi": "completion_rate",
        "target": 85,
        "higher_is_better": [
            "output",
            "completed",
            "productivity",
            "quality",
            "completion_rate",
            "success_rate",
        ],
        "lower_is_better": [
            "pending",
            "failure_rate",
            "backlog",
            "aging",
        ],
        "weights": {
            "completion_rate": 0.30,
            "quality": 0.25,
            "productivity": 0.20,
            "pending": 0.15,
            "aging": 0.10,
        },
    },

    "Healthcare": {
        "description": "Service-provider and operational delivery control.",
        "primary_kpi": "completion_rate",
        "target": 90,
        "higher_is_better": [
            "output",
            "completed",
            "productivity",
            "quality",
            "completion_rate",
            "success_rate",
        ],
        "lower_is_better": [
            "pending",
            "failure_rate",
            "backlog",
            "aging",
        ],
        "weights": {
            "completion_rate": 0.30,
            "quality": 0.25,
            "productivity": 0.20,
            "pending": 0.15,
            "aging": 0.10,
        },
    },
}


# ============================================================
# 4. RBAC
# ============================================================

ROLE_PERMISSIONS = {
    "Admin": {
        "view",
        "upload",
        "actions",
        "reports",
        "export",
        "manage_users",
        "manage_entitlements",
        "platform_admin",
        "integrations",
        "audit",
    },

    "Manager": {
        "view",
        "upload",
        "actions",
        "reports",
        "export",
        "integrations",
    },

    "Analyst": {
        "view",
        "upload",
        "reports",
        "export",
    },

    "Viewer": {
        "view",
        "reports",
    },
}


def has_permission(permission):
    role = st.session_state.get("role")
    return permission in ROLE_PERMISSIONS.get(role, set())


# ============================================================
# 5. DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def db_execute(sql, params=(), fetch=False, many=False):
    conn = get_db()
    cur = conn.cursor()

    if many:
        cur.executemany(sql, params)
    else:
        cur.execute(sql, params)

    result = None

    if fetch:
        result = cur.fetchall()

    conn.commit()
    conn.close()

    return result


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS tenants (
            tenant_id TEXT PRIMARY KEY,
            tenant_name TEXT NOT NULL,
            plan TEXT DEFAULT 'pilot',
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS entitlements (
            tenant_id TEXT NOT NULL,
            industry TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            PRIMARY KEY (tenant_id, industry)
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            role TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL,
            UNIQUE (tenant_id, username)
        );

        CREATE TABLE IF NOT EXISTS access_links (
            link_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            industry TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            created_by TEXT,
            revoked_at TEXT,
            last_seen_at TEXT,
            use_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS datasets (
            dataset_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            industry TEXT NOT NULL,
            filename TEXT,
            row_count INTEGER,
            quality_status TEXT,
            uploaded_by TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS dataset_rows (
            row_id INTEGER PRIMARY KEY AUTOINCREMENT,
            dataset_id INTEGER NOT NULL,
            tenant_id TEXT NOT NULL,
            industry TEXT NOT NULL,
            row_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS interventions (
            action_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            industry TEXT NOT NULL,
            partner TEXT NOT NULL,
            action TEXT NOT NULL,
            owner TEXT,
            status TEXT DEFAULT 'Open',
            priority TEXT,
            target_outcome TEXT,
            baseline_kpi REAL,
            expected_kpi REAL,
            due_date TEXT,
            estimated_value REAL DEFAULT 0,
            actual_outcome REAL,
            actual_value REAL,
            update_note TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS snapshots (
            snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            industry TEXT NOT NULL,
            snapshot_date TEXT NOT NULL,
            partner TEXT NOT NULL,
            primary_kpi REAL,
            performance_score REAL,
            risk TEXT,
            band TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT,
            username TEXT,
            event_type TEXT NOT NULL,
            object_type TEXT,
            object_id TEXT,
            details TEXT,
            timestamp TEXT NOT NULL
        );
        """
    )

    # Backward-compatible migrations for databases created by 5.1.x.
    existing = {row[1] for row in cur.execute("PRAGMA table_info(access_links)").fetchall()}
    migrations = {
        "revoked_at": "ALTER TABLE access_links ADD COLUMN revoked_at TEXT",
        "last_seen_at": "ALTER TABLE access_links ADD COLUMN last_seen_at TEXT",
        "use_count": "ALTER TABLE access_links ADD COLUMN use_count INTEGER DEFAULT 0",
    }
    for column, statement in migrations.items():
        if column not in existing:
            cur.execute(statement)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_access_links_token_hash ON access_links(token_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_datasets_tenant_industry ON datasets(tenant_id, industry, dataset_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_dataset_rows_tenant_industry ON dataset_rows(tenant_id, industry, dataset_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_log(tenant_id, timestamp)")

    conn.commit()
    conn.close()


init_db()


# ============================================================
# 6. TIME / SECURITY HELPERS
# ============================================================

def utc_now():
    return datetime.now(timezone.utc)


def utc_iso():
    return utc_now().isoformat()


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )

    return (
        derived.hex(),
        salt.hex(),
    )


def verify_password(password, stored_hash, stored_salt):
    try:
        salt = bytes.fromhex(stored_salt)
        calculated, _ = hash_password(password, salt)

        return hmac.compare_digest(
            calculated,
            stored_hash,
        )
    except Exception:
        return False


def hash_access_token(token):
    return hmac.new(
        ACCESS_SECRET.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def stable_partner_hash(partner_id):
    return hashlib.sha256(
        str(partner_id or "default").encode("utf-8")
    ).hexdigest()[:10]


def audit(
    event_type,
    object_type=None,
    object_id=None,
    details=None,
    tenant_id=None,
    username=None,
):
    tenant_id = tenant_id or st.session_state.get("tenant_id")
    username = username or st.session_state.get("username")

    db_execute(
        """
        INSERT INTO audit_log
        (tenant_id, username, event_type, object_type, object_id, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            tenant_id,
            username,
            event_type,
            object_type,
            str(object_id) if object_id is not None else None,
            json.dumps(details or {}, default=str),
            utc_iso(),
        ),
    )


# ============================================================
# 7. DEMO / SEED DATA
# ============================================================

def seed_data():
    tenants = db_execute(
        "SELECT COUNT(*) AS n FROM tenants",
        fetch=True,
    )[0]["n"]

    if tenants:
        return

    now = utc_iso()

    db_execute(
        """
        INSERT INTO tenants
        (tenant_id, tenant_name, plan, status, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "partnerops_demo",
            "PartnerOps Demo",
            "commercial",
            "active",
            now,
        ),
    )

    db_execute(
        """
        INSERT INTO tenants
        (tenant_id, tenant_name, plan, status, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "hatikvah_demo",
            "Hatikvah Telecom Pilot",
            "pilot",
            "active",
            now,
        ),
    )

    for industry in INDUSTRIES:
        db_execute(
            """
            INSERT INTO entitlements
            (tenant_id, industry, enabled)
            VALUES (?, ?, 1)
            """,
            ("partnerops_demo", industry),
        )

    db_execute(
        """
        INSERT INTO entitlements
        (tenant_id, industry, enabled)
        VALUES (?, ?, 1)
        """,
        ("hatikvah_demo", "Telecom / ISP / OSP"),
    )

    admin_hash, admin_salt = hash_password(
        INITIAL_ADMIN_PASSWORD
        if INITIAL_ADMIN_PASSWORD != "CHANGE_THIS_ADMIN_PASSWORD"
        else "admin123"
    )

    db_execute(
        """
        INSERT INTO users
        (tenant_id, username, password_hash, password_salt,
         role, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "partnerops_demo",
            "admin",
            admin_hash,
            admin_salt,
            "Admin",
            "active",
            now,
        ),
    )

    if INITIAL_ADMIN_PASSWORD == "CHANGE_THIS_ADMIN_PASSWORD":
        logger.warning(
            "Demo admin password is temporary. "
            "Configure PARTNEROPS_INITIAL_ADMIN_PASSWORD before production."
        )


seed_data()


# ============================================================
# 8. INDUSTRY / TENANT SECURITY
# ============================================================

def get_tenant(tenant_id):
    rows = db_execute(
        "SELECT * FROM tenants WHERE tenant_id = ?",
        (tenant_id,),
        fetch=True,
    )

    return dict(rows[0]) if rows else None


def tenant_exists(tenant_id):
    return get_tenant(tenant_id) is not None


def tenant_industry_enabled(tenant_id, industry):
    rows = db_execute(
        """
        SELECT enabled
        FROM entitlements
        WHERE tenant_id = ? AND industry = ?
        """,
        (tenant_id, industry),
        fetch=True,
    )

    return bool(rows and rows[0]["enabled"])


def customer_scope_valid():
    if st.session_state.get("access_mode") != "customer":
        return True

    tenant_id = st.session_state.get("tenant_id")
    industry = st.session_state.get("locked_industry")

    if not tenant_id or not industry:
        return False

    return (
        tenant_exists(tenant_id)
        and tenant_industry_enabled(tenant_id, industry)
    )


def enforce_scope():
    if not customer_scope_valid():
        st.error("Customer access scope is invalid or expired.")
        st.stop()


# ============================================================
# 9. CUSTOMER ACCESS LINKS
# ============================================================

def create_access_link(
    tenant_id,
    industry,
    days=7,
    created_by=None,
):
    """Create an opaque, server-resolved customer access credential."""
    tenant = get_tenant(tenant_id)
    if not tenant or tenant["status"] != "active":
        raise ValueError("Customer tenant is not active.")

    if not tenant_industry_enabled(tenant_id, industry):
        raise ValueError("Industry is not entitled for this customer.")

    days = int(days)
    if days < 1 or days > 365:
        raise ValueError("Access-link validity must be between 1 and 365 days.")

    token = secrets.token_urlsafe(48)
    token_hash = hash_access_token(token)
    expires_at = (utc_now() + timedelta(days=days)).isoformat()
    created_at = utc_iso()

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO access_links
            (tenant_id, industry, token_hash, expires_at, active, created_at, created_by)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (
                tenant_id,
                industry,
                token_hash,
                expires_at,
                created_at,
                created_by or st.session_state.get("username"),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    audit(
        "ACCESS_LINK_CREATED",
        "access_link",
        token_hash[:12],
        {"industry": industry, "expires_at": expires_at},
        tenant_id=tenant_id,
    )

    base = BASE_URL or ""
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}access={token}"


def validate_access_token(token):
    """Resolve an opaque token and re-check authorization on every app rerun."""
    if not token or not isinstance(token, str) or len(token) < 32 or len(token) > 256:
        return None

    token_hash = hash_access_token(token)
    rows = db_execute(
        """
        SELECT link_id, tenant_id, industry, expires_at, active, revoked_at
        FROM access_links
        WHERE token_hash = ?
        ORDER BY link_id DESC
        LIMIT 1
        """,
        (token_hash,),
        fetch=True,
    )

    if not rows:
        return None

    row = rows[0]
    if not row["active"] or row["revoked_at"]:
        return None

    try:
        expires = datetime.fromisoformat(row["expires_at"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= utc_now():
            db_execute(
                "UPDATE access_links SET active = 0 WHERE link_id = ?",
                (row["link_id"],),
            )
            return None
    except Exception:
        return None

    tenant = get_tenant(row["tenant_id"])
    if not tenant or tenant["status"] != "active":
        return None

    if not tenant_industry_enabled(row["tenant_id"], row["industry"]):
        return None

    db_execute(
        """
        UPDATE access_links
        SET last_seen_at = ?, use_count = COALESCE(use_count, 0) + 1
        WHERE link_id = ? AND active = 1
        """,
        (utc_iso(), row["link_id"]),
    )

    return {
        "link_id": row["link_id"],
        "tenant_id": row["tenant_id"],
        "industry": row["industry"],
        "expires_at": row["expires_at"],
    }


def validate_access_link(tenant_id, industry, token):
    """Legacy validation retained for existing old-style links."""
    scope = validate_access_token(token)
    if not scope:
        return False

    return (
        hmac.compare_digest(str(scope["tenant_id"]), str(tenant_id))
        and hmac.compare_digest(str(scope["industry"]), str(industry))
    )


def rotate_customer_links(tenant_id, industry):
    db_execute(
        """
        UPDATE access_links
        SET active = 0, revoked_at = ?
        WHERE tenant_id = ? AND industry = ?
        """,
        (utc_iso(), tenant_id, industry),
    )

    audit(
        "ACCESS_LINKS_ROTATED",
        "tenant",
        tenant_id,
        {"industry": industry},
        tenant_id=tenant_id,
    )


# ============================================================
# 10. URL ACCESS BOOTSTRAP
# ============================================================

def process_customer_access():
    params = st.query_params

    token = params.get("access")
    legacy_tenant = params.get("tenant")
    legacy_industry = params.get("industry")

    if isinstance(token, list):
        token = token[0]
    if isinstance(legacy_tenant, list):
        legacy_tenant = legacy_tenant[0]
    if isinstance(legacy_industry, list):
        legacy_industry = legacy_industry[0]

    # New links: the token alone determines tenant and industry server-side.
    if token:
        scope = validate_access_token(token)

        if scope:
            same_session = (
                st.session_state.get("access_mode") == "customer"
                and st.session_state.get("authenticated") is True
                and hmac.compare_digest(
                    str(st.session_state.get("access_token") or ""),
                    str(token),
                )
            )

            st.session_state.authenticated = True
            st.session_state.access_mode = "customer"
            st.session_state.tenant_id = scope["tenant_id"]
            st.session_state.locked_industry = scope["industry"]
            st.session_state.current_industry = scope["industry"]
            st.session_state.role = "Viewer"
            st.session_state.username = "customer_link"
            st.session_state.access_token = token

            if not same_session:
                now = utc_iso()
                st.session_state.session_started_at = now
                st.session_state.last_activity_at = now
                audit(
                    "CUSTOMER_ACCESS_GRANTED",
                    "access_link",
                    scope["link_id"],
                    {"industry": scope["industry"]},
                    tenant_id=scope["tenant_id"],
                    username="customer_link",
                )

            # Keep the credential out of the visible browser URL after bootstrap.
            try:
                st.query_params.clear()
            except Exception:
                pass
            return True

        audit(
            "CUSTOMER_ACCESS_DENIED",
            "access_link",
            "unknown",
            {"reason": "invalid_or_expired_token"},
            username="customer_link",
        )

        st.error(
            "This customer access link is invalid, inactive, expired, "
            "or no longer entitled."
        )
        st.stop()

    # No credential means normal login flow.
    return False


# ============================================================
# 11. SESSION STATE
# ============================================================

DEFAULT_STATE = {
    "authenticated": False,
    "username": None,
    "tenant_id": None,
    "role": None,
    "access_mode": None,
    "locked_industry": None,
    "current_industry": None,
    "current_df": None,
    "generated_link": None,
    "selected_partner": None,
    "access_token": None,
    "session_started_at": None,
    "last_activity_at": None,
}

for key, value in DEFAULT_STATE.items():
    if key not in st.session_state:
        st.session_state[key] = value


customer_access = process_customer_access()


def revalidate_customer_session():
    """Re-check customer authorization on every Streamlit rerun."""
    if st.session_state.get("access_mode") != "customer":
        return

    token = st.session_state.get("access_token")
    if not token:
        st.session_state.authenticated = False
        st.error("Customer session is no longer valid. Please use a current access link.")
        st.stop()

    scope = validate_access_token(token)
    if not scope:
        audit(
            "CUSTOMER_SESSION_REVOKED",
            "access_link",
            "session",
            {"reason": "link_disabled_expired_or_tenant_disabled"},
            tenant_id=st.session_state.get("tenant_id"),
            username="customer_link",
        )
        for key in DEFAULT_STATE:
            st.session_state[key] = DEFAULT_STATE[key]
        st.error("Access revoked or expired. This customer workspace is no longer available.")
        st.stop()

    now = utc_now()
    try:
        started = datetime.fromisoformat(st.session_state.get("session_started_at"))
        last = datetime.fromisoformat(st.session_state.get("last_activity_at"))
        if started.tzinfo is None: started = started.replace(tzinfo=timezone.utc)
        if last.tzinfo is None: last = last.replace(tzinfo=timezone.utc)
    except Exception:
        started = now
        last = now
        st.session_state.session_started_at = now.isoformat()

    if now - last > timedelta(minutes=SESSION_IDLE_MINUTES) or now - started > timedelta(minutes=SESSION_MAX_MINUTES):
        audit(
            "CUSTOMER_SESSION_EXPIRED",
            "access_link",
            scope["link_id"],
            {"reason": "session_timeout"},
            tenant_id=scope["tenant_id"],
            username="customer_link",
        )
        for key in DEFAULT_STATE:
            st.session_state[key] = DEFAULT_STATE[key]
        st.error("Your customer session expired. Please open a fresh access link.")
        st.stop()

    st.session_state.tenant_id = scope["tenant_id"]
    st.session_state.locked_industry = scope["industry"]
    st.session_state.current_industry = scope["industry"]
    st.session_state.last_activity_at = now.isoformat()


revalidate_customer_session()


# ============================================================
# 12. LOGIN
# ============================================================

def authenticate_user(tenant_id, username, password):
    rows = db_execute(
        """
        SELECT *
        FROM users
        WHERE tenant_id = ?
          AND username = ?
        LIMIT 1
        """,
        (tenant_id, username),
        fetch=True,
    )

    if not rows:
        return False, "Invalid credentials."

    user = rows[0]

    if user["status"] != "active":
        return False, "User account is inactive."

    if user["locked_until"]:
        try:
            locked_until = datetime.fromisoformat(
                user["locked_until"]
            )

            if locked_until > utc_now():
                return False, "Account temporarily locked."

        except Exception:
            pass

    valid = verify_password(
        password,
        user["password_hash"],
        user["password_salt"],
    )

    if not valid:
        attempts = user["failed_attempts"] + 1

        if attempts >= 5:
            locked_until = (
                utc_now() + timedelta(minutes=15)
            ).isoformat()

            db_execute(
                """
                UPDATE users
                SET failed_attempts = 0,
                    locked_until = ?
                WHERE user_id = ?
                """,
                (locked_until, user["user_id"]),
            )

            audit(
                "ACCOUNT_LOCKED",
                "user",
                user["user_id"],
                {"username": username},
                tenant_id=tenant_id,
                username=username,
            )

            return False, "Too many failed attempts."

        db_execute(
            """
            UPDATE users
            SET failed_attempts = ?
            WHERE user_id = ?
            """,
            (attempts, user["user_id"]),
        )

        audit(
            "LOGIN_FAILED",
            "user",
            user["user_id"],
            {"attempts": attempts},
            tenant_id=tenant_id,
            username=username,
        )

        return False, "Invalid credentials."

    db_execute(
        """
        UPDATE users
        SET failed_attempts = 0,
            locked_until = NULL
        WHERE user_id = ?
        """,
        (user["user_id"],),
    )

    audit(
        "LOGIN_SUCCESS",
        "user",
        user["user_id"],
        {"role": user["role"]},
        tenant_id=tenant_id,
        username=username,
    )

    return True, user


def login_screen():
    st.title("📡 PartnerOps")
    st.subheader("Commercial Control Platform")

    st.info(
        "Secure workspace for partner performance intelligence, "
        "recovery management and commercial decision control."
    )

    with st.form("login_form"):
        tenant_id = st.text_input(
            "Tenant ID",
            value="partnerops_demo",
        )

        username = st.text_input(
            "Username",
        )

        password = st.text_input(
            "Password",
            type="password",
        )

        submitted = st.form_submit_button(
            "Sign in",
            use_container_width=True,
        )

    if submitted:
        ok, result = authenticate_user(
            tenant_id.strip(),
            username.strip(),
            password,
        )

        if ok:
            st.session_state.authenticated = True
            st.session_state.username = result["username"]
            st.session_state.tenant_id = result["tenant_id"]
            st.session_state.role = result["role"]
            st.session_state.access_mode = "platform"
            st.session_state.current_industry = (
                "Telecom / ISP / OSP"
            )

            st.rerun()

        st.error(result)

    st.caption(
        "Production deployment requires secure environment secrets."
    )


if not st.session_state.authenticated:
    login_screen()
    st.stop()


enforce_scope()


# ============================================================
# 13. DATA NORMALIZATION
# ============================================================

COLUMN_ALIASES = {
    "partner": [
        "partner",
        "partner_name",
        "contractor",
        "vendor",
        "agent",
        "provider",
        "company",
    ],
    "output": [
        "output",
        "volume",
        "jobs",
        "orders",
        "completed_jobs",
        "units",
    ],
    "completed": [
        "completed",
        "done",
        "closed",
        "fulfilled",
    ],
    "pending": [
        "pending",
        "open",
        "outstanding",
        "pending_jobs",
    ],
    "productivity": [
        "productivity",
        "productivity_pct",
        "efficiency",
        "efficiency_pct",
    ],
    "quality": [
        "quality",
        "quality_pct",
        "quality_score",
        "accuracy",
    ],
    "delivery_rate": [
        "delivery_rate",
        "delivery_rate_pct",
        "on_time_rate",
        "on_time_delivery",
        "otd",
    ],
    "completion_rate": [
        "completion_rate",
        "completion_rate_pct",
        "completion",
        "completion_pct",
    ],
    "success_rate": [
        "success_rate",
        "success_rate_pct",
        "success",
        "transaction_success",
    ],
    "fulfillment_rate": [
        "fulfillment_rate",
        "fulfilment_rate",
        "fill_rate",
        "fill_rate_pct",
    ],
    "failure_rate": [
        "failure_rate",
        "failure_rate_pct",
        "failure",
        "error_rate",
    ],
    "backlog": [
        "backlog",
        "backlog_count",
    ],
    "aging": [
        "aging",
        "aging_days",
        "average_age",
        "age",
    ],
    "date": [
        "date",
        "period",
        "day",
        "week",
        "month",
        "timestamp",
        "created_at",
    ],
}


def clean_column_name(value):
    return (
        str(value)
        .strip()
        .lower()
        .replace(" ", "_")
        .replace("-", "_")
        .replace("/", "_")
    )


def _column_similarity(a, b):
    a = clean_column_name(a).replace("_", "")
    b = clean_column_name(b).replace("_", "")
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    if a in b or b in a:
        return 0.92
    return SequenceMatcher(None, a, b).ratio()


def _coerce_numeric_series(series):
    if pd.api.types.is_numeric_dtype(series):
        return pd.to_numeric(series, errors="coerce")

    cleaned = (
        series.astype(str)
        .str.strip()
        .replace({"": pd.NA, "nan": pd.NA, "None": pd.NA})
        .str.replace(",", "", regex=False)
        .str.replace("%", "", regex=False)
        .str.replace(r"[^0-9.\-]", "", regex=True)
    )
    return pd.to_numeric(cleaned, errors="coerce")


def normalize_dataframe(df):
    if df is None:
        return pd.DataFrame()

    df = df.copy()

    if df.empty:
        return df

    df.dropna(axis=0, how="all", inplace=True)
    df.dropna(axis=1, how="all", inplace=True)

    original_columns = []
    seen = {}

    for idx, col in enumerate(df.columns):
        raw = str(col).strip()

        if not raw or raw.lower().startswith("unnamed"):
            raw = f"column_{idx + 1}"

        base = clean_column_name(raw)
        count = seen.get(base, 0)
        seen[base] = count + 1

        original_columns.append(
            base if count == 0 else f"{base}_{count + 1}"
        )

    df.columns = original_columns

    rename_map = {}
    claimed_targets = set()

    # Exact aliases first.
    for canonical, aliases in COLUMN_ALIASES.items():
        if canonical in df.columns:
            claimed_targets.add(canonical)
            continue

        alias_set = {
            clean_column_name(alias)
            for alias in aliases
        }

        for col in df.columns:
            if col in rename_map:
                continue

            if col in alias_set and canonical not in claimed_targets:
                rename_map[col] = canonical
                claimed_targets.add(canonical)
                break

    df.rename(columns=rename_map, inplace=True)

    # Conservative fuzzy matching for common human variations.
    for col in list(df.columns):
        if col in claimed_targets:
            continue

        candidates = []

        for canonical, aliases in COLUMN_ALIASES.items():
            if canonical in df.columns or canonical in claimed_targets:
                continue

            for alias in [canonical] + aliases:
                candidates.append(
                    (_column_similarity(col, alias), canonical)
                )

        candidates.sort(reverse=True)

        if not candidates:
            continue

        best_score, best_target = candidates[0]
        second_score = (
            candidates[1][0]
            if len(candidates) > 1
            else 0.0
        )

        if (
            best_score >= 0.88
            and best_score - second_score >= 0.04
            and best_target not in df.columns
            and best_target not in claimed_targets
        ):
            df.rename(
                columns={col: best_target},
                inplace=True,
            )
            claimed_targets.add(best_target)

    if "partner" in df.columns:
        df["partner"] = (
            df["partner"]
            .astype(str)
            .str.strip()
            .replace({"nan": pd.NA, "None": pd.NA})
        )

    numeric_columns = [
        "output",
        "completed",
        "pending",
        "productivity",
        "quality",
        "delivery_rate",
        "completion_rate",
        "success_rate",
        "fulfillment_rate",
        "failure_rate",
        "backlog",
        "aging",
    ]

    for col in numeric_columns:
        if col in df.columns:
            df[col] = _coerce_numeric_series(df[col])

    if "date" in df.columns:
        df["date"] = pd.to_datetime(
            df["date"],
            errors="coerce",
        )

    if (
        "completion_rate" not in df.columns
        and "completed" in df.columns
        and "output" in df.columns
    ):
        denominator = df["output"].replace(0, pd.NA)
        df["completion_rate"] = (
            df["completed"] / denominator * 100
        )

    if (
        "delivery_rate" not in df.columns
        and "completed" in df.columns
        and "output" in df.columns
    ):
        denominator = df["output"].replace(0, pd.NA)
        df["delivery_rate"] = (
            df["completed"] / denominator * 100
        )

    return df


# ============================================================
# 14. DATA QUALITY ENGINE
# ============================================================

def quality_check(df, industry):
    cfg = INDUSTRIES[industry]

    issues = []
    warnings = []

    if df is None or df.empty:
        issues.append("Dataset is empty.")
        return {
            "status": "BLOCKED",
            "issues": issues,
            "warnings": warnings,
            "rows": 0,
            "columns": 0,
            "duplicates": 0,
        }

    # Missing fields are onboarding warnings, not automatic rejection.
    # Operational exports frequently contain only a subset of available KPIs.
    if "partner" not in df.columns:
        warnings.append(
            "Partner identifier was not detected. Rows will be retained, but a partner-level name should be mapped during onboarding."
        )

    primary = cfg["primary_kpi"]

    if primary not in df.columns:
        warnings.append(
            f"Primary KPI '{primary}' is not present. PartnerOps will use available configured metrics and mark the primary KPI as unavailable."
        )

    duplicates = int(df.duplicated().sum())

    if duplicates:
        warnings.append(
            f"{duplicates} duplicate row(s) detected."
        )

    if "partner" in df.columns:
        missing_partners = int(
            df["partner"].isna().sum()
        )

        if missing_partners:
            warnings.append(
                f"{missing_partners} row(s) have no partner identifier."
            )

    if primary in df.columns:
        missing_kpi = int(
            df[primary].isna().sum()
        )

        if missing_kpi:
            warnings.append(
                f"{missing_kpi} row(s) have missing primary KPI values."
            )

    numeric_columns = [
        c for c in df.columns
        if c in COLUMN_ALIASES
        and c not in ["partner", "date"]
    ]

    for col in numeric_columns:
        if df[col].notna().any():
            bad = pd.to_numeric(
                df[col],
                errors="coerce",
            ).isna() & df[col].notna()

            if bad.any():
                warnings.append(
                    f"Non-numeric values detected in '{col}'."
                )

    if issues:
        status = "BLOCKED"
    elif warnings:
        status = "REVIEW"
    else:
        status = "GOOD"

    return {
        "status": status,
        "issues": issues,
        "warnings": warnings,
        "rows": len(df),
        "columns": len(df.columns),
        "duplicates": duplicates,
    }


# ============================================================
# 15. PERFORMANCE ENGINE
# ============================================================

def score_band(score):
    if score >= 90:
        return "Excellent"

    if score >= 80:
        return "Strong"

    if score >= 70:
        return "Watch"

    if score >= 50:
        return "At Risk"

    return "Critical"


def risk_band(score):
    if score < 50:
        return "Critical"

    if score < 70:
        return "High"

    if score < 80:
        return "Medium"

    return "Low"


def normalize_metric(value, target, lower_is_better=False):
    if pd.isna(value):
        return None

    try:
        value = float(value)
        target = float(target)

        if lower_is_better:
            if value <= target:
                return 100.0

            if target <= 0:
                return max(
                    0,
                    100 - value,
                )

            return max(
                0,
                min(
                    100,
                    (target / value) * 100,
                ),
            )

        if target <= 0:
            return 0

        return max(
            0,
            min(
                100,
                (value / target) * 100,
            ),
        )

    except Exception:
        return None


def diagnosis_for_row(row, cfg):
    primary = cfg["primary_kpi"]
    target = cfg["target"]

    value = row.get(primary)

    if pd.isna(value):
        return "Insufficient KPI data."

    gap = target - float(value)

    if gap <= 0:
        return "Meeting or exceeding primary KPI target."

    if gap >= 30:
        return "Severe performance gap requiring immediate recovery."

    if gap >= 15:
        return "Material performance gap requiring management intervention."

    return "Moderate performance gap requiring monitoring and targeted action."


def recommended_action(row, cfg):
    primary = cfg["primary_kpi"]

    if primary in row.index:
        value = row.get(primary)

        if pd.notna(value) and value < cfg["target"]:
            if "pending" in row.index and pd.notna(row["pending"]):
                if row["pending"] > 0:
                    return "Clear backlog and assign recovery owner."

            if "productivity" in row.index and pd.notna(row["productivity"]):
                if row["productivity"] < 80:
                    return "Run productivity intervention and capacity review."

            if "quality" in row.index and pd.notna(row["quality"]):
                if row["quality"] < 80:
                    return "Run quality root-cause review and corrective action."

            return "Create targeted recovery action."

    return "Continue monitoring."


def performance_engine(df, industry):
    cfg = INDUSTRIES[industry]
    result = df.copy()

    for metric in cfg["weights"]:
        if metric not in result.columns:
            result[metric] = pd.NA

    # Portfolio maximums for lower-is-better normalization.
    lower_max = {}

    for metric in cfg["lower_is_better"]:
        if metric in result.columns:
            values = pd.to_numeric(
                result[metric],
                errors="coerce",
            )

            lower_max[metric] = (
                values.max()
                if values.notna().any()
                else 1
            )

    scores = []

    for _, row in result.iterrows():
        weighted_total = 0
        weight_total = 0

        for metric, weight in cfg["weights"].items():
            if metric not in row.index:
                continue

            value = row.get(metric)

            if pd.isna(value):
                continue

            if metric in cfg["lower_is_better"]:
                target = cfg["target"]

                if metric in ["pending", "backlog", "aging"]:
                    maximum = lower_max.get(metric, 1)

                    if maximum and maximum > 0:
                        metric_score = (
                            100
                            * (maximum - float(value))
                            / maximum
                        )

                        metric_score = max(
                            0,
                            min(100, metric_score),
                        )
                    else:
                        metric_score = 100

                else:
                    metric_score = normalize_metric(
                        value,
                        target,
                        lower_is_better=True,
                    )

            else:
                metric_score = normalize_metric(
                    value,
                    cfg["target"],
                    lower_is_better=False,
                )

            if metric_score is not None:
                weighted_total += metric_score * weight
                weight_total += weight

        score = (
            weighted_total / weight_total
            if weight_total
            else 0
        )

        scores.append(score)

    result["performance_score"] = (
        pd.Series(scores, index=result.index)
        .round(2)
    )

    primary = cfg["primary_kpi"]

    result["target"] = cfg["target"]

    if primary in result.columns:
        primary_values = pd.to_numeric(
            result[primary],
            errors="coerce",
        )

        result["target_gap"] = (
            cfg["target"] - primary_values
        ).round(2)
    else:
        result["target_gap"] = float("nan")

    result["band"] = result["performance_score"].apply(
        score_band
    )

    result["risk"] = result["performance_score"].apply(
        risk_band
    )

    result["attention_required"] = (
        result["performance_score"] < cfg["target"]
    )

    result["diagnosis"] = result.apply(
        lambda r: diagnosis_for_row(r, cfg),
        axis=1,
    )

    result["recommended_action"] = result.apply(
        lambda r: recommended_action(r, cfg),
        axis=1,
    )

    if "output" in result.columns:
        result["recovery_opportunity"] = (
            result["target_gap"].clip(lower=0)
            * result["output"]
            / 100
        ).round(2)
    else:
        result["recovery_opportunity"] = 0

    def priority(score):
        if score < 50:
            return "P1"
        if score < 70:
            return "P2"
        if score < 80:
            return "P3"
        return "P4"

    result["priority"] = (
        result["performance_score"]
        .apply(priority)
    )

    result["rank"] = (
        result["performance_score"]
        .rank(
            ascending=False,
            method="min",
        )
        .astype(int)
    )

    return result.sort_values(
        "performance_score",
        ascending=False,
    ).reset_index(drop=True)


# ============================================================
# 16. SNAPSHOTS
# ============================================================

def save_snapshot(df, industry, tenant_id):
    if df is None or df.empty:
        return

    cfg = INDUSTRIES[industry]
    primary = cfg["primary_kpi"]
    snapshot_date = utc_now().date().isoformat()

    rows = []

    for _, row in df.iterrows():
        partner = str(row.get("partner", ""))

        if not partner:
            continue

        rows.append(
            (
                tenant_id,
                industry,
                snapshot_date,
                partner,
                float(row.get(primary, 0))
                if pd.notna(row.get(primary))
                else None,
                float(row.get("performance_score", 0))
                if pd.notna(row.get("performance_score"))
                else None,
                row.get("risk"),
                row.get("band"),
            )
        )

    if rows:
        db_execute(
            """
            INSERT INTO snapshots
            (tenant_id, industry, snapshot_date, partner,
             primary_kpi, performance_score, risk, band)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
            many=True,
        )


# ============================================================
# 17. TREND ENGINE
# ============================================================

def trend_analysis(df, industry):
    cfg = INDUSTRIES[industry]
    primary = cfg["primary_kpi"]

    if "date" not in df.columns:
        return None, (
            "Trend analysis requires a historical date/period column."
        )

    if primary not in df.columns:
        return None, (
            f"Trend analysis requires '{primary}'."
        )

    work = df[
        ["date", primary]
    ].copy()

    work = work.dropna()

    if work.empty:
        return None, "No historical observations available."

    work["date"] = pd.to_datetime(
        work["date"],
        errors="coerce",
    )

    work = work.dropna(subset=["date"])

    if work.empty:
        return None, "No valid historical dates found."

    trend = (
        work.groupby(
            work["date"].dt.date
        )[primary]
        .mean()
        .reset_index()
    )

    trend.columns = [
        "date",
        primary,
    ]

    trend = trend.sort_values("date")

    if len(trend) >= 2:
        first = float(trend.iloc[0][primary])
        last = float(trend.iloc[-1][primary])

        if last > first:
            direction = "Improving"
        elif last < first:
            direction = "Declining"
        else:
            direction = "Flat"
    else:
        direction = "Insufficient history"

    return trend, direction


# ============================================================
# 18. ANOMALY ENGINE
# ============================================================

def anomaly_analysis(df, industry):
    cfg = INDUSTRIES[industry]
    primary = cfg["primary_kpi"]

    if primary not in df.columns:
        return pd.DataFrame()

    work = df.copy()

    numeric = pd.to_numeric(
        work[primary],
        errors="coerce",
    )

    mean = numeric.mean()
    std = numeric.std()

    if pd.isna(std) or std == 0:
        work["anomaly"] = False
        work["anomaly_reason"] = ""
        return work

    z = (
        (numeric - mean)
        / std
    ).abs()

    work["anomaly_score"] = z.round(2)
    work["anomaly"] = z >= 2

    work["anomaly_reason"] = work.apply(
        lambda r:
        f"Unusual {primary} value."
        if r["anomaly"]
        else "",
        axis=1,
    )

    return work[
        work["anomaly"]
    ].copy()


# ============================================================
# 19. PREDICTIVE RISK ENGINE
# ============================================================

def predictive_risk(df, industry):
    cfg = INDUSTRIES[industry]

    result = df.copy()

    scores = []
    reasons = []

    for _, row in result.iterrows():
        risk_score = 0
        reason = []

        score = row.get("performance_score", 0)

        if score < 50:
            risk_score += 50
            reason.append("critical current performance")
        elif score < 70:
            risk_score += 30
            reason.append("high performance risk")
        elif score < 80:
            risk_score += 15
            reason.append("performance below strong range")

        pending = row.get("pending")

        if pd.notna(pending) and pending > 0:
            risk_score += min(
                20,
                float(pending) / 10,
            )
            reason.append("open workload")

        aging = row.get("aging")

        if pd.notna(aging) and aging > 7:
            risk_score += min(
                20,
                float(aging),
            )
            reason.append("aging workload")

        quality = row.get("quality")

        if pd.notna(quality) and quality < 80:
            risk_score += 10
            reason.append("quality pressure")

        risk_score = min(
            100,
            round(risk_score, 2),
        )

        if risk_score >= 70:
            forecast = "Severe"
        elif risk_score >= 45:
            forecast = "Elevated"
        elif risk_score >= 20:
            forecast = "Moderate"
        else:
            forecast = "Low"

        scores.append(risk_score)

        reasons.append(
            ", ".join(reason)
            if reason
            else "No major leading indicators detected."
        )

    result["predictive_risk_score"] = scores
    result["predicted_risk"] = [
        (
            "Severe"
            if s >= 70
            else "Elevated"
            if s >= 45
            else "Moderate"
            if s >= 20
            else "Low"
        )
        for s in scores
    ]
    result["risk_drivers"] = reasons

    return result


# ============================================================
# 20. COMMERCIAL VALUE ENGINE
# ============================================================

def commercial_value(df, value_per_unit):
    result = df.copy()

    if "recovery_opportunity" not in result.columns:
        result["recovery_opportunity"] = 0

    result["estimated_value_ksh"] = (
        pd.to_numeric(
            result["recovery_opportunity"],
            errors="coerce",
        )
        .fillna(0)
        * float(value_per_unit)
    ).round(2)

    return result


# ============================================================
# 21. DATA STORAGE
# ============================================================

def save_dataset(
    df,
    filename,
    quality_status,
    industry,
):
    """Persist a tenant-scoped dataset atomically and return its id."""
    tenant_id = st.session_state.tenant_id
    if not tenant_id or not tenant_industry_enabled(tenant_id, industry):
        raise PermissionError("Dataset cannot be saved outside the authorized tenant scope.")

    if len(df) > MAX_UPLOAD_ROWS or len(df.columns) > MAX_UPLOAD_COLUMNS:
        raise ValueError("Dataset exceeds the configured processing limits.")

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO datasets
            (tenant_id, industry, filename, row_count, quality_status, uploaded_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (tenant_id, industry, filename, len(df), quality_status, st.session_state.username, utc_iso()),
        )
        dataset_id = cur.lastrowid

        payloads = [
            (dataset_id, tenant_id, industry, json.dumps(row.to_dict(), default=str))
            for _, row in df.iterrows()
        ]
        if payloads:
            cur.executemany(
                """
                INSERT INTO dataset_rows (dataset_id, tenant_id, industry, row_json)
                VALUES (?, ?, ?, ?)
                """,
                payloads,
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    audit(
        "DATASET_UPLOADED",
        "dataset",
        dataset_id,
        {"filename": filename, "rows": len(df), "quality": quality_status},
    )
    return dataset_id


def load_latest_saved_dataset(tenant_id, industry):
    rows = db_execute(
        """
        SELECT dataset_id
        FROM datasets
        WHERE tenant_id = ?
          AND industry = ?
        ORDER BY dataset_id DESC
        LIMIT 1
        """,
        (
            tenant_id,
            industry,
        ),
        fetch=True,
    )

    if not rows:
        return None

    dataset_id = rows[0]["dataset_id"]

    row_data = db_execute(
        """
        SELECT row_json
        FROM dataset_rows
        WHERE dataset_id = ?
        """,
        (dataset_id,),
        fetch=True,
    )

    if not row_data:
        return None

    records = []

    for row in row_data:
        try:
            records.append(
                json.loads(row["row_json"])
            )
        except Exception:
            pass

    if not records:
        return None

    return pd.DataFrame(records)


# ============================================================
# 22. DEMO DATA
# ============================================================

def demo_telecom():
    return pd.DataFrame(
        [
            {
                "partner": "Alpha Networks",
                "output": 950,
                "completed": 900,
                "pending": 50,
                "productivity": 94,
                "quality": 96,
                "completion_rate": 94.7,
                "delivery_rate": 94.7,
                "date": "2026-09-01",
            },
            {
                "partner": "Beta Connect",
                "output": 850,
                "completed": 680,
                "pending": 170,
                "productivity": 79,
                "quality": 86,
                "completion_rate": 80,
                "delivery_rate": 80,
                "date": "2026-09-01",
            },
            {
                "partner": "Gamma Fiber",
                "output": 720,
                "completed": 560,
                "pending": 160,
                "productivity": 76,
                "quality": 83,
                "completion_rate": 77.8,
                "delivery_rate": 77.8,
                "date": "2026-09-01",
            },
            {
                "partner": "Delta Works",
                "output": 1100,
                "completed": 1010,
                "pending": 90,
                "productivity": 91,
                "quality": 92,
                "completion_rate": 91.8,
                "delivery_rate": 91.8,
                "date": "2026-09-01",
            },
            {
                "partner": "EastLink",
                "output": 500,
                "completed": 330,
                "pending": 170,
                "productivity": 65,
                "quality": 72,
                "completion_rate": 66,
                "delivery_rate": 66,
                "date": "2026-09-01",
            },
            {
                "partner": "Prime Field",
                "output": 880,
                "completed": 700,
                "pending": 180,
                "productivity": 73,
                "quality": 79,
                "completion_rate": 79.5,
                "delivery_rate": 79.5,
                "date": "2026-09-01",
            },
            {
                "partner": "Rapid Install",
                "output": 1020,
                "completed": 970,
                "pending": 50,
                "productivity": 96,
                "quality": 94,
                "completion_rate": 95.1,
                "delivery_rate": 95.1,
                "date": "2026-09-01",
            },
            {
                "partner": "Metro OSP",
                "output": 610,
                "completed": 430,
                "pending": 180,
                "productivity": 68,
                "quality": 75,
                "completion_rate": 70.5,
                "delivery_rate": 70.5,
                "date": "2026-09-01",
            },
        ]
    )


def demo_logistics():
    return pd.DataFrame(
        [
            {
                "partner": "Swift Logistics",
                "output": 1000,
                "completed": 960,
                "pending": 40,
                "productivity": 95,
                "quality": 94,
                "delivery_rate": 96,
                "date": "2026-09-01",
            },
            {
                "partner": "Route Masters",
                "output": 850,
                "completed": 700,
                "pending": 150,
                "productivity": 78,
                "quality": 82,
                "delivery_rate": 82,
                "date": "2026-09-01",
            },
            {
                "partner": "East Cargo",
                "output": 700,
                "completed": 510,
                "pending": 190,
                "productivity": 70,
                "quality": 76,
                "delivery_rate": 73,
                "date": "2026-09-01",
            },
        ]
    )


def get_demo_data(industry):
    if industry == "Telecom / ISP / OSP":
        return demo_telecom()

    if industry == "Logistics / Delivery":
        return demo_logistics()

    return demo_telecom()


# ============================================================
# 23. CURRENT DATA LOADER
# ============================================================

def get_current_data(industry):
    if st.session_state.current_df is not None:
        return st.session_state.current_df.copy()

    saved = load_latest_saved_dataset(
        st.session_state.tenant_id,
        industry,
    )

    if saved is not None:
        return normalize_dataframe(saved)

    # Customer links never fall back to global/demo operational data.
    if st.session_state.get("access_mode") == "customer":
        return pd.DataFrame()

    return normalize_dataframe(get_demo_data(industry))


def set_current_data(df, industry, filename="current_dataset"):
    normalized = normalize_dataframe(df)

    quality = quality_check(
        normalized,
        industry,
    )

    if quality["status"] == "BLOCKED":
        return False, quality

    st.session_state.current_df = normalized
    st.session_state.current_industry = industry

    save_dataset(
        normalized,
        str(filename)[:255],
        quality["status"],
        industry,
    )

    return True, quality


# ============================================================
# 24. INTEGRATION ARCHITECTURE
# ============================================================

class BaseIntegrationConnector(ABC):

    def __init__(
        self,
        connector_id,
        industry,
        config=None,
    ):
        self.connector_id = connector_id
        self.industry = industry
        self.config = config or {}
        self.is_active = False
        self.last_sync_timestamp = None

    @abstractmethod
    def test_connection(self):
        pass

    @abstractmethod
    def fetch_partner_metrics(self, partner_id):
        pass

    @abstractmethod
    def push_recovery_action(self, action_payload):
        pass


class TelecomOSSConnector(BaseIntegrationConnector):

    def test_connection(self):
        endpoint = self.config.get(
            "endpoint_url"
        )

        if not endpoint:
            return {
                "status": "READY_FOR_CONFIGURATION",
                "connected": False,
                "endpoint": "NOT_CONFIGURED",
                "supported_protocols": [
                    "REST/JSON",
                    "gRPC",
                    "SNMP Traps",
                ],
            }

        return {
            "status": "STUB",
            "connected": False,
            "endpoint": endpoint,
            "supported_protocols": [
                "REST/JSON",
                "gRPC",
                "SNMP Traps",
            ],
        }

    def fetch_partner_metrics(self, partner_id):
        return {
            "partner_id": partner_id,
            "status": "MOCK_DATA",
            "sla_compliance_pct": 94.2,
            "mean_time_to_repair_hrs": 3.8,
            "first_time_fix_rate": 88.5,
            "source_system": "Telecom OSS/BSS Gate",
        }

    def push_recovery_action(self, action_payload):
        if not action_payload.get(
            "human_approved",
            False,
        ):
            return {
                "status": "PENDING_APPROVAL",
                "message": (
                    "Action held in Human-in-the-Loop queue "
                    "before OSS dispatch."
                ),
            }

        return {
            "status": "STUB_DISPATCH",
            "external_ticket_id": (
                f"TEL-TICK-"
                f"{utc_now().strftime('%Y%m%d%H%M%S')}"
            ),
            "payload": action_payload,
        }


class FieldServiceConnector(BaseIntegrationConnector):

    def test_connection(self):
        return {
            "status": "READY_FOR_CONFIGURATION",
            "connected": False,
            "target_fsm": self.config.get(
                "fsm_provider",
                "Generic FSM REST API",
            ),
        }

    def fetch_partner_metrics(self, partner_id):
        return {
            "partner_id": partner_id,
            "status": "MOCK_DATA",
            "route_efficiency_pct": 89.1,
            "on_time_delivery_rate": 91.4,
            "fsm_provider": self.config.get(
                "fsm_provider",
                "Generic FSM",
            ),
        }

    def push_recovery_action(self, action_payload):
        if not action_payload.get(
            "human_approved",
            False,
        ):
            return {
                "status": "PENDING_APPROVAL",
                "reason": (
                    "Requires Manager approval "
                    "in PartnerOps."
                ),
            }

        return {
            "status": "STUB_FSM_QUEUE",
            "fsm_job_id": (
                "FSM-JOB-"
                + stable_partner_hash(
                    action_payload.get("partner_id")
                )
            ),
        }


class FMCGDistributionConnector(BaseIntegrationConnector):

    def test_connection(self):
        return {
            "status": "READY_FOR_CONFIGURATION",
            "connected": False,
            "erp_target": self.config.get(
                "erp_system",
                "SAP S/4HANA",
            ),
        }

    def fetch_partner_metrics(self, partner_id):
        return {
            "partner_id": partner_id,
            "status": "MOCK_DATA",
            "fill_rate_pct": 96.0,
            "stockout_frequency_per_month": 1.2,
            "commercial_recovery_value_ksh": 450000.00,
        }

    def push_recovery_action(self, action_payload):
        if not action_payload.get(
            "human_approved",
            False,
        ):
            return {
                "status": "PENDING_APPROVAL",
                "reason": "Human approval required.",
            }

        return {
            "status": "STAGED_FOR_ERP_SYNC",
            "action_id": action_payload.get(
                "action_id"
            ),
        }


class FintechMerchantConnector(BaseIntegrationConnector):

    def test_connection(self):
        return {
            "status": "READY_FOR_CONFIGURATION",
            "connected": False,
            "gateway": self.config.get(
                "gateway",
                "Core Banking API",
            ),
        }

    def fetch_partner_metrics(self, partner_id):
        return {
            "partner_id": partner_id,
            "status": "MOCK_DATA",
            "terminal_uptime_pct": 99.1,
            "transaction_failure_rate": 0.02,
            "settlement_delay_hours": 4.5,
        }

    def push_recovery_action(self, action_payload):
        return {
            "status": "HOLD_RECOVERY_DISPATCH",
            "reason": (
                "Financial Risk Officer validation required."
            ),
        }


class UtilityGridConnector(BaseIntegrationConnector):

    def test_connection(self):
        return {
            "status": "READY_FOR_CONFIGURATION",
            "connected": False,
            "protocol": "SCADA / MQTT Bridge",
        }

    def fetch_partner_metrics(self, partner_id):
        return {
            "partner_id": partner_id,
            "status": "MOCK_DATA",
            "grid_leakage_index": 0.05,
            "maintenance_response_mins": 42,
        }

    def push_recovery_action(self, action_payload):
        if not action_payload.get(
            "human_approved",
            False,
        ):
            return {
                "status": "PENDING_APPROVAL",
                "reason": "Human approval required.",
            }

        return {
            "status": "QUEUED_GRID_DISPATCH",
            "action": action_payload,
        }


class IntegrationRegistry:

    def __init__(self):
        self._connectors = {}

    def register_connector(
        self,
        key,
        connector,
    ):
        self._connectors[key] = connector

        logger.info(
            "Registered connector [%s] - %s",
            key,
            connector.industry,
        )

    def get_connector(self, key):
        return self._connectors.get(key)

    def list_available_integrations(self):
        output = []

        for key, connector in self._connectors.items():
            test = connector.test_connection()

            output.append(
                {
                    "key": key,
                    "connector_id": connector.connector_id,
                    "industry": connector.industry,
                    "active": connector.is_active,
                    "status": test.get(
                        "status",
                        "UNKNOWN",
                    ),
                }
            )

        return output


partnerops_integrations = IntegrationRegistry()

partnerops_integrations.register_connector(
    "telecom_oss",
    TelecomOSSConnector(
        "telecom_oss",
        "Telecom / ISP / OSP",
        {},
    ),
)

partnerops_integrations.register_connector(
    "field_service",
    FieldServiceConnector(
        "field_service",
        "Field Service / Contractors",
        {
            "fsm_provider": "Generic FSM / Salesforce FSM",
        },
    ),
)

partnerops_integrations.register_connector(
    "fmcg_erp",
    FMCGDistributionConnector(
        "fmcg_erp",
        "Distribution / FMCG",
        {
            "erp_system": "SAP S/4HANA",
        },
    ),
)

partnerops_integrations.register_connector(
    "fintech_ops",
    FintechMerchantConnector(
        "fintech_ops",
        "Banking / Fintech / Agents",
        {
            "gateway": "ISO 20022 / Core Banking API",
        },
    ),
)

partnerops_integrations.register_connector(
    "utility_grid",
    UtilityGridConnector(
        "utility_grid",
        "Energy / Utilities",
        {},
    ),
)


# ============================================================
# 25. RECOVERY ACTION MANAGEMENT
# ============================================================

def create_intervention(
    industry,
    partner,
    action,
    owner,
    priority,
    target_outcome,
    baseline_kpi,
    expected_kpi,
    due_date,
    estimated_value,
):
    if not has_permission("actions"):
        return False

    db_execute(
        """
        INSERT INTO interventions
        (tenant_id, industry, partner, action, owner,
         status, priority, target_outcome, baseline_kpi,
         expected_kpi, due_date, estimated_value,
         created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            st.session_state.tenant_id,
            industry,
            partner,
            action,
            owner,
            "Open",
            priority,
            target_outcome,
            baseline_kpi,
            expected_kpi,
            due_date,
            estimated_value,
            st.session_state.username,
            utc_iso(),
        ),
    )

    audit(
        "RECOVERY_ACTION_CREATED",
        "intervention",
        partner,
        {
            "action": action,
            "owner": owner,
            "priority": priority,
            "estimated_value": estimated_value,
        },
    )

    return True


def update_intervention(
    action_id,
    status,
    actual_outcome,
    actual_value,
    update_note,
):
    rows = db_execute(
        """
        SELECT *
        FROM interventions
        WHERE action_id = ?
          AND tenant_id = ?
        """,
        (
            action_id,
            st.session_state.tenant_id,
        ),
        fetch=True,
    )

    if not rows:
        return False

    completed_at = (
        utc_iso()
        if status == "Completed"
        else None
    )

    db_execute(
        """
        UPDATE interventions
        SET status = ?,
            actual_outcome = ?,
            actual_value = ?,
            update_note = ?,
            completed_at = ?
        WHERE action_id = ?
          AND tenant_id = ?
        """,
        (
            status,
            actual_outcome,
            actual_value,
            update_note,
            completed_at,
            action_id,
            st.session_state.tenant_id,
        ),
    )

    audit(
        "RECOVERY_ACTION_UPDATED",
        "intervention",
        action_id,
        {
            "status": status,
            "actual_outcome": actual_outcome,
            "actual_value": actual_value,
        },
    )

    return True


def load_interventions(industry):
    rows = db_execute(
        """
        SELECT *
        FROM interventions
        WHERE tenant_id = ?
          AND industry = ?
        ORDER BY action_id DESC
        """,
        (
            st.session_state.tenant_id,
            industry,
        ),
        fetch=True,
    )

    return pd.DataFrame(
        [dict(r) for r in rows]
    )


# ============================================================
# 26. SIDEBAR / WORKSPACE
# ============================================================

tenant = get_tenant(
    st.session_state.tenant_id
)

st.sidebar.title("📡 PartnerOps")

st.sidebar.caption(
    f"Version {APP_VERSION}"
)

st.sidebar.write(
    f"**Tenant:** {tenant['tenant_name'] if tenant else 'Unknown'}"
)

st.sidebar.write(
    f"**Role:** {st.session_state.role}"
)

if st.session_state.access_mode == "customer":
    st.sidebar.success(
        "Customer workspace locked"
    )
    st.sidebar.caption(
        st.session_state.locked_industry
    )
else:
    st.sidebar.info(
        "Platform workspace"
    )


# Industry selection.
if st.session_state.access_mode == "customer":
    industry = st.session_state.locked_industry
else:
    entitled = [
        item
        for item in INDUSTRIES
        if tenant_industry_enabled(
            st.session_state.tenant_id,
            item,
        )
    ]

    if not entitled:
        st.error(
            "No industry entitlement configured."
        )
        st.stop()

    default_index = (
        entitled.index(
            st.session_state.current_industry
        )
        if st.session_state.current_industry in entitled
        else 0
    )

    industry = st.sidebar.selectbox(
        "Industry",
        entitled,
        index=default_index,
    )

st.session_state.current_industry = industry

if st.session_state.access_mode == "customer":
    page_options = [
        "Command Center",
        "Executive Intelligence",
        "Partners",
        "Partner Detail",
        "Partner Comparison",
        "Recovery Actions",
        "Predictive Risk",
        "Anomalies",
        "Benchmarking",
        "Trends",
        "Data Quality",
        "Commercial Value",
        "Customer Report",
        "Export",
    ]
else:
    page_options = [
        "Command Center",
        "Executive Intelligence",
        "Partners",
        "Partner Detail",
        "Partner Comparison",
        "Recovery Actions",
        "Predictive Risk",
        "Anomalies",
        "Benchmarking",
        "Trends",
        "Data Quality",
        "Commercial Value",
        "Customer Report",
        "Export",
        "Administration",
    ]

page = st.sidebar.radio(
    "Workspace",
    page_options,
)


if st.sidebar.button(
    "Log out",
    use_container_width=True,
):
    audit(
        "LOGOUT",
        "user",
        st.session_state.username,
    )

    for key in DEFAULT_STATE:
        st.session_state[key] = DEFAULT_STATE[key]
    try:
        st.query_params.clear()
    except Exception:
        pass

    st.rerun()


# ============================================================
# 26A. UNIVERSAL DATA INGESTION
# ============================================================

def _read_text_as_table(raw_bytes):
    text = raw_bytes.decode("utf-8-sig", errors="replace").strip()

    if not text:
        return pd.DataFrame()

    for sep in [None, ",", "\\t", ";", "|"]:
        try:
            if sep is None:
                candidate = pd.read_csv(
                    io.StringIO(text),
                    sep=None,
                    engine="python",
                )
            else:
                candidate = pd.read_csv(
                    io.StringIO(text),
                    sep=sep,
                )

            if len(candidate.columns) > 1 or len(candidate) > 1:
                return candidate

        except Exception:
            continue

    return pd.DataFrame(
        {"text": text.splitlines()}
    )


def _json_to_dataframe(raw_bytes):
    obj = json.loads(
        raw_bytes.decode(
            "utf-8-sig",
            errors="replace",
        )
    )

    if isinstance(obj, list):
        return pd.json_normalize(obj)

    if isinstance(obj, dict):
        for key in (
            "data",
            "records",
            "rows",
            "items",
            "results",
        ):
            value = obj.get(key)

            if isinstance(value, list):
                return pd.json_normalize(value)

        return pd.json_normalize(obj)

    raise ValueError(
        "JSON must contain an object or list of records."
    )


def _pdf_to_dataframe(raw_bytes):
    if pdfplumber is None:
        raise RuntimeError(
            "PDF support is not installed. "
            "Add pdfplumber to requirements.txt."
        )

    tables = []
    text_chunks = []

    with pdfplumber.open(io.BytesIO(raw_bytes)) as pdf:
        if len(pdf.pages) > MAX_PDF_PAGES:
            raise ValueError(f"PDF contains {len(pdf.pages)} pages; maximum supported is {MAX_PDF_PAGES}.")
        for page in pdf.pages:
            page_tables = page.extract_tables() or []

            for table in page_tables:
                if table and len(table) >= 2:
                    header = table[0]
                    rows = table[1:]

                    if header:
                        tables.append(
                            pd.DataFrame(
                                rows,
                                columns=header,
                            )
                        )

            page_text = page.extract_text() or ""

            if page_text.strip():
                text_chunks.append(page_text)

    if tables:
        return pd.concat(
            tables,
            ignore_index=True,
        )

    if text_chunks:
        return _read_text_as_table(
            "\n".join(text_chunks).encode("utf-8")
        )

    raise ValueError(
        "No extractable table/text was found in the PDF. "
        "Scanned PDFs may require OCR before upload."
    )


def _docx_to_dataframe(raw_bytes):
    if Document is None:
        raise RuntimeError(
            "DOCX support is not installed. "
            "Add python-docx to requirements.txt."
        )

    document = Document(
        io.BytesIO(raw_bytes)
    )

    tables = []

    for table in document.tables:
        rows = [
            [
                cell.text.strip()
                for cell in row.cells
            ]
            for row in table.rows
        ]

        if len(rows) >= 2 and rows[0]:
            tables.append(
                pd.DataFrame(
                    rows[1:],
                    columns=rows[0],
                )
            )

    if tables:
        return pd.concat(
            tables,
            ignore_index=True,
        )

    paragraphs = [
        p.text.strip()
        for p in document.paragraphs
        if p.text.strip()
    ]

    if paragraphs:
        return _read_text_as_table(
            "\n".join(paragraphs).encode("utf-8")
        )

    raise ValueError(
        "No readable table or text was found in the DOCX."
    )


def _image_to_dataframe(raw_bytes):
    if Image is None or pytesseract is None:
        raise RuntimeError(
            "Image OCR support is not installed. "
            "Add Pillow, pytesseract and the tesseract-ocr "
            "system package."
        )

    image = Image.open(
        io.BytesIO(raw_bytes)
    )

    text = pytesseract.image_to_string(
        image
    ).strip()

    if not text:
        raise ValueError(
            "OCR could not extract readable text from the image."
        )

    return _read_text_as_table(
        text.encode("utf-8")
    )


def _validate_upload_dataframe(df):
    if df is None or not isinstance(df, pd.DataFrame):
        raise ValueError("The uploaded content did not produce a valid dataset.")
    if df.empty:
        raise ValueError("The uploaded dataset contains no rows.")
    if len(df) > MAX_UPLOAD_ROWS:
        raise ValueError(f"Dataset has {len(df):,} rows; maximum is {MAX_UPLOAD_ROWS:,}.")
    if len(df.columns) > MAX_UPLOAD_COLUMNS:
        raise ValueError(f"Dataset has {len(df.columns):,} columns; maximum is {MAX_UPLOAD_COLUMNS:,}.")
    if len(df) * max(1, len(df.columns)) > MAX_UPLOAD_CELLS:
        raise ValueError("Dataset exceeds the configured cell-processing limit.")
    return df


def _validate_archive(raw_bytes, label):
    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ZIP_MEMBERS:
                raise ValueError(f"{label} contains too many archive members.")
            total = sum(max(0, int(i.file_size)) for i in infos)
            if total > MAX_ZIP_UNCOMPRESSED_BYTES:
                raise ValueError(f"{label} expands beyond the safe processing limit.")
            for info in infos:
                if info.file_size > MAX_ZIP_UNCOMPRESSED_BYTES:
                    raise ValueError(f"{label} contains an oversized archive member.")
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Invalid {label} archive.") from exc


def _validate_file_signature(ext, raw):
    signatures = {
        "pdf": raw.startswith(b"%PDF"),
        "png": raw.startswith(b"\x89PNG\r\n\x1a\n"),
        "jpg": raw.startswith(b"\xff\xd8\xff"),
        "jpeg": raw.startswith(b"\xff\xd8\xff"),
        "xlsx": raw.startswith(b"PK"),
        "docx": raw.startswith(b"PK"),
        "xls": raw.startswith(b"\xd0\xcf\x11\xe0"),
    }
    if ext in signatures and not signatures[ext]:
        raise ValueError("The file content does not match its extension.")


def read_partnerops_upload(upload):
    """Safely convert a supported upload into a bounded DataFrame."""
    if upload is None:
        raise ValueError("No file was supplied.")

    size = getattr(upload, "size", None)
    if size is not None and size > MAX_UPLOAD_BYTES:
        raise ValueError(f"File is too large. Maximum supported upload is {MAX_UPLOAD_MB} MB.")

    name = str(getattr(upload, "name", "upload")).strip()
    ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
    if ext not in SUPPORTED_UPLOAD_TYPES:
        raise ValueError("Unsupported file type. Supported formats: " + ", ".join(SUPPORTED_UPLOAD_TYPES))

    raw = upload.getvalue()
    if not raw:
        raise ValueError("The uploaded file is empty.")

    _validate_file_signature(ext, raw)
    if ext in {"xlsx", "docx"}:
        _validate_archive(raw, ext.upper())

    if ext == "csv":
        result = pd.read_csv(io.BytesIO(raw), low_memory=False)
    elif ext in {"xlsx", "xls"}:
        if ext == "xlsx":
            workbook = pd.ExcelFile(io.BytesIO(raw))
            if len(workbook.sheet_names) > 100:
                raise ValueError("Workbook contains too many worksheets.")
            best_df = None
            best_score = None
            for sheet in workbook.sheet_names:
                sheet_df = pd.read_excel(workbook, sheet_name=sheet)
                if sheet_df is None or sheet_df.dropna(how="all").empty:
                    continue
                if len(sheet_df) > MAX_UPLOAD_ROWS or len(sheet_df.columns) > MAX_UPLOAD_COLUMNS:
                    continue
                normalized_sheet = normalize_dataframe(sheet_df)
                mapped = sum(1 for col in COLUMN_ALIASES if col in normalized_sheet.columns)
                rows = len(normalized_sheet)
                partner_bonus = 4 if "partner" in normalized_sheet.columns else 0
                primary_bonus = 4 if "output" in normalized_sheet.columns else 0
                score = mapped * 10 + partner_bonus + primary_bonus + min(rows, 100) / 100
                if best_score is None or score > best_score:
                    best_score, best_df = score, sheet_df
            if best_df is None:
                raise ValueError("The Excel workbook contains no usable operational-data worksheet within safety limits.")
            result = best_df
        else:
            result = pd.read_excel(io.BytesIO(raw))
    elif ext == "json":
        result = _json_to_dataframe(raw)
    elif ext == "txt":
        result = _read_text_as_table(raw)
    elif ext == "pdf":
        result = _pdf_to_dataframe(raw)
    elif ext == "docx":
        result = _docx_to_dataframe(raw)
    elif ext in {"png", "jpg", "jpeg"}:
        if Image is None:
            raise RuntimeError("Image support is not installed.")
        with Image.open(io.BytesIO(raw)) as image:
            width, height = image.size
            if width * height > MAX_IMAGE_PIXELS:
                raise ValueError("Image dimensions exceed the safe OCR limit.")
        result = _image_to_dataframe(raw)
    else:
        raise ValueError("Unable to process the uploaded file.")

    return _validate_upload_dataframe(result)


def ingestion_summary(
    raw_df,
    normalized_df,
    filename,
):
    return {
        "filename": filename,
        "source_rows": int(len(raw_df)),
        "source_columns": int(
            len(raw_df.columns)
        ),
        "mapped_columns": int(
            len(normalized_df.columns)
        ),
        "mapped_fields": [
            c for c in COLUMN_ALIASES
            if c in normalized_df.columns
        ],
    }


# ============================================================
# 27. LOAD + PROCESS DATA
# ============================================================

raw_df = get_current_data(
    industry
)

quality = quality_check(
    raw_df,
    industry,
)

if quality["status"] == "BLOCKED":
    st.error(
        "Data-quality gate is blocking intelligence."
    )

    for issue in quality["issues"]:
        st.error(issue)

    if has_permission("upload"):
        upload = st.file_uploader(
            "Upload operational data",
            type=SUPPORTED_UPLOAD_TYPES,
            help=(
                f"CSV, Excel, JSON, TXT, PDF, DOCX, PNG or JPG. "
                f"Maximum {MAX_UPLOAD_MB} MB."
            ),
        )

        if upload:
            try:
                uploaded_df = read_partnerops_upload(upload)
                normalized = normalize_dataframe(uploaded_df)
                q = quality_check(
                    normalized,
                    industry,
                )

                st.caption(
                    f"Detected: {upload.name} · "
                    f"{len(uploaded_df):,} source row(s) · "
                    f"{len(normalized.columns):,} normalized column(s)"
                )

                st.dataframe(
                    normalized.head(20),
                    use_container_width=True,
                )

                if q["status"] != "BLOCKED":
                    if st.button(
                        "Accept Dataset",
                        key="blocked_upload_accept",
                    ):
                        ok, q2 = set_current_data(
                            uploaded_df,
                            industry,
                            upload.name,
                        )

                        if ok:
                            st.success(
                                "Dataset accepted and saved."
                            )
                            st.rerun()
                        else:
                            st.error(
                                "Dataset rejected by quality gate."
                            )
                            for issue in q2["issues"]:
                                st.error(issue)
                else:
                    st.error(
                        "Dataset rejected by quality gate."
                    )

                    for issue in q["issues"]:
                        st.error(issue)

            except Exception as exc:
                st.error(
                    f"Upload failed: {exc}"
                )

    st.stop()


performance_df = performance_engine(
    raw_df,
    industry,
)

predictive_df = predictive_risk(
    performance_df,
    industry,
)

anomalies_df = anomaly_analysis(
    performance_df,
    industry,
)

save_snapshot(
    performance_df,
    industry,
    st.session_state.tenant_id,
)


# ============================================================
# 28. COMMAND CENTER
# ============================================================

if page == "Command Center":

    st.title("🎯 PartnerOps Command Center")

    st.caption(
        "Operational control layer for identifying performance gaps "
        "and converting them into recovery actions."
    )

    total_partners = len(
        performance_df
    )

    avg_health = pd.to_numeric(
        performance_df["performance_score"],
        errors="coerce",
    ).mean()
    avg_health = 0.0 if pd.isna(avg_health) else round(float(avg_health), 1)

    target = INDUSTRIES[
        industry
    ]["target"]

    below_target = int(
        (
            performance_df[
                "performance_score"
            ] < target
        ).sum()
    )

    at_risk = int(
        performance_df[
            "risk"
        ].isin(
            ["Critical", "High"]
        ).sum()
    )

    recovery = pd.to_numeric(
        performance_df["recovery_opportunity"],
        errors="coerce",
    ).fillna(0).sum()
    recovery = round(float(recovery), 2)

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric(
        "Partners",
        total_partners,
    )

    c2.metric(
        "Average Health",
        f"{avg_health}%",
    )

    c3.metric(
        "Below Target",
        below_target,
    )

    c4.metric(
        "At Risk",
        at_risk,
    )

    c5.metric(
        "Recovery Opportunity",
        f"{recovery:,.0f} units",
    )

    st.divider()

    st.subheader(
        "Priority Recovery Queue"
    )

    queue = performance_df[
        performance_df["attention_required"]
    ][
        [
            "partner",
            "performance_score",
            "band",
            "risk",
            "priority",
            "target_gap",
            "recovery_opportunity",
            "recommended_action",
        ]
    ].copy()

    st.dataframe(
        queue,
        use_container_width=True,
        hide_index=True,
    )

    st.subheader(
        "Risk Distribution"
    )

    risk_counts = (
        performance_df[
            "risk"
        ]
        .value_counts()
        .rename_axis("Risk")
        .reset_index(name="Partners")
    )

    st.bar_chart(
        risk_counts.set_index("Risk")
    )


# ============================================================
# 29. EXECUTIVE INTELLIGENCE
# ============================================================

elif page == "Executive Intelligence":

    st.title("🧠 Executive Intelligence")

    st.write(
        "PartnerOps converts operational data into management decisions."
    )

    top = performance_df[
        [
            "rank",
            "partner",
            "performance_score",
            "band",
            "risk",
            "target_gap",
            "recovery_opportunity",
            "recommended_action",
        ]
    ]

    st.dataframe(
        top,
        use_container_width=True,
        hide_index=True,
    )

    strongest = performance_df.iloc[0]

    weakest = performance_df.iloc[-1]

    st.success(
        f"Strongest partner: **{strongest['partner']}** "
        f"({strongest['performance_score']:.1f}%)"
    )

    st.error(
        f"Highest priority partner: **{weakest['partner']}** "
        f"({weakest['performance_score']:.1f}%)"
    )

    total_recovery = performance_df[
        "recovery_opportunity"
    ].sum()

    st.metric(
        "Portfolio recovery opportunity",
        f"{total_recovery:,.0f} units",
    )


# ============================================================
# 30. PARTNERS
# ============================================================

elif page == "Partners":

    st.title("👥 Partner Portfolio")

    search = st.text_input(
        "Search partner"
    ).strip().lower()

    view = performance_df.copy()

    if search:
        view = view[
            view["partner"]
            .astype(str)
            .str.lower()
            .str.contains(
                search,
                na=False,
            )
        ]

    columns = [
        "partner",
        "performance_score",
        "band",
        "risk",
        "priority",
        "target_gap",
        "recovery_opportunity",
    ]

    st.dataframe(
        view[columns],
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# 31. PARTNER DETAIL
# ============================================================

elif page == "Partner Detail":

    st.title("🔎 Partner Detail")

    partners = (
        performance_df[
            "partner"
        ]
        .astype(str)
        .tolist()
    )

    selected = st.selectbox(
        "Select partner",
        partners,
    )

    row = performance_df[
        performance_df["partner"] == selected
    ].iloc[0]

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Health",
        f"{row['performance_score']:.1f}%",
    )

    c2.metric(
        "Band",
        row["band"],
    )

    c3.metric(
        "Risk",
        row["risk"],
    )

    target_gap = row["target_gap"]

    c4.metric(
        "Target Gap",
        "N/A" if pd.isna(target_gap) else f"{float(target_gap):.1f}",
    )

    st.subheader("Diagnosis")

    st.info(
        row["diagnosis"]
    )

    st.subheader("Recommended Recovery Action")

    st.warning(
        row["recommended_action"]
    )

    st.subheader("Partner Metrics")

    detail = pd.DataFrame(
        {
            "Metric": [
                c
                for c in performance_df.columns
                if c not in [
                    "partner",
                    "diagnosis",
                    "recommended_action",
                ]
            ],
            "Value": [
                row[c]
                for c in performance_df.columns
                if c not in [
                    "partner",
                    "diagnosis",
                    "recommended_action",
                ]
            ],
        }
    )

    st.dataframe(
        detail,
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# 32. PARTNER COMPARISON
# ============================================================

elif page == "Partner Comparison":

    st.title("⚖️ Partner Comparison")

    partners = (
        performance_df[
            "partner"
        ]
        .astype(str)
        .tolist()
    )

    selected = st.multiselect(
        "Choose partners",
        partners,
        default=partners[:2],
    )

    if selected:
        comparison = performance_df[
            performance_df[
                "partner"
            ].isin(selected)
        ]

        st.dataframe(
            comparison,
            use_container_width=True,
            hide_index=True,
        )

        if "performance_score" in comparison:
            st.bar_chart(
                comparison.set_index(
                    "partner"
                )["performance_score"]
            )


# ============================================================
# 33. RECOVERY ACTIONS
# ============================================================

elif page == "Recovery Actions":

    st.title("🛠️ Recovery Action Management")

    if not has_permission("actions"):
        st.warning(
            "Your role is view-only for recovery actions."
        )
    else:

        st.subheader(
            "Create Recovery Action"
        )

        partners = (
            performance_df[
                "partner"
            ]
            .astype(str)
            .tolist()
        )

        with st.form("create_action"):

            partner = st.selectbox(
                "Partner",
                partners,
            )

            action = st.text_area(
                "Recovery action",
                value=(
                    performance_df[
                        performance_df["partner"] == partner
                    ].iloc[0]["recommended_action"]
                ),
            )

            owner = st.text_input(
                "Owner"
            )

            priority = st.selectbox(
                "Priority",
                ["P1", "P2", "P3", "P4"],
            )

            target_outcome = st.text_input(
                "Target outcome"
            )

            row = performance_df[
                performance_df["partner"] == partner
            ].iloc[0]

            baseline = float(
                row[
                    INDUSTRIES[
                        industry
                    ]["primary_kpi"]
                ]
            ) if (
                INDUSTRIES[industry]["primary_kpi"]
                in row.index
                and pd.notna(
                    row[
                        INDUSTRIES[
                            industry
                        ]["primary_kpi"]
                    ]
                )
            ) else 0

            expected = st.number_input(
                "Expected KPI",
                min_value=0.0,
                value=float(
                    INDUSTRIES[
                        industry
                    ]["target"]
                ),
            )

            due_date = st.date_input(
                "Due date",
                value=date.today()
                + timedelta(days=7),
            )

            estimated_value = st.number_input(
                "Estimated commercial value (KSh)",
                min_value=0.0,
                value=0.0,
            )

            submitted = st.form_submit_button(
                "Create Recovery Action",
                use_container_width=True,
            )

            if submitted:

                create_intervention(
                    industry,
                    partner,
                    action,
                    owner,
                    priority,
                    target_outcome,
                    baseline,
                    expected,
                    due_date.isoformat(),
                    estimated_value,
                )

                st.success(
                    "Recovery action created."
                )

                st.rerun()

    st.divider()

    actions = load_interventions(
        industry
    )

    if actions.empty:
        st.info(
            "No recovery actions have been created."
        )
    else:

        st.subheader(
            "Recovery Pipeline"
        )

        st.dataframe(
            actions,
            use_container_width=True,
            hide_index=True,
        )

        if has_permission("actions"):

            st.subheader(
                "Update Action"
            )

            action_ids = actions[
                "action_id"
            ].tolist()

            action_id = st.selectbox(
                "Action ID",
                action_ids,
            )

            selected_action = actions[
                actions["action_id"] == action_id
            ].iloc[0]

            with st.form(
                "update_action"
            ):

                status = st.selectbox(
                    "Status",
                    [
                        "Open",
                        "In Progress",
                        "Blocked",
                        "Completed",
                        "Cancelled",
                    ],
                    index=[
                        "Open",
                        "In Progress",
                        "Blocked",
                        "Completed",
                        "Cancelled",
                    ].index(
                        selected_action["status"]
                    ),
                )

                actual_outcome = st.number_input(
                    "Actual KPI outcome",
                    value=float(
                        selected_action[
                            "actual_outcome"
                        ]
                    )
                    if pd.notna(
                        selected_action[
                            "actual_outcome"
                        ]
                    )
                    else 0.0,
                )

                actual_value = st.number_input(
                    "Actual recovered value (KSh)",
                    value=float(
                        selected_action[
                            "actual_value"
                        ]
                    )
                    if pd.notna(
                        selected_action[
                            "actual_value"
                        ]
                    )
                    else 0.0,
                )

                note = st.text_area(
                    "Update note",
                    value=(
                        selected_action[
                            "update_note"
                        ]
                        or ""
                    ),
                )

                submit_update = st.form_submit_button(
                    "Update Recovery Action",
                    use_container_width=True,
                )

                if submit_update:
                    update_intervention(
                        action_id,
                        status,
                        actual_outcome,
                        actual_value,
                        note,
                    )

                    st.success(
                        "Recovery action updated."
                    )

                    st.rerun()


# ============================================================
# 34. PREDICTIVE RISK
# ============================================================

elif page == "Predictive Risk":

    st.title("🔮 Predictive Risk")

    st.caption(
        "Rule-based leading-indicator risk model. "
        "This is predictive decision support, not a claim of an AI model."
    )

    columns = [
        "partner",
        "performance_score",
        "predictive_risk_score",
        "predicted_risk",
        "risk_drivers",
    ]

    st.dataframe(
        predictive_df[
            columns
        ],
        use_container_width=True,
        hide_index=True,
    )

    st.bar_chart(
        predictive_df.set_index(
            "partner"
        )["predictive_risk_score"]
    )


# ============================================================
# 35. ANOMALIES
# ============================================================

elif page == "Anomalies":

    st.title("🚨 Anomaly / Drift Detection")

    if anomalies_df.empty:
        st.success(
            "No major statistical anomalies detected."
        )
    else:
        st.warning(
            f"{len(anomalies_df)} anomaly/anomalies detected."
        )

        st.dataframe(
            anomalies_df,
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# 36. BENCHMARKING
# ============================================================

elif page == "Benchmarking":

    st.title("📏 Benchmarking")

    primary = INDUSTRIES[
        industry
    ]["primary_kpi"]

    portfolio_average = performance_df[
        "performance_score"
    ].mean()

    median = performance_df[
        "performance_score"
    ].median()

    best = performance_df[
        "performance_score"
    ].max()

    weakest = performance_df[
        "performance_score"
    ].min()

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Portfolio Average",
        f"{portfolio_average:.1f}%",
    )

    c2.metric(
        "Median",
        f"{median:.1f}%",
    )

    c3.metric(
        "Best",
        f"{best:.1f}%",
    )

    c4.metric(
        "Weakest",
        f"{weakest:.1f}%",
    )

    benchmark = performance_df[
        [
            "partner",
            "performance_score",
            "band",
            "risk",
        ]
    ].copy()

    benchmark["relative_to_average"] = (
        benchmark["performance_score"]
        - portfolio_average
    ).round(2)

    st.dataframe(
        benchmark,
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# 37. TRENDS
# ============================================================

elif page == "Trends":

    st.title("📈 Trends")

    trend, direction = trend_analysis(
        raw_df,
        industry,
    )

    if trend is None:
        st.info(direction)
    else:

        st.metric(
            "Portfolio Direction",
            direction,
        )

        st.line_chart(
            trend.set_index("date")
        )

        st.dataframe(
            trend,
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# 38. DATA QUALITY
# ============================================================

elif page == "Data Quality":

    st.title("✅ Data Quality Control")

    status = quality_check(
        raw_df,
        industry,
    )

    if status["status"] == "GOOD":
        st.success(
            "Dataset passed the data-quality gate."
        )
    elif status["status"] == "REVIEW":
        st.warning(
            "Dataset is usable. Review the warnings before relying on all intelligence outputs."
        )
    else:
        st.error(
            "Dataset is blocked."
        )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Status",
        status["status"],
    )

    c2.metric(
        "Rows",
        status["rows"],
    )

    c3.metric(
        "Columns",
        status["columns"],
    )

    c4.metric(
        "Duplicates",
        status["duplicates"],
    )

    if status["issues"]:
        st.subheader("Issues requiring attention")

        for issue in status["issues"]:
            st.error(issue)

    if status["warnings"]:
        st.subheader("Warnings")

        for warning in status["warnings"]:
            st.warning(warning)

    if has_permission("upload"):

        st.divider()

        st.subheader(
            "Upload New Dataset"
        )

        upload = st.file_uploader(
            "Upload New Dataset",
            type=SUPPORTED_UPLOAD_TYPES,
            help=(
                f"CSV, Excel, JSON, TXT, PDF, DOCX, PNG or JPG. "
                f"Maximum {MAX_UPLOAD_MB} MB."
            ),
        )

        if upload:
            try:
                uploaded_df = read_partnerops_upload(upload)
                normalized = normalize_dataframe(uploaded_df)
                q = quality_check(
                    normalized,
                    industry,
                )

                summary = ingestion_summary(
                    uploaded_df,
                    normalized,
                    upload.name,
                )

                st.write(
                    f"Quality status: **{q['status']}**"
                )
                st.caption(
                    f"{summary['filename']} · "
                    f"{summary['source_rows']:,} source row(s) · "
                    f"{summary['mapped_columns']:,} normalized column(s)"
                )

                st.dataframe(
                    normalized.head(20),
                    use_container_width=True,
                )

                if q["status"] != "BLOCKED":
                    if st.button(
                        "Accept Dataset",
                        use_container_width=True,
                        key="accept_dataset_quality",
                    ):
                        ok, q2 = set_current_data(
                            uploaded_df,
                            industry,
                            upload.name,
                        )

                        if ok:
                            st.success(
                                "Dataset accepted and loaded."
                            )
                            st.rerun()
                        else:
                            st.error(
                                "Dataset rejected by quality gate."
                            )
                            for issue in q2["issues"]:
                                st.error(issue)
                else:
                    for issue in q["issues"]:
                        st.error(issue)

            except Exception as exc:
                st.error(
                    f"Unable to read dataset: {exc}"
                )


    st.subheader(
        "Data Preview"
    )

    st.dataframe(
        raw_df.head(100),
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# 39. COMMERCIAL VALUE
# ============================================================

elif page == "Commercial Value":

    st.title("💰 Commercial Recovery Value")

    st.write(
        "Translate operational improvement into a monetary recovery opportunity."
    )

    value_per_unit = st.number_input(
        "Value per recovered unit (KSh)",
        min_value=0.0,
        value=100.0,
        step=10.0,
    )

    value_df = commercial_value(
        performance_df,
        value_per_unit,
    )

    total_value = value_df[
        "estimated_value_ksh"
    ].sum()

    total_units = value_df[
        "recovery_opportunity"
    ].sum()

    c1, c2 = st.columns(2)

    c1.metric(
        "Recovery Units",
        f"{total_units:,.0f}",
    )

    c2.metric(
        "Estimated Commercial Value",
        f"KSh {total_value:,.0f}",
    )

    st.divider()

    st.dataframe(
        value_df[
            [
                "partner",
                "performance_score",
                "target_gap",
                "recovery_opportunity",
                "estimated_value_ksh",
                "priority",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# 40. CUSTOMER REPORT
# ============================================================

elif page == "Customer Report":

    st.title("📑 Customer Executive Report")

    tenant_name = (
        tenant["tenant_name"]
        if tenant
        else st.session_state.tenant_id
    )

    st.header(
        f"{tenant_name} — Partner Performance"
    )

    st.write(
        f"Industry: **{industry}**"
    )

    st.write(
        f"Report generated: **{utc_now().strftime('%Y-%m-%d %H:%M UTC')}**"
    )

    st.divider()

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "Partners",
        len(performance_df),
    )

    c2.metric(
        "Average Health",
        f"{performance_df['performance_score'].mean():.1f}%",
    )

    c3.metric(
        "Recovery Opportunity",
        f"{performance_df['recovery_opportunity'].sum():,.0f}",
    )

    st.subheader(
        "Management Summary"
    )

    below = performance_df[
        performance_df["attention_required"]
    ]

    if below.empty:
        st.success(
            "Portfolio is currently meeting the configured target."
        )
    else:
        st.warning(
            f"{len(below)} partner(s) require attention."
        )

    st.subheader(
        "Performance Table"
    )

    st.dataframe(
        performance_df[
            [
                "rank",
                "partner",
                "performance_score",
                "band",
                "risk",
                "priority",
                "target_gap",
                "recovery_opportunity",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# 41. EXPORT
# ============================================================

elif page == "Export":

    st.title("📤 Export")

    if not has_permission("export"):
        st.warning(
            "Your role does not have export permission."
        )
    else:

        actions = load_interventions(
            industry
        )

        value_df = commercial_value(
            performance_df,
            100,
        )

        output = io.BytesIO()

        with pd.ExcelWriter(
            output,
            engine="openpyxl",
        ) as writer:

            performance_df.to_excel(
                writer,
                sheet_name="Performance",
                index=False,
            )

            pd.DataFrame(
                [quality]
            ).to_excel(
                writer,
                sheet_name="Data Quality",
                index=False,
            )

            actions.to_excel(
                writer,
                sheet_name="Recovery Actions",
                index=False,
            )

            predictive_df.to_excel(
                writer,
                sheet_name="Predictive Risk",
                index=False,
            )

            anomalies_df.to_excel(
                writer,
                sheet_name="Anomalies",
                index=False,
            )

            value_df.to_excel(
                writer,
                sheet_name="Commercial Value",
                index=False,
            )

        output.seek(0)

        st.download_button(
            "Download PartnerOps Excel Report",
            data=output.getvalue(),
            file_name=(
                f"PartnerOps_{industry.replace('/', '_')}_"
                f"{utc_now().strftime('%Y%m%d_%H%M')}.xlsx"
            ),
            mime=(
                "application/vnd.openxmlformats-officedocument."
                "spreadsheetml.sheet"
            ),
            use_container_width=True,
        )


# ============================================================
# 42. ADMINISTRATION
# ============================================================

elif page == "Administration":

    if not has_permission("platform_admin"):
        st.error(
            "Administrator access required."
        )
        st.stop()

    st.title("⚙️ PartnerOps Administration")

    tabs = st.tabs(
        [
            "Customers",
            "Entitlements",
            "Access Links",
            "Users",
            "Snapshots",
            "Audit Log",
            "Integrations",
            "System",
        ]
    )

    # --------------------------------------------------------
    # CUSTOMERS
    # --------------------------------------------------------

    with tabs[0]:

        st.subheader(
            "Customer / Tenant Management"
        )

        tenants = db_execute(
            """
            SELECT *
            FROM tenants
            ORDER BY tenant_name
            """,
            fetch=True,
        )

        tenant_df = pd.DataFrame(
            [dict(r) for r in tenants]
        )

        st.dataframe(
            tenant_df,
            use_container_width=True,
            hide_index=True,
        )

        st.subheader(
            "Create Customer"
        )

        with st.form(
            "create_customer"
        ):

            tenant_id = st.text_input(
                "Tenant ID"
            )

            tenant_name = st.text_input(
                "Customer name"
            )

            plan = st.selectbox(
                "Plan",
                [
                    "pilot",
                    "commercial",
                    "enterprise",
                ],
            )

            submit = st.form_submit_button(
                "Create Customer",
                use_container_width=True,
            )

            if submit:

                tenant_id = tenant_id.strip()

                if not tenant_id or not tenant_name:
                    st.error(
                        "Tenant ID and name are required."
                    )

                elif tenant_exists(tenant_id):
                    st.error(
                        "Tenant already exists."
                    )

                else:

                    db_execute(
                        """
                        INSERT INTO tenants
                        (tenant_id, tenant_name, plan,
                         status, created_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            tenant_id,
                            tenant_name,
                            plan,
                            "active",
                            utc_iso(),
                        ),
                    )

                    audit(
                        "TENANT_CREATED",
                        "tenant",
                        tenant_id,
                        {
                            "tenant_name": tenant_name,
                            "plan": plan,
                        },
                    )

                    st.success(
                        "Customer created."
                    )

                    st.rerun()

    # --------------------------------------------------------
    # ENTITLEMENTS
    # --------------------------------------------------------

    with tabs[1]:

        st.subheader(
            "Industry Entitlements"
        )

        tenants = db_execute(
            """
            SELECT tenant_id, tenant_name
            FROM tenants
            ORDER BY tenant_name
            """,
            fetch=True,
        )

        tenant_choices = {
            row["tenant_name"]:
            row["tenant_id"]
            for row in tenants
        }

        if tenant_choices:

            selected_name = st.selectbox(
                "Customer",
                list(
                    tenant_choices.keys()
                ),
            )

            selected_tenant = tenant_choices[
                selected_name
            ]

            for industry_name in INDUSTRIES:

                enabled = tenant_industry_enabled(
                    selected_tenant,
                    industry_name,
                )

                new_value = st.checkbox(
                    industry_name,
                    value=enabled,
                    key=(
                        f"entitlement_"
                        f"{selected_tenant}_"
                        f"{industry_name}"
                    ),
                )

                if new_value != enabled:

                    db_execute(
                        """
                        INSERT INTO entitlements
                        (tenant_id, industry, enabled)
                        VALUES (?, ?, ?)
                        ON CONFLICT(tenant_id, industry)
                        DO UPDATE SET enabled = excluded.enabled
                        """,
                        (
                            selected_tenant,
                            industry_name,
                            int(new_value),
                        ),
                    )

                    audit(
                        "ENTITLEMENT_CHANGED",
                        "tenant",
                        selected_tenant,
                        {
                            "industry": industry_name,
                            "enabled": new_value,
                        },
                    )

    # --------------------------------------------------------
    # ACCESS LINKS
    # --------------------------------------------------------

    with tabs[2]:

        st.subheader(
            "Customer Access Links"
        )

        tenants = db_execute(
            """
            SELECT tenant_id, tenant_name
            FROM tenants
            ORDER BY tenant_name
            """,
            fetch=True,
        )

        choices = {
            row["tenant_name"]:
            row["tenant_id"]
            for row in tenants
        }

        if choices:

            name = st.selectbox(
                "Customer",
                list(choices.keys()),
                key="link_customer",
            )

            link_tenant = choices[name]

            industries = [
                i for i in INDUSTRIES
                if tenant_industry_enabled(
                    link_tenant,
                    i,
                )
            ]

            if industries:

                link_industry = st.selectbox(
                    "Industry",
                    industries,
                )

                days = st.number_input(
                    "Validity (days)",
                    min_value=1,
                    max_value=90,
                    value=7,
                )

                c1, c2 = st.columns(2)

                with c1:
                    if st.button(
                        "Generate Access Link",
                        use_container_width=True,
                    ):

                        link = create_access_link(
                            link_tenant,
                            link_industry,
                            days,
                        )

                        st.session_state.generated_link = link

                        st.success(
                            "Access link generated."
                        )

                with c2:
                    if st.button(
                        "Rotate Existing Links",
                        use_container_width=True,
                    ):

                        rotate_customer_links(
                            link_tenant,
                            link_industry,
                        )

                        st.success(
                            "Existing links invalidated."
                        )

                if st.session_state.generated_link:

                    st.code(
                        st.session_state.generated_link,
                        language="text",
                    )

                    st.warning(
                        "Treat customer access links as credentials. "
                        "Do not publish them publicly."
                    )

            else:
                st.warning(
                    "Customer has no enabled industries."
                )

        st.subheader(
            "Active Access Links"
        )

        rows = db_execute(
            """
            SELECT
                link_id,
                tenant_id,
                industry,
                expires_at,
                active,
                created_at,
                created_by,
                revoked_at,
                last_seen_at,
                use_count
            FROM access_links
            ORDER BY link_id DESC
            """,
            fetch=True,
        )

        st.dataframe(
            pd.DataFrame(
                [dict(r) for r in rows]
            ),
            use_container_width=True,
            hide_index=True,
        )

    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    with tabs[3]:

        st.subheader(
            "Customer Users"
        )

        users = db_execute(
            """
            SELECT
                user_id,
                tenant_id,
                username,
                role,
                status,
                failed_attempts,
                locked_until,
                created_at
            FROM users
            ORDER BY user_id DESC
            """,
            fetch=True,
        )

        st.dataframe(
            pd.DataFrame(
                [dict(r) for r in users]
            ),
            use_container_width=True,
            hide_index=True,
        )

        st.subheader(
            "Create User"
        )

        with st.form(
            "create_user"
        ):

            tenants = db_execute(
                """
                SELECT tenant_id, tenant_name
                FROM tenants
                ORDER BY tenant_name
                """,
                fetch=True,
            )

            user_choices = {
                r["tenant_name"]:
                r["tenant_id"]
                for r in tenants
            }

            if user_choices:

                selected_customer = st.selectbox(
                    "Customer",
                    list(
                        user_choices.keys()
                    ),
                )

                new_tenant = user_choices[
                    selected_customer
                ]

                new_username = st.text_input(
                    "Username"
                )

                new_password = st.text_input(
                    "Temporary password",
                    type="password",
                )

                new_role = st.selectbox(
                    "Role",
                    [
                        "Manager",
                        "Analyst",
                        "Viewer",
                    ],
                )

                create = st.form_submit_button(
                    "Create User",
                    use_container_width=True,
                )

                if create:

                    if not new_username or not new_password:
                        st.error(
                            "Username and password required."
                        )
                    elif len(new_password) < 8:
                        st.error(
                            "Password should be at least 8 characters."
                        )
                    else:

                        password_hash, password_salt = (
                            hash_password(
                                new_password
                            )
                        )

                        try:

                            db_execute(
                                """
                                INSERT INTO users
                                (tenant_id, username,
                                 password_hash, password_salt,
                                 role, status, created_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    new_tenant,
                                    new_username,
                                    password_hash,
                                    password_salt,
                                    new_role,
                                    "active",
                                    utc_iso(),
                                ),
                            )

                            audit(
                                "USER_CREATED",
                                "user",
                                new_username,
                                {
                                    "role": new_role,
                                    "tenant_id": new_tenant,
                                },
                            )

                            st.success(
                                "User created."
                            )

                            st.rerun()

                        except sqlite3.IntegrityError:
                            st.error(
                                "Username already exists for this customer."
                            )

    # --------------------------------------------------------
    # SNAPSHOTS
    # --------------------------------------------------------

    with tabs[4]:

        st.subheader(
            "Performance History / Snapshots"
        )

        rows = db_execute(
            """
            SELECT *
            FROM snapshots
            WHERE tenant_id = ?
            ORDER BY snapshot_id DESC
            LIMIT 1000
            """,
            (
                st.session_state.tenant_id,
            ),
            fetch=True,
        )

        snapshot_df = pd.DataFrame(
            [dict(r) for r in rows]
        )

        if snapshot_df.empty:
            st.info(
                "No snapshots available."
            )
        else:
            st.dataframe(
                snapshot_df,
                use_container_width=True,
                hide_index=True,
            )

    # --------------------------------------------------------
    # AUDIT LOG
    # --------------------------------------------------------

    with tabs[5]:

        st.subheader(
            "Security / Audit Log"
        )

        rows = db_execute(
            """
            SELECT *
            FROM audit_log
            WHERE tenant_id = ?
            ORDER BY audit_id DESC
            LIMIT 1000
            """,
            (
                st.session_state.tenant_id,
            ),
            fetch=True,
        )

        audit_df = pd.DataFrame(
            [dict(r) for r in rows]
        )

        if audit_df.empty:
            st.info(
                "No audit events."
            )
        else:
            st.dataframe(
                audit_df,
                use_container_width=True,
                hide_index=True,
            )

    # --------------------------------------------------------
    # INTEGRATIONS
    # --------------------------------------------------------

    with tabs[6]:

        st.subheader(
            "Integration Architecture"
        )

        st.info(
            "PartnerOps is integration-ready. "
            "The connectors below are intentionally not represented "
            "as live external connections until configured."
        )

        integrations = pd.DataFrame(
            partnerops_integrations.list_available_integrations()
        )

        st.dataframe(
            integrations,
            use_container_width=True,
            hide_index=True,
        )

        selected_connector = st.selectbox(
            "Integration",
            list(
                partnerops_integrations._connectors.keys()
            ),
        )

        connector = (
            partnerops_integrations
            .get_connector(
                selected_connector
            )
        )

        if st.button(
            "Test Integration Configuration",
            use_container_width=True,
        ):

            result = connector.test_connection()

            audit(
                "INTEGRATION_TEST",
                "connector",
                selected_connector,
                result,
            )

            st.json(result)

        st.divider()

        st.subheader(
            "Human-in-the-Loop Control"
        )

        st.write(
            "External recovery actions are not dispatched automatically. "
            "The connector requires an explicit human approval flag."
        )

    # --------------------------------------------------------
    # SYSTEM
    # --------------------------------------------------------

    with tabs[7]:

        st.subheader(
            "Platform Configuration"
        )

        config_table = pd.DataFrame(
            [
                {
                    "Control": "Application",
                    "Value": PLATFORM_NAME,
                },
                {
                    "Control": "Version",
                    "Value": APP_VERSION,
                },
                {
                    "Control": "Database",
                    "Value": DB_FILE,
                },
                {
                    "Control": "Production Mode",
                    "Value": PRODUCTION_MODE,
                },
                {
                    "Control": "Base URL Configured",
                    "Value": bool(BASE_URL),
                },
                {
                    "Control": "Secure Access Secret",
                    "Value": (
                        "Configured"
                        if security_configuration_ok()
                        else "CHANGE REQUIRED"
                    ),
                },
                {
                    "Control": "External Integrations",
                    "Value": "Architecture / Stubs",
                },
                {
                    "Control": "Tenant Isolation",
                    "Value": "Enabled",
                },
                {
                    "Control": "RBAC",
                    "Value": "Enabled",
                },
                {
                    "Control": "Audit Logging",
                    "Value": "Enabled",
                },
                {
                    "Control": "Access Link Expiry",
                    "Value": "Enabled",
                },
            ]
        )

        st.dataframe(
            config_table,
            use_container_width=True,
            hide_index=True,
        )

        st.divider()

        st.subheader(
            "Security Checklist"
        )

        checks = {
            "Password hashing": True,
            "PBKDF2 password derivation": True,
            "Random password salts": True,
            "HMAC access tokens": True,
            "Expiring customer links": True,
            "Tenant-scoped access": True,
            "Industry entitlements": True,
            "RBAC": True,
            "Audit logging": True,
            "Failed-login lockout": True,
            "Human approval before connector dispatch": True,
            "Connector credentials hard-coded": False,
            "Actual external system connection claimed": False,
        }

        for item, enabled in checks.items():

            if enabled:
                st.success(
                    f"✓ {item}"
                )
            else:
                st.info(
                    f"✓ {item} — intentionally not enabled/claimed"
                )

        st.warning(
            "Application security is hardened, but Streamlit Community Cloud + local SQLite "
            "is still pilot infrastructure. For production customer data, use managed PostgreSQL "
            "or equivalent, durable backups, monitoring, a secrets manager, HTTPS and independent security testing."
        )


# ============================================================
# 43. GLOBAL DATA EXPORT / ADMIN UPLOAD NOTICE
# ============================================================

if page != "Administration":
    if has_permission("upload"):
        with st.sidebar.expander(
            "Data Operations"
        ):

            st.caption(
                "Upload a CSV/Excel dataset from the Data Quality page."
            )

            st.caption(
                "The quality gate runs before intelligence is accepted."
            )


# ============================================================
# 44. PLATFORM FOOTER
# ============================================================

st.sidebar.divider()

st.sidebar.caption(
    "PartnerOps 5.0 Commercial Control"
)

st.sidebar.caption(
    "Operational intelligence → recovery action → measurable value"
)
