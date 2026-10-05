# ============================================================
# PARTNEROPS 5.5 PHASE 1-4 CONTROL PLATFORM
# SINGLE-SOURCE-OF-TRUTH APPLICATION
#
# 5.5 ROADMAP: Phase 1 TPRM, Phase 2 Process Intelligence + Predictive Risk,
# Phase 3 Knowledge Graph + Governed Agents, Phase 4 Financial Value + Scenario Simulation.
# 5.4 HARDENING: cached deterministic intelligence, vectorized scoring,
# bounded ingestion, batched persistence, daily snapshot idempotency,
# tenant-scoped dataset identity, and reduced CMS query fan-out.
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

# Streamlit page configuration MUST happen before any other Streamlit command
# (including secrets access) to avoid Cloud startup failures on newer releases.
st.set_page_config(
    page_title="PartnerOps",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded",
)

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
    InvalidToken = Exception

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
APP_VERSION = "5.5.1 Deployment & Runtime Hardened"


def get_config_value(name, default=None):
    """Read configuration safely from Streamlit Secrets or environment variables."""
    # Environment variables remain a valid deployment mechanism.
    env_value = os.getenv(name)
    if env_value is not None:
        return str(env_value)

    try:
        secrets_obj = st.secrets
        value = secrets_obj.get(name)
        if value is not None:
            return str(value)
    except Exception:
        # Local development and some Cloud bootstrap states may not expose
        # secrets yet; defaults should keep the application bootable.
        pass

    return default


DB_FILE = get_config_value("PARTNEROPS_DB", "partnerops.db")
try:
    _db_parent = os.path.dirname(os.path.abspath(DB_FILE))
    if _db_parent:
        os.makedirs(_db_parent, exist_ok=True)
except OSError:
    pass

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
    MAX_UPLOAD_ROWS = int(get_config_value("PARTNEROPS_MAX_UPLOAD_ROWS", "100000"))
except (TypeError, ValueError):
    MAX_UPLOAD_ROWS = 250000
MAX_UPLOAD_ROWS = max(1000, min(MAX_UPLOAD_ROWS, 500000))

try:
    MAX_UPLOAD_COLUMNS = int(get_config_value("PARTNEROPS_MAX_UPLOAD_COLUMNS", "100"))
except (TypeError, ValueError):
    MAX_UPLOAD_COLUMNS = 250
MAX_UPLOAD_COLUMNS = max(20, min(MAX_UPLOAD_COLUMNS, 500))

MAX_UPLOAD_CELLS = min(MAX_UPLOAD_ROWS * MAX_UPLOAD_COLUMNS, 10_000_000)
MAX_DATASET_INSERT_BATCH = 1000
ANALYSIS_CACHE_TTL_SECONDS = 900
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

# Contract documents contain potentially sensitive legal/commercial data.
# The encryption key is defined during the security bootstrap so production
# validation cannot reference a variable that has not yet been initialized.
CONTRACT_DOCUMENT_ENCRYPTION_KEY = get_config_value(
    "PARTNEROPS_DOCUMENT_ENCRYPTION_KEY", ""
)

PBKDF2_ITERATIONS = 210_000

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PartnerOps")


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

    unsafe_document_key = PRODUCTION_MODE and (not CONTRACT_DOCUMENT_ENCRYPTION_KEY or Fernet is None)

    return not unsafe_secret and not unsafe_password and not unsafe_document_key


if PRODUCTION_MODE and not security_configuration_ok():
    st.error(
        "PartnerOps is configured for production but secure secrets have not "
        "been configured. Set PARTNEROPS_ACCESS_SECRET, "
        "PARTNEROPS_INITIAL_ADMIN_PASSWORD, and PARTNEROPS_DOCUMENT_ENCRYPTION_KEY for production contract storage."
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
    """Open a resilient SQLite connection for Streamlit Cloud and local use."""
    conn = sqlite3.connect(DB_FILE, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA synchronous = NORMAL")
    if DB_FILE != ":memory:":
        try:
            conn.execute("PRAGMA journal_mode = WAL")
        except sqlite3.DatabaseError:
            # WAL may be unavailable on unusual filesystems; normal SQLite mode
            # remains functional for the pilot application.
            pass
    return conn


def db_execute(sql, params=(), fetch=False, many=False):
    conn = get_db()
    cur = conn.cursor()
    try:
        if many:
            cur.executemany(sql, params)
        else:
            cur.execute(sql, params)
        result = cur.fetchall() if fetch else None
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


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
    cur.execute("""
        DELETE FROM snapshots
        WHERE snapshot_id NOT IN (
            SELECT MAX(snapshot_id)
            FROM snapshots
            GROUP BY tenant_id, industry, snapshot_date, partner
        )
    """)
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_snapshots_scope_day_partner
        ON snapshots(tenant_id, industry, snapshot_date, partner)
    """)

    conn.commit()
    conn.close()


init_db()


# ============================================================
# 5A. CONTRACT MANAGEMENT DATA LAYER
# ============================================================

CONTRACT_DOCUMENT_MAX_BYTES = 10 * 1024 * 1024
CONTRACT_STATUSES = ["Draft", "Active", "Expiring", "Expired", "Terminated", "Renewal Pending"]
CONTRACT_RISK_LEVELS = ["Low", "Medium", "High", "Critical"]
OBLIGATION_STATUSES = ["Open", "On Track", "At Risk", "Breached", "Completed", "Waived"]
SLA_DIRECTIONS = ["higher_is_better", "lower_is_better"]


def init_contract_db():
    """Create the contract intelligence layer without changing existing PartnerOps tables."""
    conn = get_db()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS tenant_modules (
            tenant_id TEXT NOT NULL,
            module_key TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            PRIMARY KEY (tenant_id, module_key)
        );

        CREATE TABLE IF NOT EXISTS contracts (
            contract_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            contract_number TEXT NOT NULL,
            title TEXT NOT NULL,
            counterparty TEXT NOT NULL,
            partner_name TEXT,
            industry TEXT,
            contract_type TEXT,
            status TEXT DEFAULT 'Draft',
            start_date TEXT,
            end_date TEXT,
            auto_renew INTEGER DEFAULT 0,
            notice_days INTEGER DEFAULT 30,
            currency TEXT DEFAULT 'KES',
            contract_value REAL DEFAULT 0,
            owner TEXT,
            governing_law TEXT,
            risk_level TEXT DEFAULT 'Medium',
            summary TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(tenant_id, contract_number)
        );

        CREATE TABLE IF NOT EXISTS contract_obligations (
            obligation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            contract_id INTEGER NOT NULL,
            obligation_title TEXT NOT NULL,
            description TEXT,
            responsible_party TEXT NOT NULL,
            owner TEXT,
            due_date TEXT,
            recurrence TEXT,
            target_value REAL,
            unit TEXT,
            evidence_required TEXT,
            status TEXT DEFAULT 'Open',
            risk_level TEXT DEFAULT 'Medium',
            value_at_risk REAL DEFAULT 0,
            last_completed_date TEXT,
            next_due_date TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(contract_id) REFERENCES contracts(contract_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS contract_slas (
            sla_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            contract_id INTEGER NOT NULL,
            sla_name TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            target_value REAL NOT NULL,
            direction TEXT DEFAULT 'higher_is_better',
            unit TEXT DEFAULT '%',
            measurement_period TEXT DEFAULT 'Monthly',
            grace_period_days INTEGER DEFAULT 0,
            penalty_rate REAL DEFAULT 0,
            current_value REAL,
            status TEXT DEFAULT 'Not Measured',
            breach_count INTEGER DEFAULT 0,
            last_measured_at TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(contract_id) REFERENCES contracts(contract_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS contract_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            contract_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            event_date TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            owner TEXT,
            status TEXT DEFAULT 'Open',
            created_by TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(contract_id) REFERENCES contracts(contract_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS contract_documents (
            document_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            contract_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            mime_type TEXT,
            file_size INTEGER DEFAULT 0,
            sha256 TEXT NOT NULL,
            content BLOB,
            uploaded_by TEXT,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(contract_id) REFERENCES contracts(contract_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS contract_reviews (
            review_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            contract_id INTEGER NOT NULL,
            review_type TEXT NOT NULL,
            review_date TEXT NOT NULL,
            reviewer TEXT NOT NULL,
            result TEXT NOT NULL,
            findings TEXT,
            remediation TEXT,
            status TEXT DEFAULT 'Open',
            created_at TEXT NOT NULL,
            FOREIGN KEY(contract_id) REFERENCES contracts(contract_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_contracts_tenant_status ON contracts(tenant_id, status);
        CREATE INDEX IF NOT EXISTS idx_contracts_tenant_end ON contracts(tenant_id, end_date);
        CREATE INDEX IF NOT EXISTS idx_contract_obligations_contract ON contract_obligations(contract_id, status);
        CREATE INDEX IF NOT EXISTS idx_contract_slas_contract ON contract_slas(contract_id, status);
        CREATE INDEX IF NOT EXISTS idx_contract_events_contract ON contract_events(contract_id, event_date);
        CREATE INDEX IF NOT EXISTS idx_contract_documents_contract ON contract_documents(contract_id);
        CREATE INDEX IF NOT EXISTS idx_contract_reviews_contract ON contract_reviews(contract_id, review_date);
        """
    )

    # Cross-module traceability: contract recovery actions must remain linked
    # to the originating contract/obligation while remaining tenant-scoped.
    existing_intervention = {row[1] for row in cur.execute("PRAGMA table_info(interventions)").fetchall()}
    if "contract_id" not in existing_intervention:
        cur.execute("ALTER TABLE interventions ADD COLUMN contract_id INTEGER")
    if "obligation_id" not in existing_intervention:
        cur.execute("ALTER TABLE interventions ADD COLUMN obligation_id INTEGER")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_interventions_contract ON interventions(tenant_id, contract_id, obligation_id)")

    # Forward-compatible migration for contracts created before industry scoping.
    existing_contract_columns = {row[1] for row in cur.execute("PRAGMA table_info(contracts)").fetchall()}
    if "industry" not in existing_contract_columns:
        cur.execute("ALTER TABLE contracts ADD COLUMN industry TEXT")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_contracts_tenant_industry ON contracts(tenant_id, industry)")

    conn.commit()
    conn.close()


def module_enabled(tenant_id, module_key):
    rows = db_execute(
        "SELECT enabled FROM tenant_modules WHERE tenant_id = ? AND module_key = ?",
        (tenant_id, module_key), fetch=True
    )
    return bool(rows and rows[0]["enabled"])


# Initialize the contract-intelligence schema before any module entitlement
# queries or default-module seeding. This is required on a fresh deployment
# as well as on an upgraded 5.2.x database.
init_contract_db()


def ensure_default_modules():
    """Ensure module-entitlement storage exists before seeding tenant defaults.

    This is intentionally defensive because Streamlit Cloud may start against
    an existing SQLite file created by an earlier application revision.
    The function must therefore be safe even if the contract schema bootstrap
    was interrupted or the database was created by a pre-CMS version.
    """
    db_execute(
        """
        CREATE TABLE IF NOT EXISTS tenant_modules (
            tenant_id TEXT NOT NULL,
            module_key TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            PRIMARY KEY (tenant_id, module_key)
        )
        """
    )

    db_execute(
        "CREATE INDEX IF NOT EXISTS idx_tenant_modules_tenant ON tenant_modules(tenant_id)"
    )

    tenants = db_execute("SELECT tenant_id FROM tenants", fetch=True)
    if not tenants:
        return

    db_execute(
        "INSERT OR IGNORE INTO tenant_modules(tenant_id, module_key, enabled) VALUES (?, ?, 1)",
        [
            (row["tenant_id"], module_key)
            for row in tenants
            for module_key in ("partner_performance", "contract_intelligence")
        ],
        many=True,
    )


ensure_default_modules()


# ============================================================
# 10A. PHASE 1-4 CONTROL-PLATFORM DATA LAYER
# ============================================================
# These tables extend PartnerOps without replacing the existing 5.4.1
# performance/CMS schema. Every record is tenant-scoped and auditable.

def init_phase_roadmap_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS tprm_entities (
            entity_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            entity_type TEXT NOT NULL DEFAULT 'Third Party',
            name TEXT NOT NULL,
            category TEXT,
            criticality TEXT DEFAULT 'Medium',
            owner TEXT,
            contract_id INTEGER,
            status TEXT DEFAULT 'Active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_tprm_entities_tenant ON tprm_entities(tenant_id, status);

        CREATE TABLE IF NOT EXISTS tprm_assessments (
            assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            assessment_date TEXT NOT NULL,
            cyber_score REAL DEFAULT 0,
            financial_score REAL DEFAULT 0,
            operational_score REAL DEFAULT 0,
            compliance_score REAL DEFAULT 0,
            concentration_score REAL DEFAULT 0,
            overall_score REAL DEFAULT 0,
            risk_level TEXT DEFAULT 'Medium',
            findings TEXT,
            assessor TEXT,
            next_review_date TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(entity_id) REFERENCES tprm_entities(entity_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_tprm_assessments_entity ON tprm_assessments(tenant_id, entity_id, assessment_date);

        CREATE TABLE IF NOT EXISTS tprm_controls (
            control_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            control_name TEXT NOT NULL,
            control_type TEXT DEFAULT 'Preventive',
            owner TEXT,
            due_date TEXT,
            status TEXT DEFAULT 'Open',
            evidence_required TEXT,
            effectiveness REAL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(entity_id) REFERENCES tprm_entities(entity_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_tprm_controls_entity ON tprm_controls(tenant_id, entity_id, status);

        CREATE TABLE IF NOT EXISTS tprm_incidents (
            incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            incident_date TEXT NOT NULL,
            severity TEXT DEFAULT 'Medium',
            category TEXT,
            description TEXT,
            financial_impact REAL DEFAULT 0,
            status TEXT DEFAULT 'Open',
            owner TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(entity_id) REFERENCES tprm_entities(entity_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_tprm_incidents_entity ON tprm_incidents(tenant_id, entity_id, status);

        CREATE TABLE IF NOT EXISTS process_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            process_name TEXT NOT NULL,
            process_step TEXT,
            event_date TEXT NOT NULL,
            entity_name TEXT,
            volume REAL DEFAULT 0,
            cycle_time_hours REAL,
            outcome TEXT,
            status TEXT DEFAULT 'Completed',
            owner TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_process_events_tenant ON process_events(tenant_id, process_name, event_date);

        CREATE TABLE IF NOT EXISTS process_metrics (
            metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            process_name TEXT NOT NULL,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            throughput REAL DEFAULT 0,
            completion_rate REAL DEFAULT 0,
            avg_cycle_time REAL DEFAULT 0,
            backlog REAL DEFAULT 0,
            failure_rate REAL DEFAULT 0,
            bottleneck_score REAL DEFAULT 0,
            risk_score REAL DEFAULT 0,
            diagnosis TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_process_metrics_tenant ON process_metrics(tenant_id, process_name, period_end);

        CREATE TABLE IF NOT EXISTS knowledge_entities (
            knowledge_entity_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_key TEXT NOT NULL,
            label TEXT NOT NULL,
            source_type TEXT,
            source_id TEXT,
            confidence REAL DEFAULT 1.0,
            created_at TEXT NOT NULL,
            UNIQUE(tenant_id, entity_type, entity_key)
        );
        CREATE INDEX IF NOT EXISTS idx_knowledge_entities_tenant ON knowledge_entities(tenant_id, entity_type);

        CREATE TABLE IF NOT EXISTS knowledge_relations (
            relation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            from_entity_id INTEGER NOT NULL,
            relation_type TEXT NOT NULL,
            to_entity_id INTEGER NOT NULL,
            confidence REAL DEFAULT 1.0,
            source_type TEXT,
            source_id TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(tenant_id, from_entity_id, relation_type, to_entity_id)
        );
        CREATE INDEX IF NOT EXISTS idx_knowledge_relations_tenant ON knowledge_relations(tenant_id, relation_type);

        CREATE TABLE IF NOT EXISTS agent_runs (
            agent_run_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            agent_name TEXT NOT NULL,
            objective TEXT NOT NULL,
            scope TEXT,
            decision TEXT,
            evidence TEXT,
            recommended_action TEXT,
            confidence REAL DEFAULT 0,
            approval_status TEXT DEFAULT 'Pending',
            approved_by TEXT,
            approved_at TEXT,
            executed_at TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_agent_runs_tenant ON agent_runs(tenant_id, approval_status, created_at);

        CREATE TABLE IF NOT EXISTS value_drivers (
            driver_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            unit TEXT DEFAULT 'KES',
            baseline REAL DEFAULT 0,
            current_value REAL DEFAULT 0,
            target_value REAL DEFAULT 0,
            value_per_unit REAL DEFAULT 0,
            owner TEXT,
            status TEXT DEFAULT 'Active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_value_drivers_tenant ON value_drivers(tenant_id, status);

        CREATE TABLE IF NOT EXISTS scenarios (
            scenario_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            horizon_days INTEGER DEFAULT 90,
            probability REAL DEFAULT 1.0,
            assumptions_json TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scenarios_tenant ON scenarios(tenant_id, created_at);

        CREATE TABLE IF NOT EXISTS scenario_results (
            result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            scenario_id INTEGER NOT NULL,
            driver_id INTEGER,
            baseline_value REAL DEFAULT 0,
            scenario_value REAL DEFAULT 0,
            gross_value REAL DEFAULT 0,
            risk_adjusted_value REAL DEFAULT 0,
            notes TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(scenario_id) REFERENCES scenarios(scenario_id) ON DELETE CASCADE,
            FOREIGN KEY(driver_id) REFERENCES value_drivers(driver_id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scenario_results_tenant ON scenario_results(tenant_id, scenario_id);
        """
    )
    conn.commit()
    conn.close()


init_phase_roadmap_db()


def _phase_rows(sql, params=()):
    return [dict(r) for r in db_execute(sql, params, fetch=True)]


def _phase_tenant():
    return st.session_state.get("tenant_id")


def _phase_write_allowed():
    return has_permission("write") or has_permission("admin") or st.session_state.get("role") in {"admin", "manager"}


def _risk_level(score):
    score = float(score or 0)
    if score >= 80:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _phase4_money(value):
    return f"KES {float(value or 0):,.0f}"


def _phase1_score(values):
    vals = [max(0.0, min(100.0, float(v or 0))) for v in values]
    return round(sum(vals) / len(vals), 2) if vals else 0.0


def _sync_contracts_to_tprm():
    tenant_id = _phase_tenant()
    rows = _phase_rows("SELECT contract_id, counterparty, partner_name, risk_level, owner, status FROM contracts WHERE tenant_id = ?", (tenant_id,))
    created = 0
    for r in rows:
        name = r.get("partner_name") or r.get("counterparty") or f"Contract {r['contract_id']}"
        exists = _phase_rows("SELECT entity_id FROM tprm_entities WHERE tenant_id = ? AND contract_id = ? LIMIT 1", (tenant_id, r["contract_id"]))
        if not exists:
            criticality = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low"}.get(r.get("risk_level"), "Medium")
            db_execute("""INSERT INTO tprm_entities(tenant_id, entity_type, name, category, criticality, owner, contract_id, status, created_at, updated_at)
                          VALUES (?, 'Contracted Third Party', ?, 'Contract Counterparty', ?, ?, ?, ?, ?, ?)""",
                       (tenant_id, name, criticality, r.get("owner"), r["contract_id"], r.get("status") or "Active", utc_iso(), utc_iso()))
            created += 1
    return created


def phase1_tprm_page():
    st.title("🛡️ Third-Party Risk Management")
    st.caption("Phase 1 · Third party → risk → control → incident → remediation → residual risk")
    tenant_id = _phase_tenant()
    synced = _sync_contracts_to_tprm()
    if synced:
        st.success(f"Synchronized {synced} contract counterparty record(s) into the TPRM register.")

    entities = pd.DataFrame(_phase_rows("SELECT * FROM tprm_entities WHERE tenant_id = ? ORDER BY entity_id DESC", (tenant_id,)))
    assessments = pd.DataFrame(_phase_rows("SELECT * FROM tprm_assessments WHERE tenant_id = ? ORDER BY assessment_date DESC", (tenant_id,)))
    incidents = pd.DataFrame(_phase_rows("SELECT * FROM tprm_incidents WHERE tenant_id = ? ORDER BY incident_id DESC", (tenant_id,)))
    high_risk = int((assessments["risk_level"].isin(["High", "Critical"])).sum()) if not assessments.empty else 0
    open_incidents = int((incidents["status"].isin(["Open", "Investigating"])).sum()) if not incidents.empty else 0
    avg_risk = float(assessments["overall_score"].mean()) if not assessments.empty else 0
    c1,c2,c3,c4=st.columns(4)
    c1.metric("Third Parties", len(entities))
    c2.metric("High / Critical Assessments", high_risk)
    c3.metric("Open Incidents", open_incidents)
    c4.metric("Average Risk Score", f"{avg_risk:.1f}/100")

    tabs=st.tabs(["Register","Assessments","Controls & Incidents"])
    with tabs[0]:
        if not entities.empty:
            st.dataframe(entities[[c for c in ["entity_id","name","entity_type","category","criticality","owner","contract_id","status"] if c in entities.columns]], use_container_width=True, hide_index=True)
        if _phase_write_allowed():
            with st.form("tprm_entity_form", clear_on_submit=True):
                a,b=st.columns(2)
                with a:
                    name=st.text_input("Third party name *")
                    category=st.text_input("Category", value="Supplier / Contractor")
                    owner=st.text_input("Risk owner")
                with b:
                    criticality=st.selectbox("Criticality", ["Low","Medium","High","Critical"], index=1)
                    status=st.selectbox("Status", ["Active","Under Review","Suspended","Exited"])
                if st.form_submit_button("Add Third Party", use_container_width=True):
                    if name.strip():
                        db_execute("INSERT INTO tprm_entities(tenant_id,name,category,criticality,owner,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)", (tenant_id,name.strip(),category.strip(),criticality,owner.strip() or None,status,utc_iso(),utc_iso()))
                        audit("TPRM_ENTITY_CREATED","tprm_entity",name.strip(),{"criticality":criticality})
                        st.rerun()
                    else: st.error("Third party name is required.")
    with tabs[1]:
        if not entities.empty:
            opts={f"{r['name']} (ID {r['entity_id']})":int(r['entity_id']) for _,r in entities.iterrows()}
            with st.form("tprm_assessment_form", clear_on_submit=True):
                label=st.selectbox("Third party", list(opts))
                a,b,c=st.columns(3)
                with a:
                    cyber=st.slider("Cyber / information risk",0,100,30)
                    financial=st.slider("Financial risk",0,100,30)
                with b:
                    operational=st.slider("Operational risk",0,100,30)
                    compliance=st.slider("Compliance risk",0,100,30)
                with c:
                    concentration=st.slider("Concentration risk",0,100,30)
                    next_review=st.date_input("Next review", value=utc_now().date()+timedelta(days=90))
                findings=st.text_area("Findings")
                if st.form_submit_button("Record Risk Assessment", use_container_width=True):
                    score=_phase1_score([cyber,financial,operational,compliance,concentration])
                    db_execute("""INSERT INTO tprm_assessments(tenant_id,entity_id,assessment_date,cyber_score,financial_score,operational_score,compliance_score,concentration_score,overall_score,risk_level,findings,assessor,next_review_date,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (tenant_id,opts[label],_contract_date(utc_now().date()),cyber,financial,operational,compliance,concentration,score,_risk_level(score),findings.strip() or None,st.session_state.username,_contract_date(next_review),utc_iso()))
                    audit("TPRM_ASSESSMENT_CREATED","tprm_assessment",opts[label],{"risk_score":score,"risk_level":_risk_level(score)})
                    st.rerun()
        if not assessments.empty:
            st.dataframe(assessments[[c for c in ["assessment_id","entity_id","assessment_date","overall_score","risk_level","findings","next_review_date"] if c in assessments.columns]], use_container_width=True, hide_index=True)
    with tabs[2]:
        controls=pd.DataFrame(_phase_rows("SELECT * FROM tprm_controls WHERE tenant_id = ? ORDER BY control_id DESC", (tenant_id,)))
        if not controls.empty:
            st.subheader("Control Register")
            st.dataframe(controls, use_container_width=True, hide_index=True)
        if _phase_write_allowed() and not entities.empty:
            opts={f"{r['name']} (ID {r['entity_id']})":int(r['entity_id']) for _,r in entities.iterrows()}
            with st.form("tprm_control_form", clear_on_submit=True):
                a,b=st.columns(2)
                with a:
                    entity_label=st.selectbox("Third party", list(opts), key="tprm_control_entity")
                    control_name=st.text_input("Control name *", value="Quarterly risk review")
                    control_type=st.selectbox("Control type", ["Preventive","Detective","Corrective"])
                with b:
                    control_owner=st.text_input("Control owner")
                    control_due=st.date_input("Due date", value=utc_now().date()+timedelta(days=30), key="tprm_control_due")
                    control_status=st.selectbox("Status", ["Open","In Progress","Effective","Overdue","Closed"])
                evidence_required=st.text_input("Evidence required")
                effectiveness=st.slider("Effectiveness", 0, 100, 50)
                if st.form_submit_button("Add Control", use_container_width=True) and control_name.strip():
                    db_execute("INSERT INTO tprm_controls(tenant_id,entity_id,control_name,control_type,owner,due_date,status,evidence_required,effectiveness,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)", (tenant_id,opts[entity_label],control_name.strip(),control_type,control_owner.strip() or None,_contract_date(control_due),control_status,evidence_required.strip() or None,float(effectiveness),utc_iso()))
                    audit("TPRM_CONTROL_CREATED","tprm_control",control_name.strip(),{"entity_id":opts[entity_label]})
                    st.rerun()
        st.divider()
        st.subheader("Incident Register")
        if not incidents.empty:
            st.dataframe(incidents, use_container_width=True, hide_index=True)
        if _phase_write_allowed() and not entities.empty:
            opts={f"{r['name']} (ID {r['entity_id']})":int(r['entity_id']) for _,r in entities.iterrows()}
            with st.form("tprm_incident_form", clear_on_submit=True):
                a,b=st.columns(2)
                with a:
                    incident_entity=st.selectbox("Third party", list(opts), key="tprm_incident_entity")
                    incident_date=st.date_input("Incident date", value=utc_now().date(), key="tprm_incident_date")
                    severity=st.selectbox("Severity", ["Low","Medium","High","Critical"])
                with b:
                    category=st.text_input("Category", value="Operational")
                    incident_status=st.selectbox("Status", ["Open","Investigating","Resolved","Closed"])
                    impact=st.number_input("Financial impact", min_value=0.0, value=0.0)
                description=st.text_area("Description")
                incident_owner=st.text_input("Incident owner")
                if st.form_submit_button("Record Incident", use_container_width=True):
                    db_execute("INSERT INTO tprm_incidents(tenant_id,entity_id,incident_date,severity,category,description,financial_impact,status,owner,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)", (tenant_id,opts[incident_entity],_contract_date(incident_date),severity,category.strip() or None,description.strip() or None,float(impact),incident_status,incident_owner.strip() or None,utc_iso()))
                    audit("TPRM_INCIDENT_CREATED","tprm_incident",opts[incident_entity],{"severity":severity,"financial_impact":impact})
                    st.rerun()


def phase2_process_page():
    st.title("⚙️ Process Intelligence")
    st.caption("Phase 2 · Process → bottleneck → risk signal → intervention priority")
    tenant_id=_phase_tenant()
    events=pd.DataFrame(_phase_rows("SELECT * FROM process_events WHERE tenant_id = ? ORDER BY event_id DESC", (tenant_id,)))
    metrics=pd.DataFrame(_phase_rows("SELECT * FROM process_metrics WHERE tenant_id = ? ORDER BY metric_id DESC", (tenant_id,)))
    c1,c2,c3,c4=st.columns(4)
    c1.metric("Process Events",len(events))
    c2.metric("Processes",int(events["process_name"].nunique()) if not events.empty else 0)
    c3.metric("Open / Pending",int(events["status"].isin(["Open","Pending","Failed"] ).sum()) if not events.empty else 0)
    c4.metric("Bottlenecks",int((metrics["bottleneck_score"]>=65).sum()) if not metrics.empty else 0)
    if _phase_write_allowed():
        with st.expander("Register Process Evidence", expanded=not bool(events.empty)):
            with st.form("process_event_form", clear_on_submit=True):
                a,b=st.columns(2)
                with a:
                    process=st.text_input("Process name *", value="Field Operations")
                    step=st.text_input("Process step", value="Execution")
                    entity=st.text_input("Entity / partner")
                    event_date=st.date_input("Event date", value=utc_now().date())
                with b:
                    volume=st.number_input("Volume", min_value=0.0, value=1.0)
                    cycle=st.number_input("Cycle time (hours)", min_value=0.0, value=24.0)
                    outcome=st.text_input("Outcome")
                    status=st.selectbox("Status", ["Completed","Open","Pending","Failed","Cancelled"])
                owner=st.text_input("Owner")
                if st.form_submit_button("Add Process Event", use_container_width=True):
                    if process.strip():
                        db_execute("INSERT INTO process_events(tenant_id,process_name,process_step,event_date,entity_name,volume,cycle_time_hours,outcome,status,owner,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)", (tenant_id,process.strip(),step.strip() or None,_contract_date(event_date),entity.strip() or None,float(volume),float(cycle),outcome.strip() or None,status,owner.strip() or None,utc_iso()))
                        audit("PROCESS_EVENT_CREATED","process_event",process.strip(),{"status":status,"volume":volume})
                        st.rerun()
    if not events.empty:
        agg=events.groupby("process_name",dropna=False).agg(events=("event_id","count"),volume=("volume","sum"),avg_cycle=("cycle_time_hours","mean"),failed=("status",lambda x:int((x=="Failed").sum())),pending=("status",lambda x:int(x.isin(["Open","Pending"]).sum()))).reset_index()
        agg["failure_rate"]=(agg["failed"]/agg["events"]*100).round(2)
        agg["backlog_rate"]=(agg["pending"]/agg["events"]*100).round(2)
        agg["bottleneck_score"]=(agg["failure_rate"]*0.35+agg["backlog_rate"]*0.35+(agg["avg_cycle"]/max(float(agg["avg_cycle"].max()),1)*100)*0.30).clip(0,100).round(2)
        agg["risk"] = agg["bottleneck_score"].apply(_risk_level)
        st.subheader("Current Process Risk")
        st.dataframe(agg, use_container_width=True, hide_index=True)
        if _phase_write_allowed() and st.button("Persist Current Process Intelligence", use_container_width=True):
            period_start=str(events["event_date"].min())
            period_end=str(events["event_date"].max())
            for _,r in agg.iterrows():
                db_execute("DELETE FROM process_metrics WHERE tenant_id=? AND process_name=? AND period_start=? AND period_end=?", (tenant_id,str(r["process_name"]),period_start,period_end))
                db_execute("INSERT INTO process_metrics(tenant_id,process_name,period_start,period_end,throughput,completion_rate,avg_cycle_time,backlog,failure_rate,bottleneck_score,risk_score,diagnosis,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (tenant_id,str(r["process_name"]),period_start,period_end,float(r["volume"]),float(max(0,100-r["failure_rate"]-r["backlog_rate"])),float(r["avg_cycle"]),float(r["pending"]),float(r["failure_rate"]),float(r["bottleneck_score"]),float(r["bottleneck_score"]),f"Primary process pressure is driven by failure/backlog/cycle-time signals; risk band {_risk_level(r['bottleneck_score'])}.",utc_iso()))
            audit("PROCESS_INTELLIGENCE_PERSISTED","process_metrics","batch",{"processes":len(agg)})
            st.success("Process intelligence persisted.")
            st.rerun()
    elif not metrics.empty:
        st.dataframe(metrics, use_container_width=True, hide_index=True)
    st.info("Phase 2 is evidence-first: predictive risk is derived from measurable process signals. No unsupported AI conclusion is presented as fact.")


def phase3_knowledge_page():
    st.title("🧠 Knowledge Graph & Governed Triage")
    st.caption("Phase 3 · Evidence graph → governed reasoning → human approval → controlled action")
    tenant_id=_phase_tenant()
    entities=pd.DataFrame(_phase_rows("SELECT * FROM knowledge_entities WHERE tenant_id = ? ORDER BY knowledge_entity_id DESC", (tenant_id,)))
    relations=pd.DataFrame(_phase_rows("SELECT * FROM knowledge_relations WHERE tenant_id = ? ORDER BY relation_id DESC", (tenant_id,)))
    runs=pd.DataFrame(_phase_rows("SELECT * FROM agent_runs WHERE tenant_id = ? ORDER BY agent_run_id DESC", (tenant_id,)))
    c1,c2,c3=st.columns(3)
    c1.metric("Knowledge Entities",len(entities))
    c2.metric("Relationships",len(relations))
    c3.metric("Pending Agent Decisions",int((runs["approval_status"]=="Pending").sum()) if not runs.empty else 0)
    if _phase_write_allowed():
        tabs=st.tabs(["Graph Builder","Governed Agent"])
        with tabs[0]:
            with st.form("knowledge_entity_form", clear_on_submit=True):
                a,b=st.columns(2)
                with a:
                    etype=st.selectbox("Entity type",["Partner","Contract","Obligation","SLA","Process","Risk","Action","Outcome","Third Party"])
                    ekey=st.text_input("Stable entity key *")
                with b:
                    label=st.text_input("Label *")
                    source=st.text_input("Source type",value="Operational evidence")
                if st.form_submit_button("Add Knowledge Entity",use_container_width=True):
                    if ekey.strip() and label.strip():
                        db_execute("INSERT OR IGNORE INTO knowledge_entities(tenant_id,entity_type,entity_key,label,source_type,created_at) VALUES (?,?,?,?,?,?)",(tenant_id,etype,ekey.strip(),label.strip(),source.strip() or None,utc_iso()))
                        audit("KNOWLEDGE_ENTITY_CREATED","knowledge_entity",ekey.strip(),{"entity_type":etype})
                        st.rerun()
            if not entities.empty: st.dataframe(entities,use_container_width=True,hide_index=True)
            if len(entities)>=2:
                opts={f"{r['label']} [{r['entity_type']}]":int(r['knowledge_entity_id']) for _,r in entities.iterrows()}
                with st.form("knowledge_relation_form",clear_on_submit=True):
                    a,b,c=st.columns(3)
                    with a: frm=st.selectbox("From",list(opts),key="kg_from")
                    with b: rel=st.selectbox("Relation",["OWNS","HAS_OBLIGATION","HAS_SLA","USES_PROCESS","AT_RISK","TRIGGERS","REQUIRES_ACTION","IMPROVES","GOVERNS"])
                    with c: to=st.selectbox("To",list(opts),key="kg_to")
                    if st.form_submit_button("Create Relationship",use_container_width=True) and opts[frm]!=opts[to]:
                        db_execute("INSERT OR IGNORE INTO knowledge_relations(tenant_id,from_entity_id,relation_type,to_entity_id,source_type,created_at) VALUES (?,?,?,?,?,?)",(tenant_id,opts[frm],rel,opts[to],"Governed platform record",utc_iso()))
                        audit("KNOWLEDGE_RELATION_CREATED","knowledge_relation",f"{opts[frm]}->{opts[to]}",{"relation":rel})
                        st.rerun()
        with tabs[1]:
            objective=st.text_area("Agent objective",value="Identify the highest-priority operational control issue supported by current evidence.")
            scope=st.selectbox("Scope",["Current tenant","Current industry","Current contract portfolio","Current TPRM register"])
            if st.button("Run Governed Analysis",use_container_width=True):
                evidence=[]
                actions=[]
                contracts=_phase_rows("SELECT contract_number,title,risk_level FROM contracts WHERE tenant_id=? AND status NOT IN ('Expired','Terminated') ORDER BY CASE risk_level WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END LIMIT 5",(tenant_id,))
                tprm=_phase_rows("SELECT e.name,a.overall_score,a.risk_level FROM tprm_entities e JOIN tprm_assessments a ON a.entity_id=e.entity_id WHERE e.tenant_id=? ORDER BY a.assessment_id DESC LIMIT 5",(tenant_id,))
                process=_phase_rows("SELECT process_name,bottleneck_score,risk_score,diagnosis FROM process_metrics WHERE tenant_id=? ORDER BY metric_id DESC LIMIT 5",(tenant_id,))
                graph_counts=_phase_rows("SELECT COUNT(*) AS n FROM knowledge_entities WHERE tenant_id=?",(tenant_id,))
                relation_counts=_phase_rows("SELECT COUNT(*) AS n FROM knowledge_relations WHERE tenant_id=?",(tenant_id,))
                if contracts: evidence.append(f"Contract risk records available: {len(contracts)}")
                if tprm: evidence.append(f"Recent TPRM assessments available: {len(tprm)}")
                if process: evidence.append(f"Persisted process-risk records available: {len(process)}")
                if graph_counts and int(graph_counts[0].get("n") or 0): evidence.append(f"Knowledge entities available: {int(graph_counts[0].get('n') or 0)}")
                if relation_counts and int(relation_counts[0].get("n") or 0): evidence.append(f"Knowledge relationships available: {int(relation_counts[0].get('n') or 0)}")
                process_high=process and max(float(x.get("risk_score") or 0) for x in process)>=65
                if contracts and any(str(x.get("risk_level")) in ("High","Critical") for x in contracts):
                    decision="Prioritize high-risk contractual counterparties for controlled review."
                    actions.append("Open or refresh a contract/TPrm review with named owner and due date.")
                    confidence=0.86
                elif tprm and max(float(x.get("overall_score") or 0) for x in tprm)>=65:
                    decision="Prioritize high-risk third parties for remediation."
                    actions.append("Assign a risk-control remediation action and evidence deadline.")
                    confidence=0.82
                elif process_high:
                    decision="Prioritize the highest-risk process bottleneck for controlled review."
                    actions.append("Assign a process recovery owner and validate the underlying cycle-time, backlog and failure evidence.")
                    confidence=0.80
                else:
                    decision="No high-confidence critical control issue identified from the currently registered evidence."
                    actions.append("Collect more operational/contract evidence before escalating.")
                    confidence=0.68
                db_execute("INSERT INTO agent_runs(tenant_id,agent_name,objective,scope,decision,evidence,recommended_action,confidence,approval_status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",(tenant_id,"Control Triage Agent",objective,scope,decision,"; ".join(evidence) or "No supporting records found."," ".join(actions),confidence,"Pending",utc_iso()))
                audit("GOVERNED_AGENT_RUN","agent_run","Control Triage Agent",{"confidence":confidence,"scope":scope})
                st.success("Governed analysis completed. Execution remains blocked until an authorized human approves it.")
                st.write(decision)
                st.caption(f"Confidence: {confidence:.0%} · Evidence: {'; '.join(evidence) or 'Insufficient registered evidence'}")
    if not runs.empty:
        st.subheader("Agent Governance Queue")
        st.dataframe(runs[[c for c in ["agent_run_id","agent_name","objective","decision","recommended_action","confidence","approval_status","created_at"] if c in runs.columns]],use_container_width=True,hide_index=True)
        pending=runs[runs["approval_status"]=="Pending"]
        if _phase_write_allowed() and not pending.empty:
            for _,r in pending.head(5).iterrows():
                if st.button(f"Approve recommendation #{int(r['agent_run_id'])}",key=f"approve_agent_{int(r['agent_run_id'])}"):
                    db_execute("UPDATE agent_runs SET approval_status='Approved',approved_by=?,approved_at=? WHERE tenant_id=? AND agent_run_id=? AND approval_status='Pending'",(st.session_state.username,utc_iso(),tenant_id,int(r['agent_run_id'])))
                    audit("GOVERNED_AGENT_APPROVED","agent_run",int(r['agent_run_id']),{"agent":r['agent_name']})
                    st.rerun()
    st.warning("Governed agents in this release are deterministic control agents. They may recommend; they do not autonomously execute external actions.")


def phase4_value_page():
    st.title("💰 Financial Value & Scenario Simulation")
    st.caption("Phase 4 · Driver → baseline → intervention → scenario → risk-adjusted value")
    tenant_id=_phase_tenant()
    drivers=pd.DataFrame(_phase_rows("SELECT * FROM value_drivers WHERE tenant_id=? ORDER BY driver_id DESC",(tenant_id,)))
    scenarios=pd.DataFrame(_phase_rows("SELECT * FROM scenarios WHERE tenant_id=? ORDER BY scenario_id DESC",(tenant_id,)))
    results=pd.DataFrame(_phase_rows("SELECT * FROM scenario_results WHERE tenant_id=? ORDER BY result_id DESC",(tenant_id,)))
    total_value=float(results["risk_adjusted_value"].sum()) if not results.empty else 0
    c1,c2,c3=st.columns(3)
    c1.metric("Value Drivers",len(drivers))
    c2.metric("Scenarios",len(scenarios))
    c3.metric("Risk-Adjusted Scenario Value",_phase4_money(total_value))
    if _phase_write_allowed():
        tabs=st.tabs(["Value Drivers","Scenarios","Results"])
        with tabs[0]:
            if not drivers.empty: st.dataframe(drivers,use_container_width=True,hide_index=True)
            with st.form("value_driver_form",clear_on_submit=True):
                a,b=st.columns(2)
                with a:
                    name=st.text_input("Value driver *",value="Recovered operational value")
                    unit=st.selectbox("Unit",["KES","USD","EUR","Units","Hours"])
                    owner=st.text_input("Owner")
                with b:
                    baseline=st.number_input("Baseline",min_value=0.0,value=0.0)
                    current=st.number_input("Current",min_value=0.0,value=0.0)
                    target=st.number_input("Target",min_value=0.0,value=0.0)
                    vpu=st.number_input("Value per unit",min_value=0.0,value=0.0)
                if st.form_submit_button("Add Value Driver",use_container_width=True) and name.strip():
                    db_execute("INSERT INTO value_drivers(tenant_id,name,unit,baseline,current_value,target_value,value_per_unit,owner,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",(tenant_id,name.strip(),unit,float(baseline),float(current),float(target),float(vpu),owner.strip() or None,utc_iso(),utc_iso()))
                    audit("VALUE_DRIVER_CREATED","value_driver",name.strip(),{"value_per_unit":vpu})
                    st.rerun()
        with tabs[1]:
            with st.form("scenario_form",clear_on_submit=True):
                name=st.text_input("Scenario name *",value="Base Recovery Case")
                desc=st.text_area("Description",value="Controlled improvement scenario based on measurable recovery assumptions.")
                horizon=st.number_input("Horizon (days)",min_value=1,max_value=3650,value=90)
                probability=st.slider("Probability",0.0,1.0,0.75,0.05)
                if st.form_submit_button("Create Scenario",use_container_width=True) and name.strip():
                    db_execute("INSERT INTO scenarios(tenant_id,name,description,horizon_days,probability,assumptions_json,created_by,created_at) VALUES (?,?,?,?,?,?,?,?)",(tenant_id,name.strip(),desc.strip() or None,int(horizon),float(probability),json.dumps({"governed":True}),st.session_state.username,utc_iso()))
                    audit("SCENARIO_CREATED","scenario",name.strip(),{"probability":probability,"horizon_days":horizon})
                    st.rerun()
            if not scenarios.empty: st.dataframe(scenarios,use_container_width=True,hide_index=True)
            if not scenarios.empty and not drivers.empty:
                sc_opts={f"{r['scenario_id']} — {r['name']}":int(r['scenario_id']) for _,r in scenarios.iterrows()}
                dr_opts={f"{r['driver_id']} — {r['name']}":int(r['driver_id']) for _,r in drivers.iterrows()}
                with st.form("scenario_result_form",clear_on_submit=True):
                    sc=st.selectbox("Scenario",list(sc_opts))
                    dr=st.selectbox("Value driver",list(dr_opts))
                    baseline=st.number_input("Scenario baseline",min_value=0.0,value=0.0)
                    scenario_value=st.number_input("Scenario value",min_value=0.0,value=0.0)
                    notes=st.text_area("Assumption / evidence note")
                    if st.form_submit_button("Calculate & Store Scenario",use_container_width=True):
                        sr=scenarios[scenarios["scenario_id"]==sc_opts[sc]].iloc[0]
                        driver_row=drivers[drivers["driver_id"]==dr_opts[dr]].iloc[0]
                        raw_delta=max(0.0,float(scenario_value)-float(baseline))
                        value_per_unit=float(driver_row.get("value_per_unit") or 0)
                        gross=raw_delta*value_per_unit if value_per_unit > 0 else raw_delta
                        risk_adj=gross*max(0.0,min(1.0,float(sr.get("probability") or 0)))
                        db_execute("INSERT INTO scenario_results(tenant_id,scenario_id,driver_id,baseline_value,scenario_value,gross_value,risk_adjusted_value,notes,created_at) VALUES (?,?,?,?,?,?,?,?,?)",(tenant_id,sc_opts[sc],dr_opts[dr],float(baseline),float(scenario_value),gross,risk_adj,notes.strip() or None,utc_iso()))
                        audit("SCENARIO_CALCULATED","scenario_result",sc_opts[sc],{"gross_value":gross,"risk_adjusted_value":risk_adj})
                        st.rerun()
        with tabs[2]:
            if not results.empty: st.dataframe(results,use_container_width=True,hide_index=True)
    st.info("Financial scenarios are decision-support models. Value is calculated from explicit assumptions and probability; it is not presented as guaranteed revenue or savings.")



def _contract_scope_clause():
    return (st.session_state.get("tenant_id"),)


def _contract_date(value):
    if value is None or str(value).strip() == "":
        return None
    if isinstance(value, (datetime, date)):
        return value.isoformat()[:10]
    parsed = pd.to_datetime(value, errors="coerce")
    if pd.isna(parsed):
        return None
    return parsed.date().isoformat()


def _contract_days_remaining(end_date):
    if not end_date:
        return None
    try:
        return (date.fromisoformat(str(end_date)[:10]) - utc_now().date()).days
    except Exception:
        return None


def _contract_status_from_dates(start_date, end_date, current_status=None):
    if current_status in {"Draft", "Terminated", "Renewal Pending"}:
        return current_status
    today = utc_now().date()
    try:
        start = date.fromisoformat(str(start_date)[:10]) if start_date else None
        end = date.fromisoformat(str(end_date)[:10]) if end_date else None
    except Exception:
        return current_status or "Draft"
    if end and end < today:
        return "Expired"
    if end and (end - today).days <= 90:
        return "Expiring"
    if start and start > today:
        return "Draft"
    return "Active"


def _sla_is_breached(current_value, target_value, direction):
    if current_value is None or target_value is None:
        return False
    if direction == "lower_is_better":
        return float(current_value) > float(target_value)
    return float(current_value) < float(target_value)


def _contract_performance_score(contract_id):
    obligations = db_execute(
        "SELECT status, risk_level FROM contract_obligations WHERE tenant_id = ? AND contract_id = ?",
        (st.session_state.tenant_id, contract_id), fetch=True
    )
    slas = db_execute(
        "SELECT current_value, target_value, direction, status FROM contract_slas WHERE tenant_id = ? AND contract_id = ?",
        (st.session_state.tenant_id, contract_id), fetch=True
    )
    points = []
    for row in obligations:
        status = row["status"]
        points.append({"Completed": 100, "On Track": 100, "Open": 80, "At Risk": 50, "Breached": 0, "Waived": 100}.get(status, 70))
    for row in slas:
        if row["current_value"] is None:
            points.append(70)
        elif _sla_is_breached(row["current_value"], row["target_value"], row["direction"]):
            points.append(0)
        else:
            points.append(100)
    return round(sum(points) / len(points), 1) if points else None


def contract_summary_df_for_tenant(tenant_id):
    rows = db_execute(
        """SELECT * FROM contracts WHERE tenant_id = ? ORDER BY end_date IS NULL, end_date, contract_id DESC""",
        (tenant_id,), fetch=True
    )
    if not rows:
        return pd.DataFrame()

    records = [dict(r) for r in rows]
    ids = [int(r["contract_id"]) for r in records]
    placeholders = ",".join("?" for _ in ids)

    obs = db_execute(
        f"""SELECT contract_id,
                    COALESCE(SUM(CASE WHEN status IN ('At Risk','Breached') THEN value_at_risk ELSE 0 END),0) AS value_at_risk,
                    SUM(CASE WHEN status = 'Breached' THEN 1 ELSE 0 END) AS breached_count,
                    COUNT(*) AS obligation_count,
                    COALESCE(SUM(CASE status WHEN 'Completed' THEN 100 WHEN 'On Track' THEN 100 WHEN 'Open' THEN 80 WHEN 'At Risk' THEN 50 WHEN 'Breached' THEN 0 WHEN 'Waived' THEN 100 ELSE 70 END),0) AS obligation_points
             FROM contract_obligations
             WHERE tenant_id = ? AND contract_id IN ({placeholders})
             GROUP BY contract_id""",
        (tenant_id, *ids), fetch=True
    )
    obs_map = {int(r["contract_id"]): dict(r) for r in obs}

    slas = db_execute(
        f"""SELECT contract_id,
                    SUM(CASE WHEN current_value IS NOT NULL AND ((direction='lower_is_better' AND current_value > target_value) OR (direction!='lower_is_better' AND current_value < target_value)) THEN 1 ELSE 0 END) AS breached_slas,
                    COUNT(*) AS sla_count,
                    COALESCE(SUM(CASE WHEN current_value IS NULL THEN 70 WHEN ((direction='lower_is_better' AND current_value > target_value) OR (direction!='lower_is_better' AND current_value < target_value)) THEN 0 ELSE 100 END),0) AS sla_points
             FROM contract_slas
             WHERE tenant_id = ? AND contract_id IN ({placeholders})
             GROUP BY contract_id""",
        (tenant_id, *ids), fetch=True
    )
    sla_map = {int(r["contract_id"]): dict(r) for r in slas}

    for d in records:
        cid = int(d["contract_id"])
        d["days_remaining"] = _contract_days_remaining(d.get("end_date"))
        d["industry"] = d.get("industry") or "Unassigned"
        o = obs_map.get(cid, {})
        sl = sla_map.get(cid, {})
        d["value_at_risk"] = float(o.get("value_at_risk") or 0)
        d["breached_obligations"] = int(o.get("breached_count") or 0)
        d["breached_slas"] = int(sl.get("breached_slas") or 0)
        obligation_count = int(o.get("obligation_count") or 0)
        sla_count = int(sl.get("sla_count") or 0)
        total_points = float(o.get("obligation_points") or 0) + float(sl.get("sla_points") or 0)
        total_items = obligation_count + sla_count
        d["performance_score"] = round(total_points / total_items, 1) if total_items else None

    return pd.DataFrame(records)


def contract_summary_df():
    return contract_summary_df_for_tenant(st.session_state.tenant_id)


def contract_detail(contract_id):
    rows = db_execute(
        "SELECT * FROM contracts WHERE tenant_id = ? AND contract_id = ?",
        (st.session_state.tenant_id, contract_id), fetch=True
    )
    return dict(rows[0]) if rows else None


def _require_contract_write():
    if st.session_state.get("access_mode") == "customer" or not has_permission("actions"):
        st.error("Contract management changes require an authorized platform user.")
        return False
    return True


def _contract_value_at_risk(contract_id):
    obligations = db_execute(
        "SELECT COALESCE(SUM(value_at_risk),0) AS v FROM contract_obligations WHERE tenant_id = ? AND contract_id = ? AND status IN ('At Risk','Breached')",
        (st.session_state.tenant_id, contract_id), fetch=True
    )
    return float(obligations[0]["v"] or 0) if obligations else 0.0


def _create_contract_action(contract_id, title, owner, priority, due_date, value_at_risk, obligation_id=None):
    contract = contract_detail(contract_id)
    if not contract:
        raise ValueError("Contract not found in the current tenant.")
    partner = contract.get("partner_name") or contract.get("counterparty")
    db_execute(
        """INSERT INTO interventions
        (tenant_id, industry, partner, action, owner, status, priority, target_outcome, due_date, estimated_value, contract_id, obligation_id, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?, ?, ?, ?, ?)""",
        (st.session_state.tenant_id, st.session_state.current_industry, partner, title, owner, priority, "Contract obligation/SLA recovery", _contract_date(due_date), value_at_risk, contract_id, obligation_id, st.session_state.username, utc_iso())
    )
    audit("CONTRACT_ACTION_CREATED", "contract", contract_id, {"title": title, "owner": owner, "priority": priority, "due_date": due_date, "obligation_id": obligation_id, "value_at_risk": value_at_risk})


def _refresh_contract_sla(sla_id):
    rows = db_execute(
        """SELECT s.*, c.industry AS contract_industry
           FROM contract_slas s
           JOIN contracts c ON c.contract_id = s.contract_id AND c.tenant_id = s.tenant_id
          WHERE s.tenant_id = ? AND s.sla_id = ?""",
        (st.session_state.tenant_id, sla_id), fetch=True
    )
    if not rows:
        return None
    sla = dict(rows[0])
    contract_industry = sla.get("contract_industry") or st.session_state.current_industry
    df = get_current_data(contract_industry)
    metric = sla["metric_name"]
    if df.empty or metric not in df.columns:
        return {"status": "Not Measured", "value": None}
    values = pd.to_numeric(df[metric], errors="coerce").dropna()
    if values.empty:
        return {"status": "Not Measured", "value": None}
    value = float(values.mean())
    breached = _sla_is_breached(value, sla["target_value"], sla["direction"])
    status = "Breached" if breached else "Compliant"
    db_execute(
        """UPDATE contract_slas SET current_value = ?, status = ?, last_measured_at = ?, breach_count = CASE WHEN ? = 'Breached' THEN breach_count + 1 ELSE breach_count END WHERE tenant_id = ? AND sla_id = ?""",
        (value, status, utc_iso(), status, st.session_state.tenant_id, sla_id)
    )
    return {"status": status, "value": value}


def _document_cipher():
    if not CONTRACT_DOCUMENT_ENCRYPTION_KEY:
        return None
    if Fernet is None:
        raise RuntimeError("cryptography is required when document encryption is configured.")
    try:
        return Fernet(CONTRACT_DOCUMENT_ENCRYPTION_KEY.encode("utf-8"))
    except Exception as exc:
        raise RuntimeError("PARTNEROPS_DOCUMENT_ENCRYPTION_KEY must be a valid Fernet key.") from exc


def _encrypt_contract_document(raw):
    cipher = _document_cipher()
    if cipher is None:
        raise RuntimeError(
            "Contract document storage is disabled until PARTNEROPS_DOCUMENT_ENCRYPTION_KEY is configured."
        )
    return cipher.encrypt(raw)


def _decrypt_contract_document(blob):
    cipher = _document_cipher()
    if cipher is None:
        return bytes(blob)
    try:
        return cipher.decrypt(bytes(blob))
    except InvalidToken as exc:
        raise RuntimeError("Contract document could not be decrypted with the configured key.") from exc


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
    "current_dataset_id": None,
    "last_snapshot_dataset_id": None,
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



def clear_authenticated_session():
    """Clear authentication/session state without leaving stale tenant scope."""
    for key in DEFAULT_STATE:
        st.session_state[key] = DEFAULT_STATE[key]


def revalidate_platform_session():
    """Re-check platform-user status, tenant status and session lifetime."""
    if not st.session_state.get("authenticated") or st.session_state.get("access_mode") != "platform":
        return
    tenant_id = st.session_state.get("tenant_id")
    username = st.session_state.get("username")
    if not tenant_id or not username:
        clear_authenticated_session()
        st.error("Your session is incomplete. Please sign in again.")
        st.stop()
    rows = db_execute(
        """SELECT u.user_id, u.role, u.status AS user_status, t.status AS tenant_status
           FROM users u JOIN tenants t ON t.tenant_id = u.tenant_id
           WHERE u.tenant_id = ? AND u.username = ? LIMIT 1""",
        (tenant_id, username), fetch=True,
    )
    if not rows or rows[0]["user_status"] != "active" or rows[0]["tenant_status"] != "active":
        audit("PLATFORM_SESSION_REVOKED", "user", username, {"reason": "user_or_tenant_inactive"}, tenant_id=tenant_id, username=username)
        clear_authenticated_session()
        st.error("Your account or tenant is no longer active. Please sign in again.")
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
        audit("PLATFORM_SESSION_EXPIRED", "user", username, {"reason": "session_timeout"}, tenant_id=tenant_id, username=username)
        clear_authenticated_session()
        st.error("Your session expired. Please sign in again.")
        st.stop()
    st.session_state.role = rows[0]["role"]
    st.session_state.last_activity_at = now.isoformat()

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

revalidate_platform_session()

with st.sidebar:
    if st.button("Sign out", use_container_width=True):
        audit(
            "LOGOUT",
            "user",
            st.session_state.get("username") or "customer_link",
            {"access_mode": st.session_state.get("access_mode")},
            tenant_id=st.session_state.get("tenant_id"),
            username=st.session_state.get("username"),
        )
        clear_authenticated_session()
        st.rerun()

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


@st.cache_data(show_spinner=False, ttl=ANALYSIS_CACHE_TTL_SECONDS)
def performance_engine(df, industry):
    """Vectorized performance engine. Cached because it is deterministic for a dataset/config pair."""
    cfg = INDUSTRIES[industry]
    result = df.copy()

    for metric in cfg["weights"]:
        if metric not in result.columns:
            result[metric] = pd.NA

    numeric_cache = {}
    for metric in set(cfg["weights"]) | set(cfg["lower_is_better"]):
        if metric in result.columns:
            numeric_cache[metric] = pd.to_numeric(result[metric], errors="coerce")
            result[metric] = numeric_cache[metric]

    weighted = pd.Series(0.0, index=result.index)
    weight_total = pd.Series(0.0, index=result.index)

    lower_max = {}
    for metric in cfg["lower_is_better"]:
        series = numeric_cache.get(metric)
        lower_max[metric] = float(series.max()) if series is not None and series.notna().any() else 1.0

    for metric, weight in cfg["weights"].items():
        if metric not in result.columns:
            continue
        values = numeric_cache.get(metric, pd.to_numeric(result[metric], errors="coerce"))
        valid = values.notna()
        if not valid.any():
            continue

        if metric in cfg["lower_is_better"]:
            if metric in {"pending", "backlog", "aging"}:
                maximum = lower_max.get(metric, 1.0)
                if maximum > 0:
                    metric_score = (100.0 * (maximum - values) / maximum).clip(0, 100)
                else:
                    metric_score = pd.Series(100.0, index=result.index)
            else:
                target = float(cfg["target"])
                metric_score = (100.0 * target / values.replace(0, pd.NA)).clip(0, 100)
                metric_score = metric_score.fillna(100.0)
        else:
            target = float(cfg["target"])
            metric_score = (100.0 * values / target).clip(0, 100)

        metric_score = metric_score.where(valid)
        weighted = weighted.add(metric_score.fillna(0.0) * float(weight), fill_value=0.0)
        weight_total = weight_total.add(valid.astype(float) * float(weight), fill_value=0.0)

    result["performance_score"] = (weighted.div(weight_total.replace(0, pd.NA)).fillna(0).clip(0, 100)).round(2)
    result["target"] = cfg["target"]

    primary = cfg["primary_kpi"]
    primary_values = pd.to_numeric(result[primary], errors="coerce") if primary in result.columns else pd.Series(float("nan"), index=result.index)
    result["target_gap"] = (float(cfg["target"]) - primary_values).round(2)

    score = result["performance_score"]
    result["band"] = score.map(score_band)
    result["risk"] = score.map(risk_band)
    result["attention_required"] = score < float(cfg["target"])

    # These are decision-language functions, so retain their behavior while
    # limiting expensive work to the already-small number of output rows.
    result["diagnosis"] = result.apply(lambda r: diagnosis_for_row(r, cfg), axis=1)
    result["recommended_action"] = result.apply(lambda r: recommended_action(r, cfg), axis=1)

    if "output" in result.columns:
        output = pd.to_numeric(result["output"], errors="coerce").fillna(0)
        result["recovery_opportunity"] = (result["target_gap"].clip(lower=0) * output / 100).round(2)
    else:
        result["recovery_opportunity"] = 0.0

    result["priority"] = pd.cut(
        score,
        bins=[-float("inf"), 50, 70, 80, float("inf")],
        labels=["P1", "P2", "P3", "P4"],
        right=False,
    ).astype(str)
    result["rank"] = score.rank(ascending=False, method="min").fillna(len(result) + 1).astype(int)

    return result.sort_values("performance_score", ascending=False).reset_index(drop=True)


# ============================================================
# 16. SNAPSHOTS
# ============================================================

def save_snapshot(df, industry, tenant_id, dataset_id=None):
    """Persist one daily snapshot per tenant/industry/partner, not per Streamlit rerun."""
    if df is None or df.empty:
        return

    snapshot_date = utc_now().date().isoformat()
    primary = INDUSTRIES[industry]["primary_kpi"]
    work = df.copy()
    if "partner" not in work.columns:
        return

    work["partner"] = work["partner"].astype(str).str.strip()
    work = work[work["partner"] != ""]

    records = []
    for row in work[["partner", primary, "performance_score", "risk", "band"]].itertuples(index=False, name=None):
        partner, primary_value, score, risk, band = row
        records.append((
            tenant_id, industry, snapshot_date, partner,
            float(primary_value) if pd.notna(primary_value) else None,
            float(score) if pd.notna(score) else None,
            risk, band,
        ))

    if not records:
        return

    db_execute(
        """
        INSERT OR IGNORE INTO snapshots
        (tenant_id, industry, snapshot_date, partner, primary_kpi, performance_score, risk, band)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        records,
        many=True,
    )

    if dataset_id is not None:
        st.session_state.last_snapshot_dataset_id = int(dataset_id)


# ============================================================
# 17. TREND ENGINE
# ============================================================

@st.cache_data(show_spinner=False, ttl=ANALYSIS_CACHE_TTL_SECONDS)
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

@st.cache_data(show_spinner=False, ttl=ANALYSIS_CACHE_TTL_SECONDS)
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

@st.cache_data(show_spinner=False, ttl=ANALYSIS_CACHE_TTL_SECONDS)
def predictive_risk(df, industry):
    """Vectorized leading-indicator risk model."""
    result = df.copy()
    score = pd.to_numeric(result.get("performance_score", pd.Series(0, index=result.index)), errors="coerce").fillna(0)
    risk = pd.Series(0.0, index=result.index)
    reason_parts = pd.DataFrame(index=result.index)

    critical = score < 50
    high = (score >= 50) & (score < 70)
    moderate = (score >= 70) & (score < 80)
    risk += critical.astype(float) * 50 + high.astype(float) * 30 + moderate.astype(float) * 15
    reason_parts["performance"] = pd.Series("", index=result.index)
    reason_parts.loc[critical, "performance"] = "critical current performance"
    reason_parts.loc[high, "performance"] = "high performance risk"
    reason_parts.loc[moderate, "performance"] = "performance below strong range"

    pending = pd.to_numeric(result.get("pending", pd.Series(float("nan"), index=result.index)), errors="coerce")
    pending_pressure = pending.div(10).clip(upper=20).fillna(0)
    risk += pending_pressure
    reason_parts["pending"] = pending_pressure.gt(0).map({True: "open workload", False: ""})

    aging = pd.to_numeric(result.get("aging", pd.Series(float("nan"), index=result.index)), errors="coerce")
    aging_pressure = aging.where(aging > 7, 0).clip(upper=20).fillna(0)
    risk += aging_pressure
    reason_parts["aging"] = aging_pressure.gt(0).map({True: "aging workload", False: ""})

    quality = pd.to_numeric(result.get("quality", pd.Series(float("nan"), index=result.index)), errors="coerce")
    quality_pressure = quality.lt(80).fillna(False).astype(float) * 10
    risk += quality_pressure
    reason_parts["quality"] = quality_pressure.gt(0).map({True: "quality pressure", False: ""})

    result["predictive_risk_score"] = risk.clip(upper=100).round(2)
    result["predicted_risk"] = pd.cut(
        result["predictive_risk_score"],
        bins=[-float("inf"), 20, 45, 70, float("inf")],
        labels=["Low", "Moderate", "Elevated", "Severe"],
        right=False,
    ).astype(str)

    def join_reasons(row):
        values = [str(v) for v in row if str(v).strip()]
        return ", ".join(values) if values else "No major leading indicators detected."

    result["risk_drivers"] = reason_parts.apply(join_reasons, axis=1)
    return result


# ============================================================
# 20. COMMERCIAL VALUE ENGINE
# ============================================================

@st.cache_data(show_spinner=False, ttl=ANALYSIS_CACHE_TTL_SECONDS)
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

        records = df.to_dict(orient="records")
        for start_idx in range(0, len(records), MAX_DATASET_INSERT_BATCH):
            batch = records[start_idx:start_idx + MAX_DATASET_INSERT_BATCH]
            payloads = [
                (dataset_id, tenant_id, industry, json.dumps(row, default=str))
                for row in batch
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

    try:
        st.cache_data.clear()
    except Exception:
        pass

    audit(
        "DATASET_UPLOADED",
        "dataset",
        dataset_id,
        {"filename": filename, "rows": len(df), "quality": quality_status},
    )
    return dataset_id


@st.cache_data(show_spinner=False, ttl=ANALYSIS_CACHE_TTL_SECONDS)
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
        rows = db_execute(
            "SELECT dataset_id FROM datasets WHERE tenant_id = ? AND industry = ? ORDER BY dataset_id DESC LIMIT 1",
            (st.session_state.tenant_id, industry), fetch=True
        )
        st.session_state.current_dataset_id = int(rows[0]["dataset_id"]) if rows else None
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

    dataset_id = save_dataset(
        normalized,
        str(filename)[:255],
        quality["status"],
        industry,
    )
    st.session_state.current_dataset_id = dataset_id
    st.session_state.last_snapshot_dataset_id = None

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
        "Third-Party Risk",
        "Process Intelligence",
        "Knowledge & Agents",
        "Value & Scenarios",
    ]
    if not module_enabled(st.session_state.get("tenant_id"), "partner_performance"):
        page_options = []
    if module_enabled(st.session_state.get("tenant_id"), "contract_intelligence"):
        page_options.append("Contract Management")
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
        "Third-Party Risk",
        "Process Intelligence",
        "Knowledge & Agents",
        "Value & Scenarios",
        "Administration",
    ]
    if not module_enabled(st.session_state.get("tenant_id"), "partner_performance"):
        page_options = [p for p in page_options if p in ("Administration", "Contract Management", "Third-Party Risk", "Process Intelligence", "Knowledge & Agents", "Value & Scenarios")]
    if module_enabled(st.session_state.get("tenant_id"), "contract_intelligence"):
        page_options.insert(-1, "Contract Management")

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

    checked = _validate_upload_dataframe(result)
    if len(checked) * max(1, len(checked.columns)) > MAX_UPLOAD_CELLS:
        raise ValueError(
            f"Dataset contains {len(checked) * max(1, len(checked.columns)):,} cells; "
            f"the safe processing limit is {MAX_UPLOAD_CELLS:,}."
        )
    return checked


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

# Phase 1-4 workspaces are independently operable and therefore do not pass
# through the legacy operational-data quality gate. This preserves the CMS
# independence model while allowing the new control modules to operate with
# their own evidence stores.
if page == "Third-Party Risk":
    phase1_tprm_page()
    st.stop()

if page == "Process Intelligence":
    phase2_process_page()
    st.stop()

if page == "Knowledge & Agents":
    phase3_knowledge_page()
    st.stop()

if page == "Value & Scenarios":
    phase4_value_page()
    st.stop()

if page == "Contract Management":
    # CMS is independently operable. It must not require an operational
    # performance dataset merely to open the contract workspace.
    raw_df = pd.DataFrame()
    performance_df = pd.DataFrame()
    predictive_df = pd.DataFrame()
    anomalies_df = pd.DataFrame()
else:
    raw_df = get_current_data(industry)

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

    current_dataset_id = st.session_state.get("current_dataset_id")
    if (
        current_dataset_id is not None
        and st.session_state.get("last_snapshot_dataset_id") != current_dataset_id
    ):
        save_snapshot(
            performance_df,
            industry,
            st.session_state.tenant_id,
            dataset_id=current_dataset_id,
        )


# ============================================================
# 28. COMMAND CENTER
# ============================================================

if page == "Contract Management":

    if not module_enabled(st.session_state.get("tenant_id"), "contract_intelligence"):
        st.error("Contract Intelligence is not enabled for this customer.")
        st.stop()

    st.title("📑 Contract Management & Contract Intelligence")
    st.caption("Contract → Obligation → SLA → Performance → Risk → Action → Outcome → Value")

    customer_view = st.session_state.get("access_mode") == "customer"
    contracts_df = contract_summary_df()

    # Executive contract control strip
    active_count = int((contracts_df["status"] == "Active").sum()) if not contracts_df.empty else 0
    expiring_count = int(contracts_df["status"].isin(["Expiring", "Renewal Pending"]).sum()) if not contracts_df.empty else 0
    breached_count = int(contracts_df["breached_obligations"].sum()) if not contracts_df.empty and "breached_obligations" in contracts_df.columns else 0
    value_at_risk = float(contracts_df["value_at_risk"].sum()) if not contracts_df.empty and "value_at_risk" in contracts_df.columns else 0.0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Contracts", len(contracts_df))
    c2.metric("Active", active_count)
    c3.metric("Renewal / Expiry Watch", expiring_count)
    c4.metric("Value at Risk", f"KES {value_at_risk:,.0f}")

    if not contracts_df.empty:
        st.subheader("Contract Portfolio")
        view_cols = [c for c in ["contract_number", "title", "counterparty", "partner_name", "industry", "status", "start_date", "end_date", "days_remaining", "risk_level", "currency", "contract_value", "performance_score"] if c in contracts_df.columns]
        st.dataframe(contracts_df[view_cols], use_container_width=True, hide_index=True)

    if not customer_view and _require_contract_write():
        st.divider()
        st.subheader("Create Contract")
        with st.form("create_contract_form", clear_on_submit=True):
            a, b = st.columns(2)
            with a:
                contract_number = st.text_input("Contract number *")
                contract_title = st.text_input("Contract title *")
                counterparty = st.text_input("Counterparty / legal entity *")
                partner_name = st.text_input("Operational partner (optional)")
                contract_type = st.selectbox("Contract type", ["Service Agreement", "Master Service Agreement", "Vendor", "Contractor", "Distribution", "SLA", "Lease", "Employment", "Other"])
                contract_industry = st.selectbox("Operational industry", ["Unassigned"] + list(INDUSTRIES.keys()), index=(1 + list(INDUSTRIES.keys()).index(st.session_state.current_industry)) if st.session_state.current_industry in INDUSTRIES else 0)
                contract_status = st.selectbox("Initial status", CONTRACT_STATUSES)
            with b:
                start_date = st.date_input("Start date", value=utc_now().date())
                end_date = st.date_input("End date", value=utc_now().date() + timedelta(days=365))
                auto_renew = st.checkbox("Auto-renewal")
                notice_days = st.number_input("Notice period (days)", min_value=0, max_value=3650, value=30)
                currency = st.selectbox("Currency", ["KES", "USD", "EUR", "GBP", "AED", "Other"])
                contract_value = st.number_input("Contract value", min_value=0.0, value=0.0, step=1000.0)
                owner = st.text_input("Contract owner")
                risk_level = st.selectbox("Initial risk", CONTRACT_RISK_LEVELS, index=1)
            governing_law = st.text_input("Governing law / jurisdiction", value="Kenya")
            summary = st.text_area("Commercial / operational summary")
            create_contract = st.form_submit_button("Create Contract", use_container_width=True)
            if create_contract:
                if not contract_number.strip() or not contract_title.strip() or not counterparty.strip():
                    st.error("Contract number, title and counterparty are required.")
                elif end_date < start_date:
                    st.error("End date cannot be before start date.")
                else:
                    try:
                        db_execute("""INSERT INTO contracts
                        (tenant_id, contract_number, title, counterparty, partner_name, industry, contract_type, status, start_date, end_date, auto_renew, notice_days, currency, contract_value, owner, governing_law, risk_level, summary, created_by, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (st.session_state.tenant_id, contract_number.strip(), contract_title.strip(), counterparty.strip(), partner_name.strip() or None, None if contract_industry == "Unassigned" else contract_industry, contract_type, contract_status, _contract_date(start_date), _contract_date(end_date), int(auto_renew), int(notice_days), currency, float(contract_value), owner.strip() or None, governing_law.strip() or None, risk_level, summary.strip() or None, st.session_state.username, utc_iso(), utc_iso()))
                        audit("CONTRACT_CREATED", "contract", contract_number.strip(), {"title": contract_title, "counterparty": counterparty})
                        st.success("Contract created.")
                        st.rerun()
                    except sqlite3.IntegrityError:
                        st.error("That contract number already exists for this customer.")

    if contracts_df.empty:
        st.info("No contracts are registered yet. Create a contract above or use the import-ready database/API layer for onboarding.")
    else:
        selected_options = {f"{r['contract_number']} — {r['title']}": int(r['contract_id']) for _, r in contracts_df.iterrows()}
        selected_label = st.selectbox("Open contract", list(selected_options.keys()))
        contract_id = selected_options[selected_label]
        contract = contract_detail(contract_id)
        if not contract:
            st.error("Contract is no longer available in this tenant scope.")
            st.stop()

        score = _contract_performance_score(contract_id)
        risk_value = _contract_value_at_risk(contract_id)
        days_remaining = _contract_days_remaining(contract.get("end_date"))
        if days_remaining is not None and days_remaining <= int(contract.get("notice_days") or 0) and contract.get("status") not in ["Expired", "Terminated"]:
            derived_status = "Renewal Pending"
        else:
            derived_status = _contract_status_from_dates(contract.get("start_date"), contract.get("end_date"), contract.get("status"))

        h1, h2, h3, h4 = st.columns(4)
        h1.metric("Contract Health", f"{score:.1f}%" if score is not None else "Not measured")
        h2.metric("Days Remaining", days_remaining if days_remaining is not None else "—")
        h3.metric("Value at Risk", f"{contract.get('currency','KES')} {risk_value:,.0f}")
        h4.metric("Lifecycle", derived_status)

        tabs = st.tabs(["Overview", "Obligations", "SLAs", "Events & Renewals", "Documents", "Compliance", "Actions"])

        with tabs[0]:
            st.subheader(f"{contract['contract_number']} — {contract['title']}")
            overview = pd.DataFrame([
                {"Field": "Counterparty", "Value": contract.get("counterparty")},
                {"Field": "Operational Partner", "Value": contract.get("partner_name") or "—"},
                {"Field": "Type", "Value": contract.get("contract_type")},
                {"Field": "Status", "Value": derived_status},
                {"Field": "Term", "Value": f"{contract.get('start_date') or '—'} → {contract.get('end_date') or '—'}"},
                {"Field": "Auto Renewal", "Value": "Yes" if contract.get("auto_renew") else "No"},
                {"Field": "Notice Period", "Value": f"{contract.get('notice_days') or 0} days"},
                {"Field": "Owner", "Value": contract.get("owner") or "—"},
                {"Field": "Governing Law", "Value": contract.get("governing_law") or "—"},
                {"Field": "Contract Value", "Value": f"{contract.get('currency','KES')} {float(contract.get('contract_value') or 0):,.2f}"},
                {"Field": "Risk", "Value": contract.get("risk_level")},
            ])
            st.dataframe(overview, use_container_width=True, hide_index=True)
            if contract.get("summary"):
                st.markdown("**Summary**")
                st.write(contract["summary"])
            if not customer_view and _require_contract_write():
                if st.button("Recalculate Lifecycle Status", key=f"refresh_contract_{contract_id}"):
                    db_execute("UPDATE contracts SET status = ?, updated_at = ? WHERE tenant_id = ? AND contract_id = ?", (derived_status, utc_iso(), st.session_state.tenant_id, contract_id))
                    audit("CONTRACT_STATUS_RECALCULATED", "contract", contract_id, {"status": derived_status})
                    st.rerun()

        with tabs[1]:
            st.subheader("Obligation Register")
            obligations = db_execute("SELECT * FROM contract_obligations WHERE tenant_id = ? AND contract_id = ? ORDER BY due_date IS NULL, due_date, obligation_id", (st.session_state.tenant_id, contract_id), fetch=True)
            odf = pd.DataFrame([dict(r) for r in obligations])
            if not odf.empty:
                st.dataframe(odf, use_container_width=True, hide_index=True)
            else:
                st.info("No obligations recorded yet.")
            if not customer_view and _require_contract_write():
                with st.form(f"obligation_form_{contract_id}", clear_on_submit=True):
                    a,b = st.columns(2)
                    with a:
                        ot = st.text_input("Obligation title *")
                        desc = st.text_area("Description")
                        party = st.selectbox("Responsible party", ["Our organization", "Counterparty", "Operational partner", "Shared / joint"])
                        owner_o = st.text_input("Action owner")
                        due = st.date_input("Due date", value=utc_now().date())
                        recurrence = st.selectbox("Recurrence", ["One-off", "Daily", "Weekly", "Monthly", "Quarterly", "Annual"])
                    with b:
                        target = st.number_input("Target value", value=0.0)
                        unit = st.text_input("Unit", value="%")
                        evidence = st.text_input("Evidence required")
                        ostatus = st.selectbox("Status", OBLIGATION_STATUSES)
                        orisk = st.selectbox("Risk", CONTRACT_RISK_LEVELS, index=1)
                        var = st.number_input("Value at risk", min_value=0.0, value=0.0, step=1000.0)
                        next_due = st.date_input("Next due date", value=due)
                    notes = st.text_area("Notes")
                    add_obligation = st.form_submit_button("Add Obligation", use_container_width=True)
                    if add_obligation:
                        if not ot.strip():
                            st.error("Obligation title is required.")
                        else:
                            db_execute("""INSERT INTO contract_obligations
                            (tenant_id, contract_id, obligation_title, description, responsible_party, owner, due_date, recurrence, target_value, unit, evidence_required, status, risk_level, value_at_risk, next_due_date, notes, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (st.session_state.tenant_id, contract_id, ot.strip(), desc.strip() or None, party, owner_o.strip() or None, _contract_date(due), recurrence, float(target), unit.strip() or None, evidence.strip() or None, ostatus, orisk, float(var), _contract_date(next_due), notes.strip() or None, utc_iso()))
                            audit("CONTRACT_OBLIGATION_CREATED", "contract_obligation", contract_id, {"title": ot, "status": ostatus, "value_at_risk": var})
                            st.success("Obligation added.")
                            st.rerun()

        with tabs[2]:
            st.subheader("SLA Register & Operational Measurement")
            slas = db_execute("SELECT * FROM contract_slas WHERE tenant_id = ? AND contract_id = ? ORDER BY sla_id", (st.session_state.tenant_id, contract_id), fetch=True)
            sdf = pd.DataFrame([dict(r) for r in slas])
            if not sdf.empty:
                st.dataframe(sdf, use_container_width=True, hide_index=True)
            else:
                st.info("No SLAs mapped to this contract yet.")
            if not customer_view and _require_contract_write():
                with st.form(f"sla_form_{contract_id}", clear_on_submit=True):
                    a,b = st.columns(2)
                    with a:
                        sn = st.text_input("SLA name *")
                        metric = st.text_input("PartnerOps metric / dataset column *", placeholder="completion_rate")
                        target = st.number_input("Target", value=90.0)
                        direction = st.selectbox("Performance direction", SLA_DIRECTIONS)
                        unit = st.text_input("Unit", value="%")
                    with b:
                        period = st.selectbox("Measurement period", ["Daily", "Weekly", "Monthly", "Quarterly"])
                        grace = st.number_input("Grace period (days)", min_value=0, max_value=365, value=0)
                        penalty = st.number_input("Penalty rate", min_value=0.0, value=0.0, help="Store as a rate/percentage defined by the contract; calculation is informational until configured.")
                        notes = st.text_area("SLA notes")
                    add_sla = st.form_submit_button("Add SLA", use_container_width=True)
                    if add_sla:
                        if not sn.strip() or not metric.strip():
                            st.error("SLA name and metric are required.")
                        else:
                            db_execute("""INSERT INTO contract_slas
                            (tenant_id, contract_id, sla_name, metric_name, target_value, direction, unit, measurement_period, grace_period_days, penalty_rate, notes, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (st.session_state.tenant_id, contract_id, sn.strip(), metric.strip().lower(), float(target), direction, unit.strip() or "%", period, int(grace), float(penalty), notes.strip() or None, utc_iso()))
                            audit("CONTRACT_SLA_CREATED", "contract_sla", contract_id, {"name": sn, "metric": metric, "target": target})
                            st.success("SLA added.")
                            st.rerun()
            if not sdf.empty:
                st.caption("SLA measurement uses the currently loaded PartnerOps dataset. It is a controlled operational signal, not a claim of legal compliance.")
                for _, row in sdf.iterrows():
                    if st.button(f"Measure {row['sla_name']}", key=f"measure_sla_{int(row['sla_id'])}", use_container_width=True):
                        result = _refresh_contract_sla(int(row["sla_id"]))
                        audit("CONTRACT_SLA_MEASURED", "contract_sla", int(row["sla_id"]), result or {})
                        if result and result.get("status") == "Breached":
                            st.warning(f"SLA breach signal detected: {result.get('value'):.2f} vs target {row['target_value']:.2f}.")
                        elif result and result.get("value") is not None:
                            st.success(f"Measured {result.get('value'):.2f}; target {row['target_value']:.2f}.")
                        else:
                            st.info("The current dataset cannot measure this SLA yet.")
                        st.rerun()

        with tabs[3]:
            st.subheader("Events, Notices, Amendments & Renewals")
            events = db_execute("SELECT * FROM contract_events WHERE tenant_id = ? AND contract_id = ? ORDER BY event_date DESC, event_id DESC", (st.session_state.tenant_id, contract_id), fetch=True)
            edf = pd.DataFrame([dict(r) for r in events])
            if not edf.empty:
                st.dataframe(edf, use_container_width=True, hide_index=True)
            else:
                st.info("No contract events recorded.")
            if not customer_view and _require_contract_write():
                with st.form(f"event_form_{contract_id}", clear_on_submit=True):
                    a,b = st.columns(2)
                    with a:
                        etype = st.selectbox("Event type", ["Renewal", "Notice", "Amendment", "Review", "Breach", "Meeting", "Milestone", "Other"])
                        edate = st.date_input("Event date", value=utc_now().date())
                        etitle = st.text_input("Event title *")
                    with b:
                        eowner = st.text_input("Owner")
                        estatus = st.selectbox("Event status", ["Open", "In Progress", "Completed", "Cancelled"])
                    edesc = st.text_area("Description")
                    add_event = st.form_submit_button("Record Event", use_container_width=True)
                    if add_event:
                        if not etitle.strip():
                            st.error("Event title is required.")
                        else:
                            db_execute("""INSERT INTO contract_events
                            (tenant_id, contract_id, event_type, event_date, title, description, owner, status, created_by, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (st.session_state.tenant_id, contract_id, etype, _contract_date(edate), etitle.strip(), edesc.strip() or None, eowner.strip() or None, estatus, st.session_state.username, utc_iso()))
                            audit("CONTRACT_EVENT_CREATED", "contract_event", contract_id, {"type": etype, "title": etitle})
                            st.success("Contract event recorded.")
                            st.rerun()

        with tabs[4]:
            st.subheader("Contract Document Register")
            docs = db_execute("SELECT document_id, filename, mime_type, file_size, sha256, uploaded_by, uploaded_at FROM contract_documents WHERE tenant_id = ? AND contract_id = ? ORDER BY document_id DESC", (st.session_state.tenant_id, contract_id), fetch=True)
            ddf = pd.DataFrame([dict(r) for r in docs])
            if not ddf.empty:
                st.dataframe(ddf, use_container_width=True, hide_index=True)
            else:
                st.info("No contract documents stored.")
            if not customer_view and _require_contract_write():
                doc = st.file_uploader("Upload contract document (pilot vault)", type=["pdf", "docx", "txt", "png", "jpg", "jpeg"], key=f"contract_doc_{contract_id}")
                st.caption("Pilot storage uses tenant-scoped SQLite BLOB storage. For production, move document content to encrypted object storage and retain the SHA-256 integrity record here.")
                if doc and st.button("Store Contract Document", key=f"store_doc_{contract_id}", use_container_width=True):
                    raw = doc.getvalue()
                    if len(raw) > CONTRACT_DOCUMENT_MAX_BYTES:
                        st.error("Contract document exceeds the 10 MB pilot document limit.")
                    else:
                        digest = hashlib.sha256(raw).hexdigest()
                        try:
                            stored_content = _encrypt_contract_document(raw)
                        except RuntimeError as exc:
                            st.error(str(exc))
                            stored_content = None
                        if stored_content is not None:
                            db_execute("""INSERT INTO contract_documents
                            (tenant_id, contract_id, filename, mime_type, file_size, sha256, content, uploaded_by, uploaded_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (st.session_state.tenant_id, contract_id, doc.name[:255], doc.type, len(raw), digest, sqlite3.Binary(stored_content), st.session_state.username, utc_iso()))
                            audit("CONTRACT_DOCUMENT_UPLOADED", "contract_document", contract_id, {"filename": doc.name, "sha256": digest, "size": len(raw)})
                            st.success("Document stored with integrity hash.")
                            st.rerun()
            if not ddf.empty:
                chosen_doc = st.selectbox("Document to download", [f"{int(r['document_id'])} — {r['filename']}" for _, r in ddf.iterrows()], key=f"download_doc_{contract_id}")
                doc_id = int(chosen_doc.split(" — ", 1)[0])
                row = db_execute("SELECT filename, mime_type, content, sha256 FROM contract_documents WHERE tenant_id = ? AND contract_id = ? AND document_id = ?", (st.session_state.tenant_id, contract_id, doc_id), fetch=True)
                if row and row[0]["content"] is not None:
                    try:
                        download_bytes = _decrypt_contract_document(row[0]["content"])
                    except RuntimeError as exc:
                        st.error(str(exc))
                        download_bytes = None
                    if download_bytes is not None:
                        if hashlib.sha256(download_bytes).hexdigest() != row[0]["sha256"]:
                            st.error("Document integrity check failed. Download has been blocked.")
                        else:
                            st.download_button("Download selected document", data=download_bytes, file_name=row[0]["filename"], mime=row[0]["mime_type"] or "application/octet-stream", use_container_width=True)

        with tabs[5]:
            st.subheader("Compliance & Contract Reviews")
            reviews = db_execute("SELECT * FROM contract_reviews WHERE tenant_id = ? AND contract_id = ? ORDER BY review_date DESC, review_id DESC", (st.session_state.tenant_id, contract_id), fetch=True)
            rdf = pd.DataFrame([dict(r) for r in reviews])
            if not rdf.empty:
                st.dataframe(rdf, use_container_width=True, hide_index=True)
            else:
                st.info("No compliance reviews recorded.")
            if not customer_view and _require_contract_write():
                with st.form(f"review_form_{contract_id}", clear_on_submit=True):
                    a,b = st.columns(2)
                    with a:
                        rtype = st.selectbox("Review type", ["Quarterly", "Annual", "Pre-Renewal", "SLA", "Compliance", "Incident", "Other"])
                        rdate = st.date_input("Review date", value=utc_now().date())
                        reviewer = st.text_input("Reviewer *")
                    with b:
                        result = st.selectbox("Result", ["Compliant", "Partially Compliant", "Non-Compliant", "Pending Evidence"])
                        rstatus = st.selectbox("Review status", ["Open", "In Progress", "Closed"])
                    findings = st.text_area("Findings")
                    remediation = st.text_area("Remediation / required action")
                    add_review = st.form_submit_button("Record Review", use_container_width=True)
                    if add_review:
                        if not reviewer.strip():
                            st.error("Reviewer is required.")
                        else:
                            db_execute("""INSERT INTO contract_reviews
                            (tenant_id, contract_id, review_type, review_date, reviewer, result, findings, remediation, status, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (st.session_state.tenant_id, contract_id, rtype, _contract_date(rdate), reviewer.strip(), result, findings.strip() or None, remediation.strip() or None, rstatus, utc_iso()))
                            audit("CONTRACT_REVIEW_CREATED", "contract_review", contract_id, {"type": rtype, "result": result})
                            st.success("Review recorded.")
                            st.rerun()

        with tabs[6]:
            st.subheader("Contract Recovery Actions")
            at_risk = db_execute("SELECT * FROM contract_obligations WHERE tenant_id = ? AND contract_id = ? AND status IN ('At Risk','Breached') ORDER BY value_at_risk DESC", (st.session_state.tenant_id, contract_id), fetch=True)
            if at_risk:
                risk_df = pd.DataFrame([dict(r) for r in at_risk])
                st.dataframe(risk_df, use_container_width=True, hide_index=True)
                if not customer_view and _require_contract_write():
                    for row in at_risk:
                        if st.button(f"Create PartnerOps action: {row['obligation_title']}", key=f"contract_action_{row['obligation_id']}", use_container_width=True):
                            priority = "Critical" if row["status"] == "Breached" or row["risk_level"] == "Critical" else "High"
                            _create_contract_action(contract_id, f"Resolve contract obligation: {row['obligation_title']}", row["owner"] or contract.get("owner") or st.session_state.username, priority, row["next_due_date"] or row["due_date"], float(row["value_at_risk"] or 0), obligation_id=int(row["obligation_id"]))
                            st.success("Recovery action created in PartnerOps Action Management.")
            else:
                st.success("No contract obligations are currently marked At Risk or Breached.")

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
            "Modules",
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
                    for module_key in ("partner_performance", "contract_intelligence"):
                        db_execute(
                            "INSERT OR IGNORE INTO tenant_modules(tenant_id, module_key, enabled) VALUES (?, ?, 1)",
                            (tenant_id, module_key),
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
    # MODULE ENTITLEMENTS
    # --------------------------------------------------------

    with tabs[1]:
        st.subheader("Customer Module Entitlements")
        st.caption("Partner Performance and Contract Intelligence can be sold and operated independently for each tenant.")
        module_tenants = db_execute("SELECT tenant_id, tenant_name FROM tenants ORDER BY tenant_name", fetch=True)
        module_choices = {row["tenant_name"]: row["tenant_id"] for row in module_tenants}
        if module_choices:
            module_customer_name = st.selectbox("Customer", list(module_choices.keys()), key="module_customer")
            module_customer_id = module_choices[module_customer_name]
            for module_key, module_label in (("partner_performance", "Partner Performance Intelligence"), ("contract_intelligence", "Contract Intelligence / CMS")):
                enabled = module_enabled(module_customer_id, module_key)
                new_value = st.checkbox(module_label, value=enabled, key=f"module_{module_customer_id}_{module_key}")
                if new_value != enabled:
                    db_execute("""INSERT INTO tenant_modules(tenant_id, module_key, enabled) VALUES (?, ?, ?)
                                   ON CONFLICT(tenant_id, module_key) DO UPDATE SET enabled = excluded.enabled""", (module_customer_id, module_key, int(new_value)))
                    audit("MODULE_ENTITLEMENT_CHANGED", "tenant", module_customer_id, {"module": module_key, "enabled": new_value})
                    st.rerun()

    # --------------------------------------------------------
    # INDUSTRY ENTITLEMENTS
    # --------------------------------------------------------

    with tabs[2]:

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

    with tabs[3]:

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

    with tabs[4]:

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

    with tabs[5]:

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

    with tabs[6]:

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

    with tabs[7]:

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

    with tabs[8]:

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
    "PartnerOps 5.5 Phase 1-4 Control Platform"
)

st.sidebar.caption(
    "Operational intelligence → recovery action → measurable value"
)
