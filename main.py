import os
import json
import gc
import asyncio
import logging
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from typing import List, Dict, Optional, Any
from contextlib import asynccontextmanager
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

import aiohttp
from bs4 import BeautifulSoup
import markdownify
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks, Request, Depends, Header
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

try:
    import stripe
except ImportError:
    stripe = None

try:
    import jwt
except ImportError:
    jwt = None

try:
    from passlib.context import CryptContext
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
except ImportError:
    pwd_ctx = None

try:
    import ollama
    _ollama_module = ollama
except ImportError:
    _ollama_module = None

# Only use mock when the ollama package is not installed; otherwise we try real Ollama first
OLLAMA_PACKAGE_AVAILABLE = _ollama_module is not None

# ============== CONFIG ==============
DB_FILE = "pricing_intel.db"
JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_DAYS = 7
LOGIN_RATE_LIMIT = 5  # per IP per hour
LOGIN_RATE_WINDOW_SEC = 3600
_login_attempts: Dict[str, List[float]] = {}  # ip -> list of timestamps
import threading
_login_lock = threading.Lock()


def _login_rate_limit_check(ip: str) -> bool:
    """Return True if IP is under limit (can attempt login), False if rate limited."""
    now = time.time()
    cutoff = now - LOGIN_RATE_WINDOW_SEC
    with _login_lock:
        attempts = _login_attempts.get(ip, [])
        attempts = [t for t in attempts if t > cutoff]
        if len(attempts) >= LOGIN_RATE_LIMIT:
            return False
        _login_attempts[ip] = attempts
    return True


def _login_rate_limit_record(ip: str) -> None:
    """Record a failed login attempt for IP."""
    now = time.time()
    with _login_lock:
        attempts = _login_attempts.get(ip, [])
        attempts.append(now)
        attempts = [t for t in attempts if t > now - LOGIN_RATE_WINDOW_SEC]
        _login_attempts[ip] = attempts
MODEL_NAME = "llama3.1:8b"  # 8GB RAM usage, leaves 8GB for system
USE_MOCK_LLM = os.environ.get("USE_MOCK_LLM", "").lower() in ("1", "true", "yes")
TEST_MODE = os.environ.get("TEST_MODE", "").lower() in ("1", "true", "yes")  # Skip Ollama, simulate 1s per agent
HEARTBEAT_INTERVAL = 5
HEARTBEAT_TIMEOUT_CLIENT = 10  # Client shows "Connection lost" after this many seconds without message

# Kill-switch: exclude entities where analysis is not offered (limited public data)
EXCLUDED_COMPANIES: List[str] = []  # Add known litigators if discovered (e.g. domain slugs)
EXCLUDED_INDUSTRIES: List[str] = ["defense", "intelligence", "government"]
EXCLUSION_MESSAGE = "Analysis unavailable for this entity due to limited public data."


def _is_excluded(url: str) -> bool:
    """Return True if URL/domain matches excluded companies or industries."""
    domain = _domain_from_url(url) if url else ""
    if not domain:
        return False
    slug = domain.split(".")[0] if "." in domain else domain
    slug_lower = slug.lower()
    for c in EXCLUDED_COMPANIES:
        if c.lower() in slug_lower or slug_lower in (c.lower(),):
            return True
    for ind in EXCLUDED_INDUSTRIES:
        if ind.lower() in domain:
            return True
    return False


class OllamaNotRunningError(Exception):
    """Raised when Ollama package is installed but the server is not reachable."""
    pass


def find_ollama_path() -> Optional[str]:
    """
    Return full path to ollama executable, or None if not found.
    On Windows checks: %%LOCALAPPDATA%%\\Programs\\Ollama\\ollama.exe,
    C:\\Program Files\\Ollama\\ollama.exe, %%USERPROFILE%%\\.ollama\\ollama.exe.
    On other platforms returns None (caller should use 'ollama' from PATH).
    """
    if sys.platform == "win32":
        candidates = [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Ollama", "ollama.exe"),
            os.path.join("C:", os.sep, "Program Files", "Ollama", "ollama.exe"),
            os.path.join(os.environ.get("USERPROFILE", ""), ".ollama", "ollama.exe"),
        ]
        for path in candidates:
            if path and os.path.isfile(path):
                return os.path.abspath(path)
    return None


def _get_ollama_version() -> Optional[str]:
    """Return Ollama server version from API, or None if unreachable."""
    try:
        req = urllib.request.Request("http://127.0.0.1:11434/api/version")
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode())
            return data.get("version")
    except Exception:
        return None


def get_ollama_health() -> Dict[str, Any]:
    """
    Check Ollama connection and model availability.
    Returns: { "connected": bool, "model_available": bool, "version": str | None, "ollama_path": str | None, "error_message": str | None }
    """
    ollama_path = find_ollama_path()
    if _ollama_module is None:
        err = "Ollama not found. Please download from https://ollama.com/download or ensure it's installed." if (sys.platform == "win32" and not ollama_path) else None
        return {"connected": False, "model_available": False, "version": None, "ollama_path": ollama_path, "error_message": err}
    try:
        models_resp = _ollama_module.list()
        models = models_resp.get("models") or []
        model_names = [m.get("name", "") for m in models]
        model_available = any(
            MODEL_NAME in name or name == MODEL_NAME
            for name in model_names
        )
        version = _get_ollama_version()
        return {"connected": True, "model_available": model_available, "version": version, "ollama_path": ollama_path, "error_message": None}
    except Exception:
        if sys.platform == "win32" and not ollama_path:
            err = "Ollama not found. Please download from https://ollama.com/download or ensure it's installed."
        elif ollama_path:
            err = f"Ollama is installed at {ollama_path} but the server isn't running. Run '{ollama_path} serve' or start Ollama from the Start menu."
        else:
            err = "Ollama not running. Start it with 'ollama serve'"
        return {"connected": False, "model_available": False, "version": _get_ollama_version(), "ollama_path": ollama_path, "error_message": err}


def _run_ollama_pull() -> bool:
    """
    Run 'ollama pull MODEL_NAME' using full path on Windows if found.
    Returns True if the pull process was started, False otherwise.
    Prints the exact command for the user.
    """
    path = find_ollama_path()
    cmd = path if path else "ollama"
    args = [cmd, "pull", MODEL_NAME] if path else ["ollama", "pull", MODEL_NAME]
    display_cmd = f'"{path}" pull {MODEL_NAME}' if path else f"ollama pull {MODEL_NAME}"
    try:
        kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        subprocess.Popen(args, **kwargs)
        logger.info("Started pulling model in background. You can also run: %s", display_cmd)
        return True
    except Exception as e:
        logger.warning("Could not start ollama pull: %s. Run: %s", e, display_cmd)
        return False


# ============== STRIPE ==============
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_CENTS = 4900  # $49 USD

# ============== SAFETY LIMITS ==============
AGENT_TIMEOUT_SECONDS = 120  # 2 minutes per agent for local CPU
CACHE_HOURS = 1
MAX_DAILY_AUDITS = 20
_current_audit_id: Optional[str] = None
# Synthesis agent: keep under ~2000 tokens total; trimmed input cap (~500 tokens for data)
SYNTHESIS_INPUT_MAX_CHARS = 2000

# ============== DATABASE SETUP ==============
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            free_tier_used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audits (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            progress INTEGER DEFAULT 0,
            results TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP
        )
    """)
    try:
        cursor.execute("ALTER TABLE audits ADD COLUMN paid_at TIMESTAMP")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE audits ADD COLUMN user_id TEXT REFERENCES users(id)")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

init_db()

def db_get(audit_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audits WHERE id = ?", (audit_id,))
    row = cursor.fetchone()
    conn.close()
    return row

def db_update(audit_id: str, status: str = None, progress: int = None, results: str = None):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    updates = []
    params = []
    if status:
        updates.append("status = ?")
        params.append(status)
    if progress is not None:
        updates.append("progress = ?")
        params.append(progress)
    if results:
        updates.append("results = ?")
        params.append(results)
        updates.append("completed_at = CURRENT_TIMESTAMP")

    if updates:
        query = f"UPDATE audits SET {', '.join(updates)} WHERE id = ?"
        params.append(audit_id)
        cursor.execute(query, params)
        conn.commit()
    conn.close()


def db_set_paid(audit_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE audits SET paid_at = CURRENT_TIMESTAMP WHERE id = ?", (audit_id,))
    conn.commit()
    conn.close()


def db_is_paid(row) -> bool:
    """Row from db_get; paid_at at index 7 (after paid_at migration)."""
    if not row or len(row) < 8:
        return False
    return row[7] is not None


def db_audit_get_user_id(row) -> Optional[str]:
    """Row from db_get; user_id at index 8 if present."""
    if not row or len(row) < 9:
        return None
    return row[8]


def normalize_url(url: str) -> str:
    """Ensure URL has https:// prefix; fix malformed input like 'www.stripe.com'."""
    if not url or not isinstance(url, str):
        return url
    url = url.strip()
    if not url:
        return url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def db_create(url: str, audit_id: str, user_id: Optional[str] = None):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audits (id, url, status, user_id) VALUES (?, ?, 'pending', ?)",
        (audit_id, url, user_id)
    )
    conn.commit()
    conn.close()


def db_count_audits_today() -> int:
    """Count audits created today (UTC day) for daily limit."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM audits WHERE date(created_at) = date('now')"
    )
    count = cursor.fetchone()[0]
    conn.close()
    return count


# ============== USERS ==============
def db_user_by_id(user_id: str) -> Optional[tuple]:
    """Return (id, email, password_hash, free_tier_used, created_at) or None."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, password_hash, free_tier_used, created_at FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def db_user_by_email(email: str) -> Optional[tuple]:
    """Return (id, email, password_hash, free_tier_used, created_at) or None."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, password_hash, free_tier_used, created_at FROM users WHERE email = ?", (email.strip().lower(),))
    row = cursor.fetchone()
    conn.close()
    return row


def db_user_create(user_id: str, email: str, password_hash: str) -> None:
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (id, email, password_hash, free_tier_used) VALUES (?, ?, ?, 0)",
        (user_id, email.strip().lower(), password_hash)
    )
    conn.commit()
    conn.close()


def db_user_set_free_tier_used(user_id: str) -> None:
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET free_tier_used = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def db_audits_by_user_id(user_id: str) -> List[tuple]:
    """Return list of (id, url, status, created_at, paid_at) for user's audits, newest first."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, url, status, created_at, paid_at FROM audits WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


# ============== AUTH (JWT + passlib) ==============
def _hash_password(password: str) -> str:
    if not pwd_ctx:
        raise HTTPException(status_code=503, detail="Auth not configured (install passlib[bcrypt])")
    return pwd_ctx.hash(password)


def _verify_password(plain: str, hashed: str) -> bool:
    if not pwd_ctx:
        return False
    return pwd_ctx.verify(plain, hashed)


def _create_token(user_id: str, email: str) -> str:
    if not jwt or not JWT_SECRET:
        raise HTTPException(status_code=503, detail="Auth not configured (set JWT_SECRET)")
    from datetime import timedelta
    payload = {"sub": user_id, "email": email, "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRY_DAYS)}
    tok = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return tok if isinstance(tok, str) else tok.decode("utf-8")


def _decode_token(token: str) -> Optional[Dict[str, Any]]:
    if not jwt or not JWT_SECRET:
        return None
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None


security = HTTPBearer(auto_error=False)


def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    authorization: Optional[str] = Header(None),
) -> Optional[Dict[str, Any]]:
    """Return { id, email, free_tier_used } or None if no/invalid token."""
    token = None
    if credentials:
        token = credentials.credentials
    if not token and authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
    if not token:
        return None
    payload = _decode_token(token)
    if not payload:
        return None
    user_id = payload.get("sub")
    email = payload.get("email")
    if not user_id:
        return None
    row = db_user_by_id(user_id)
    if not row:
        return None
    return {"id": row[0], "email": row[1], "free_tier_used": bool(row[3])}


def get_current_user(user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)) -> Dict[str, Any]:
    """Require valid token; raise 401 if missing/invalid."""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def db_get_cached_result(url: str):
    """
    Return cached audit row (id, results dict) if same URL completed within CACHE_HOURS, else None.
    results column is JSON string; returns (audit_id, parsed_results).
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        """SELECT id, results FROM audits
           WHERE url = ? AND status = 'completed' AND results IS NOT NULL
           AND completed_at IS NOT NULL
           AND datetime(completed_at) > datetime('now', ?)
           ORDER BY completed_at DESC LIMIT 1""",
        (url, f"-{CACHE_HOURS} hours")
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    try:
        parsed = json.loads(row[1]) if row[1] else None
        return (row[0], parsed)
    except Exception:
        return None

# ============== AGENT DEFINITIONS ==============
AGENTS = [
    {"id": 1, "name": "Official Page Scanner", "type": "website", "icon": "🌐"},
    {"id": 2, "name": "Community Analyst", "type": "reddit", "icon": "🔍"},
    {"id": 3, "name": "G2 Review Extractor", "type": "reviews", "icon": "⭐"},
    {"id": 4, "name": "Wayback Historian", "type": "historical", "icon": "📚"},
    {"id": 5, "name": "Partner Program Researcher", "type": "pdf", "icon": "📄"},
    {"id": 6, "name": "Forum Thread Analyzer", "type": "forums", "icon": "💬"},
    {"id": 7, "name": "Twitter/X Tracker", "type": "social", "icon": "🐦"},
    {"id": 8, "name": "LinkedIn Intel Gatherer", "type": "linkedin", "icon": "💼"},
    {"id": 9, "name": "Public Record Scanner", "type": "community", "icon": "👥"},
    {"id": 10, "name": "Consensus Validator", "type": "synthesis", "icon": "🎯"}
]

# ============== SCRAPING HELPERS ==============
def _domain_from_url(url: str) -> str:
    """Extract hostname from URL (e.g. https://www.stripe.com/pricing -> stripe.com)."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc or parsed.path
        if not netloc:
            return ""
        return netloc.lower().lstrip("www.")
    except Exception:
        return ""


def _g2_slug_from_domain(domain: str) -> str:
    """G2 product slugs are usually the brand name (e.g. stripe.com -> stripe)."""
    if not domain:
        return ""
    return domain.split(".")[0] if "." in domain else domain


# ============== SCRAPING LAYER (FREE) ==============
class FreeScraper:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        self.timeout = aiohttp.ClientTimeout(total=15)

    async def fetch(self, url: str) -> str:
        """Basic scrape - returns markdown. On failure returns '' and logs."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers, timeout=self.timeout) as resp:
                    if resp.status == 403:
                        logger.warning("Scraper fetch 403 for %s", url)
                        return ""
                    if resp.status != 200:
                        logger.warning("Scraper fetch HTTP %s for %s", resp.status, url)
                        return ""
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    for tag in soup(["script", "style"]):
                        tag.decompose()
                    return markdownify.markdownify(str(soup))
        except asyncio.TimeoutError:
            logger.warning("Scraper fetch timeout for %s", url)
            return ""
        except Exception as e:
            logger.warning("Scraper fetch failed for %s: %s", url, e)
            return ""

    async def fetch_reddit(self, target_url: str) -> str:
        """Real Reddit: PRAW if credentials set, else old.reddit.com search for domain + pricing + cost."""
        domain = _domain_from_url(target_url)
        if not domain:
            return ""
        query = f"{domain} pricing cost"
        # Prefer PRAW if credentials available (run in thread - PRAW is sync)
        if os.environ.get("REDDIT_CLIENT_ID") and os.environ.get("REDDIT_CLIENT_SECRET"):
            try:
                return await asyncio.to_thread(self._fetch_reddit_praw_sync, query)
            except Exception as e:
                logger.warning("Reddit PRAW failed, falling back to scrape: %s", e)
        return await self._fetch_reddit_old_reddit(query)

    def _fetch_reddit_praw_sync(self, query: str) -> str:
        """Search Reddit via PRAW (sync)."""
        try:
            import praw
            reddit = praw.Reddit(
                client_id=os.environ["REDDIT_CLIENT_ID"],
                client_secret=os.environ["REDDIT_CLIENT_SECRET"],
                user_agent="pricing-intel/1.0",
            )
            subs = list(reddit.subreddit("all").search(query, limit=15, time_filter="year"))
            parts = []
            for s in subs:
                parts.append(f"[{s.title}]\n{s.self_text or ''}\n")
            return "\n".join(parts) if parts else ""
        except Exception as e:
            logger.warning("Reddit PRAW error: %s", e)
            return ""

    async def _fetch_reddit_old_reddit(self, query: str) -> str:
        """Scrape old.reddit.com search results."""
        try:
            url = "https://old.reddit.com/search"
            params = {"q": query, "sort": "relevance", "t": "year"}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers, timeout=self.timeout, params=params) as resp:
                    if resp.status in (403, 429):
                        logger.warning("Reddit scrape %s (rate limit or block)", resp.status)
                        return ""
                    if resp.status != 200:
                        logger.warning("Reddit scrape HTTP %s", resp.status)
                        return ""
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    parts = []
                    for post in soup.select("div.thing")[:20]:
                        title_el = post.select_one("a.title")
                        if title_el:
                            title = title_el.get_text(strip=True)
                            body_el = post.select_one("div.usertext-body")
                            body = (body_el.get_text(strip=True)[:500] if body_el else "")
                            parts.append(f"[{title}]\n{body}")
                    return "\n".join(parts) if parts else ""
        except asyncio.TimeoutError:
            logger.warning("Reddit scrape timeout")
            return ""
        except Exception as e:
            logger.warning("Reddit scrape failed: %s", e)
            return ""

    async def fetch_wayback(self, url: str) -> str:
        """Real Wayback: CDX API for url domain, then fetch snapshot content."""
        domain = _domain_from_url(url)
        if not domain:
            return ""
        try:
            cdx_url = "https://web.archive.org/cdx/search/cdx"
            params = {
                "url": domain,
                "matchType": "domain",
                "output": "json",
                "fl": "timestamp,original",
                "limit": "25",
            }
            async with aiohttp.ClientSession() as session:
                async with session.get(cdx_url, headers=self.headers, timeout=self.timeout, params=params) as resp:
                    if resp.status in (403, 429):
                        logger.warning("Wayback CDX %s", resp.status)
                        return ""
                    if resp.status != 200:
                        logger.warning("Wayback CDX HTTP %s", resp.status)
                        return ""
                    rows = await resp.json()
                    if not rows or len(rows) < 2:
                        return ""
                    # rows[0] is header; pick latest and one older snapshot
                    timestamps_and_urls = []
                    for row in rows[1:]:
                        if len(row) >= 2:
                            timestamps_and_urls.append((row[0], row[1]))
                    if not timestamps_and_urls:
                        return ""
                    # Fetch content of latest and one older
                    collected = []
                    for i, (ts, orig) in enumerate(timestamps_and_urls[:3]):
                        snap_url = f"https://web.archive.org/web/{ts}id_/{orig}"
                        try:
                            async with session.get(snap_url, headers=self.headers, timeout=self.timeout) as snap_resp:
                                if snap_resp.status != 200:
                                    continue
                                html = await snap_resp.text()
                                soup = BeautifulSoup(html, "html.parser")
                                for tag in soup(["script", "style"]):
                                    tag.decompose()
                                text = soup.get_text(separator="\n", strip=True)[:6000]
                                collected.append(f"[Snapshot {ts}]\n{text}")
                        except (asyncio.TimeoutError, Exception) as e:
                            logger.debug("Wayback snapshot fetch failed for %s: %s", snap_url, e)
                    return "\n\n".join(collected) if collected else ""
        except asyncio.TimeoutError:
            logger.warning("Wayback CDX timeout")
            return ""
        except Exception as e:
            logger.warning("Wayback failed: %s", e)
            return ""

    async def fetch_g2_reviews(self, target_url: str) -> str:
        """Scrape G2 reviews page: https://www.g2.com/products/{slug}/reviews."""
        domain = _domain_from_url(target_url)
        slug = _g2_slug_from_domain(domain)
        if not slug:
            return ""
        try:
            url = f"https://www.g2.com/products/{slug}/reviews"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers, timeout=self.timeout) as resp:
                    if resp.status in (403, 404, 429):
                        logger.warning("G2 reviews HTTP %s for %s", resp.status, url)
                        return ""
                    if resp.status != 200:
                        logger.warning("G2 reviews HTTP %s for %s", resp.status, url)
                        return ""
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    for tag in soup(["script", "style"]):
                        tag.decompose()
                    return markdownify.markdownify(str(soup))
        except asyncio.TimeoutError:
            logger.warning("G2 reviews timeout for %s", slug)
            return ""
        except Exception as e:
            logger.warning("G2 reviews failed for %s: %s", slug, e)
            return ""

scraper = FreeScraper()

# ============== TONE SANITIZE (LEGAL-SAFE OUTPUT) ==============
def _tone_sanitize(text: Optional[str]) -> str:
    """Replace dangerous/gotcha language with analyst-grade wording. Returns '' if input is None."""
    if not text or not isinstance(text, str):
        return ""
    import re
    t = text
    # Word-level replacements (case-insensitive, whole-word where sensible)
    replacements = [
        (r"\bleaked\b", "publicly available"),
        (r"\bsecret\b", "non-public"),
        (r"\bhidden\b", "published"),
        (r"\binternal\b", "proprietary"),
        (r"\bconfidential\b", "restricted"),
        (r"\bexpose[d]?\b", "derived from"),
        (r"\breveal(?:ed|s)?\b", "analysis of"),
        (r"\buncover(?:ed|s)?\b", "analysis of"),
        (r"\bshadow\s+price\b", "estimated market rate"),
        (r"\bshadow\b", "estimated"),
    ]
    for pattern, repl in replacements:
        t = re.sub(pattern, repl, t, flags=re.IGNORECASE)
    return t


def _sanitize_findings(findings: List[Dict]) -> List[Dict]:
    """Return a copy of findings with evidence/methodology tone-sanitized for display."""
    out = []
    for f in findings:
        copy = dict(f)
        if f.get("evidence"):
            copy["evidence"] = _tone_sanitize(f["evidence"]) or f["evidence"]
        if f.get("methodology"):
            copy["methodology"] = _tone_sanitize(f["methodology"]) or f["methodology"]
        out.append(copy)
    return out


def _certainty_to_uncertainty(text: str) -> str:
    """Replace certainty words with uncertainty words for legal-safe output."""
    if not text or not isinstance(text, str):
        return ""
    import re
    t = text
    # Whole-word replacements (case-sensitive for common forms)
    replacements = [
        (r"\bwill\b", "likely will"),
        (r"\bis\b", "typically is"),
        (r"\bare\b", "are typically"),
        (r"\balways\b", "often"),
        (r"\bnever\b", "rarely"),
        (r"\bcertain(?:ly)?\b", "generally"),
        (r"\bdefinitely\b", "typically"),
        (r"\bexact(?:ly)?\b", "approximate"),
    ]
    for pattern, repl in replacements:
        t = re.sub(pattern, repl, t, flags=re.IGNORECASE)
    return t


def legal_safety_check(consensus: Dict[str, Any]) -> Dict[str, Any]:
    """
    Post-processing safety layer before displaying results.
    - Ensure all prices are presented as ranges, not single exact claims.
    - Replace certainty words with uncertainty words in rationale/caveats/methodology.
    - Ensure "estimate" appears at least once in pricing output.
    - Flag high savings claims (>50%) with verify-independently warning.
    - Ensure caveats field is populated.
    """
    out = dict(consensus)
    # Single number -> treat as midpoint of range (widen slightly for display)
    sp = out.get("shadow_price")
    sp_min = out.get("shadow_price_min")
    sp_max = out.get("shadow_price_max")
    if sp is not None and sp_min is not None and sp_max is not None:
        pass
    elif sp is not None:
        out["shadow_price_min"] = round(sp * 0.95, 2) if sp_min is None else sp_min
        out["shadow_price_max"] = round(sp * 1.05, 2) if sp_max is None else sp_max
    # Post-processing: certainty -> uncertainty language
    for key in ("rationale", "caveats", "methodology"):
        val = out.get(key)
        if val and isinstance(val, str):
            out[key] = _certainty_to_uncertainty(val)
    # Ensure "estimate" appears at least once in pricing output
    combined = " ".join([str(out.get(k) or "") for k in ("rationale", "caveats", "methodology")])
    if combined and "estimate" not in combined.lower():
        caveats = (out.get("caveats") or "").strip()
        out["caveats"] = (caveats + " This is an estimate; verify independently.").strip() if caveats else "This is an estimate; verify independently."
    # High savings -> add verify warning
    savings = out.get("savings_percent") or 0
    if savings > 50 or out.get("exceptional_savings"):
        caveats = out.get("caveats") or ""
        if "verify" not in caveats.lower() and "independent" not in caveats.lower():
            out["caveats"] = (caveats + " Verify independently before negotiating.").strip()
        out["verify_warning"] = True
    else:
        out["verify_warning"] = False
    # Ensure caveats always present
    if not (out.get("caveats") or "").strip():
        out["caveats"] = "Estimates represent analytical modeling, not verified pricing. Conduct independent verification before negotiating."
    return out


# ============== PRICE VALIDATION ==============
PRICE_MIN = 5          # Reject $1-style false positives
PRICE_MAX = 50_000     # Cap outliers
SAVINGS_CAP_PERCENT = 50  # Max savings shown in UI


def _normalize_price_found(value: Any) -> Optional[float]:
    """
    Validate and normalize price_found from agent output.
    - Must be numeric (reject true/false/null strings or bools).
    - Convert strings like '$99/month' to 99.
    - Must be > PRICE_MIN and < PRICE_MAX (filter outliers and $1 false positives).
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("true", "false", "null", ""):
            return None
        import re
        match = re.search(r"[\d,]+(?:\.\d+)?", s.replace(",", ""))
        if not match:
            return None
        try:
            value = float(match.group(0).replace(",", ""))
        except (ValueError, TypeError):
            return None
    if not isinstance(value, (int, float)):
        return None
    try:
        p = float(value)
    except (ValueError, TypeError):
        return None
    if p < PRICE_MIN or p > PRICE_MAX:
        return None
    return round(p, 2)


# ============== SERIAL SWARM LOGIC ==============
class ShadowSwarm:
    def __init__(self, audit_id: str, websocket: WebSocket):
        self.audit_id = audit_id
        self.ws = websocket
        self.results = []

    async def send_progress(self, current: int, total: int, agent_name: str, status: str = "running"):
        payload = {
            "agent": current,
            "total": total,
            "name": agent_name,
            "status": status,
            "progress_percent": int((current / total) * 100)
        }
        logger.info("WebSocket sending: agent=%s status=%s name=%s", current, status, agent_name)
        await self.ws.send_json(payload)
        logger.debug("WebSocket message sent")

    @staticmethod
    def _median_price_from_results(results: List[Dict]) -> Optional[float]:
        """Median of validated price_found from agents 1-9."""
        prices = []
        for r in results:
            p = _normalize_price_found(r.get("price_found"))
            if p is not None:
                prices.append(p)
        if not prices:
            return None
        prices.sort()
        n = len(prices)
        if n % 2 == 1:
            return prices[n // 2]
        return (prices[n // 2 - 1] + prices[n // 2]) / 2.0

    def _compute_consensus_programmatic(self) -> Dict[str, Any]:
        """
        Agent 10 (Synthesis): senior pricing analyst consolidating multiple estimates.
        - Weight by confidence (high=3x, medium=2x, low=1x).
        - Use estimated_range_low/high when present; else price_found.
        - Flag insufficient_consensus when variance > 50%.
        - Output: rationale, caveats, typical_negotiation_range_low/high.
        """
        weighted_prices: List[float] = []
        weights: List[float] = []
        ranges_low: List[float] = []
        ranges_high: List[float] = []
        rationales: List[str] = []
        caveats_list: List[str] = []
        total_source_count = 0
        for r in self.results:
            low = _normalize_price_found(r.get("estimated_range_low"))
            high = _normalize_price_found(r.get("estimated_range_high"))
            p = _normalize_price_found(r.get("price_found"))
            if low is not None and high is not None:
                mid = (low + high) / 2
                ranges_low.append(low)
                ranges_high.append(high)
                weighted_prices.append(mid)
            elif p is not None:
                weighted_prices.append(p)
                ranges_low.append(p)
                ranges_high.append(p)
            else:
                continue
            c = r.get("confidence")
            if c is not None and isinstance(c, (int, float)):
                w = 3.0 if c >= 0.7 else (2.0 if c >= 0.4 else 1.0)
            else:
                w = 1.0
            weights.append(w)
            sc = r.get("source_count")
            total_source_count += int(sc) if isinstance(sc, (int, float)) and sc >= 0 else 1
            if r.get("rationale"):
                rationales.append(str(r["rationale"])[:200])
            if r.get("caveats"):
                caveats_list.append(str(r["caveats"])[:150])

        n = len(weighted_prices)
        if n == 0:
            methodology = "No public pricing intelligence found. Published rate may be firm."
            return {
                "shadow_price": None,
                "list_price": None,
                "shadow_price_min": None,
                "shadow_price_max": None,
                "confidence": 0.0,
                "savings_percent": 0,
                "typical_negotiation_range_low": None,
                "typical_negotiation_range_high": None,
                "exceptional_savings": False,
                "insufficient_consensus": False,
                "methodology": _tone_sanitize(methodology) or methodology,
                "rationale": "",
                "caveats": "Insufficient public data to produce an estimate.",
            }

        total_w = sum(weights)
        weighted_median = sum(p * w for p, w in zip(weighted_prices, weights)) / total_w if total_w else sum(weighted_prices) / n
        min_price = min(ranges_low) if ranges_low else min(weighted_prices)
        max_price = max(ranges_high) if ranges_high else max(weighted_prices)
        list_price = round(max(max_price, weighted_median), 2)
        shadow_price = round(weighted_median, 2)
        shadow_min = round(min_price, 2)
        shadow_max = round(max_price, 2)

        # Variance: flag insufficient consensus if > 50%
        variance_pct = ((max_price - min_price) / weighted_median * 100) if weighted_median else 100
        insufficient_consensus = variance_pct > 50 or n < 2

        # Confidence: High = 3+ agents within 10%; Medium = 2 or moderate variance; Low = < 2 or high variance
        within_10pct = sum(1 for p in weighted_prices if abs(p - weighted_median) / weighted_median <= 0.10) if weighted_median else 0
        if n >= 3 and within_10pct >= 3 and not insufficient_consensus:
            confidence = 0.8
        elif n >= 2 or (n >= 1 and variance_pct <= 25):
            confidence = 0.5
        else:
            confidence = 0.3
        if insufficient_consensus:
            confidence = min(confidence, 0.5)

        # SYNTHESIS FLOOR-WIDENING: If confidence is low OR source_count < 2, widen range by minimum ±25%
        need_floor_widening = confidence < 0.5 or total_source_count < 2
        if need_floor_widening and weighted_median and weighted_median > 0:
            widen = 0.25
            shadow_min = round(weighted_median * (1 - widen), 2)
            shadow_max = round(weighted_median * (1 + widen), 2)
            shadow_min = min(shadow_min, min_price) if ranges_low else shadow_min
            shadow_max = max(shadow_max, max_price) if ranges_high else shadow_max

        raw_savings = ((list_price - shadow_price) / list_price) * 100 if list_price else 0
        savings_percent = round(min(raw_savings, SAVINGS_CAP_PERCENT), 1)
        exceptional_savings = raw_savings > SAVINGS_CAP_PERCENT

        # Typical negotiation range (percent below published)
        neg_low = round(max(0, ((list_price - shadow_max) / list_price) * 100), 0) if list_price else 0
        neg_high = round(min(50, ((list_price - shadow_min) / list_price) * 100), 0) if list_price else 0
        typical_negotiation_range_low = int(neg_low)
        typical_negotiation_range_high = int(neg_high)

        rationale = " ".join(rationales[:3]) if rationales else f"Based on {n} public source(s). Median estimate ${shadow_min:.0f}–${shadow_max:.0f}/mo."
        caveats = " ".join(caveats_list[:2]) if caveats_list else "Estimate only; verify current rates independently."
        if insufficient_consensus:
            caveats = "Insufficient consensus across sources; range is wide. " + caveats
        if need_floor_widening:
            caveats = "Range widened to reflect limited evidence. " + caveats
        methodology = f"Weighted median of {n} agent estimates (range ${shadow_min:.0f}–${shadow_max:.0f}/mo)."
        return {
            "shadow_price": shadow_price,
            "list_price": list_price,
            "shadow_price_min": shadow_min,
            "shadow_price_max": shadow_max,
            "confidence": round(confidence, 2),
            "savings_percent": savings_percent,
            "typical_negotiation_range_low": typical_negotiation_range_low,
            "typical_negotiation_range_high": typical_negotiation_range_high,
            "exceptional_savings": exceptional_savings,
            "insufficient_consensus": insufficient_consensus,
            "source_count": total_source_count,
            "methodology": _tone_sanitize(methodology) or methodology,
            "rationale": _tone_sanitize(rationale) or rationale,
            "caveats": _tone_sanitize(caveats) or caveats,
        }

    def _mock_agent_response(self, agent: Dict) -> Dict:
        """Return mock pricing result when Ollama is not available (legal-safe format)."""
        import random
        if agent["type"] == "synthesis":
            return {
                "agent_name": agent["name"],
                "agent_id": agent["id"],
                "status": "success",
                "shadow_price": 79,
                "list_price": 99,
                "confidence": 0.7,
                "savings_percent": 20,
                "methodology": "Mock mode (Ollama not installed). Install Ollama for real analysis.",
            }
        # Some agents "find" a range, others don't (for variety)
        price = random.choice([None, 79, 89, 99]) if random.random() > 0.4 else None
        price = _normalize_price_found(price)
        low = round(price * 0.9, 2) if price else None
        high = round(price * 1.1, 2) if price else None
        conf = round(random.uniform(0.5, 0.9), 2) if price else 0
        return {
            "agent_name": agent["name"],
            "agent_id": agent["id"],
            "status": "success",
            "price_found": price,
            "estimated_range_low": low,
            "estimated_range_high": high,
            "confidence": conf,
            "source_count": 1 if price else 0,
            "rationale": f"Mock finding for {agent['name']} (Ollama not installed)." if price else "",
            "caveats": "Mock data; install Ollama for real analysis.",
            "evidence": f"Mock finding for {agent['name']} (Ollama not installed)." if price else None,
        }

    def run_local_agent(self, agent: Dict, target_url: str, scraped_data: str) -> Dict:
        """Run single Ollama agent with memory cleanup. Uses legal-safe analyst framework."""

        UNIVERSAL_SYSTEM = """You are a competitive pricing analyst.

IMPORTANT CONSTRAINTS:
- You must never present inferred or reconstructed prices as exact facts.
- Only quote exact numbers if they are explicitly and publicly published.
- All inferred values must be expressed as ranges or null if insufficient.
- Every range must include a confidence level: low / medium / high.
- Use probabilistic, analytical language (e.g., "likely", "suggests", "indicates").

SOURCE RULES:
- Use only publicly accessible information.
- Do not imply insider knowledge, leaks, or confidential access.
- Do not reference specific customers or private deals.

OUTPUT SCHEMA (JSON only):
{
  "published_price": number | null,
  "estimated_range_low": number | null,
  "estimated_range_high": number | null,
  "confidence": "low" | "medium" | "high",
  "discount_likelihood": "low" | "medium" | "high",
  "rationale": "string",
  "caveats": "string",
  "source_type": "official documentation" | "community discussion" | "partner program" | "historical archive",
  "source_count": number
}

NULL SAFETY:
- If both estimated_range_low and estimated_range_high are null, confidence MUST be "low" and rationale MUST explicitly state "Insufficient public data to estimate range."

CONFIDENCE RUBRIC:
- High: ≥3 independent public sources, recent (<12 months), consistent variance <15%
- Medium: 2 sources, or indirect signals, variance 15-30%, mostly consistent
- Low: ≤1 source, outdated (>12mo), speculative, or conflicting variance >30%

POST-PROCESSING: Use uncertainty language ("likely", "typically", "suggests"); ensure "estimate" appears in rationale or caveats. Never present narrow ranges from weak evidence."""

        # Agent 1: Official documentation
        OFFICIAL_PROMPT = f"""You are analyzing official pricing documentation.
Extract only explicitly stated prices.
Note any "Contact Sales" or custom pricing indicators.
Flag volume discounts or tiered pricing clearly published.

Content: {scraped_data[:8000]}

Return ONLY valid JSON with: published_price, estimated_range_low, estimated_range_high, confidence, discount_likelihood, rationale, caveats, source_type (use "official documentation"), source_count (number of distinct public sources cited)."""

        # Agents 2-9: Community / public sources — tightened rule
        COMMUNITY_PROMPT_TEMPLATE = """You are analyzing public community discussions.

COMMUNITY RULE: Extract price mentions only if numeric values are stated explicitly AND framed as personal experience or direct observation. Exclude hearsay, speculation, or vague references ("about", "roughly", "around").
Present as "community-suggested range" not "actual price".
Flag if discussion is outdated (>1 year) or speculative.
Never attribute to specific individuals.

Content: {content}

Return ONLY valid JSON with: published_price (or null), estimated_range_low, estimated_range_high, confidence, discount_likelihood, rationale, caveats, source_type ("community discussion" | "partner program" | "historical archive"), source_count (number of distinct posts/sources cited). If no valid price signal: estimated_range_low and estimated_range_high null, confidence "low", rationale must state "Insufficient public data to estimate range."
"""

        content_6k = scraped_data[:6000]
        content_4k = scraped_data[:4000]
        prompts = {
            "website": OFFICIAL_PROMPT,
            "reddit": COMMUNITY_PROMPT_TEMPLATE.format(content=content_6k),
            "reviews": COMMUNITY_PROMPT_TEMPLATE.format(content=content_6k),
            "historical": COMMUNITY_PROMPT_TEMPLATE.format(content=content_6k),
            "pdf": COMMUNITY_PROMPT_TEMPLATE.format(content=content_6k),
            "forums": COMMUNITY_PROMPT_TEMPLATE.format(content=content_6k),
            "social": COMMUNITY_PROMPT_TEMPLATE.format(content=content_4k),
            "linkedin": COMMUNITY_PROMPT_TEMPLATE.format(content=content_4k),
            "community": COMMUNITY_PROMPT_TEMPLATE.format(content=content_6k),
            "synthesis": "",
        }

        try:
            # Mock mode only when Ollama package is not installed or explicitly requested
            if USE_MOCK_LLM or not OLLAMA_PACKAGE_AVAILABLE:
                return self._mock_agent_response(agent)

            # Use real Ollama
            logger.info("Ollama chat begin: agent=%s", agent.get("name"))
            response = _ollama_module.chat(
                model=MODEL_NAME,
                messages=[
                    {'role': 'system', 'content': UNIVERSAL_SYSTEM},
                    {'role': 'user', 'content': prompts.get(agent["type"], prompts["website"])}
                ],
                options={'temperature': 0.1, 'num_ctx': 4096}
            )

            content = response['message']['content']

            # Extract JSON from response (sometimes LLM adds markdown)
            if '```json' in content:
                content = content.split('```json')[1].split('```')[0]
            elif '```' in content:
                content = content.split('```')[1].split('```')[0]

            result = json.loads(content.strip())
            result['agent_name'] = agent['name']
            result['agent_id'] = agent['id']
            result['status'] = 'success'
            # Normalize to internal format: price_found (midpoint for consensus), confidence 0-1
            result["price_found"] = None
            result["estimated_range_low"] = result.get("estimated_range_low")
            result["estimated_range_high"] = result.get("estimated_range_high")
            low = _normalize_price_found(result.get("estimated_range_low"))
            high = _normalize_price_found(result.get("estimated_range_high"))
            pub = _normalize_price_found(result.get("published_price"))
            if low is not None and high is not None:
                result["price_found"] = round((low + high) / 2, 2)
                result["estimated_range_low"] = low
                result["estimated_range_high"] = high
            elif low is not None:
                result["price_found"] = low
                result["estimated_range_low"] = result["estimated_range_high"] = low
            elif high is not None:
                result["price_found"] = high
                result["estimated_range_low"] = result["estimated_range_high"] = high
            elif isinstance(result.get("price_found"), (int, float)):
                # Legacy: agent returned price_found
                result["price_found"] = _normalize_price_found(result.get("price_found"))
                if result["price_found"] is not None:
                    result["estimated_range_low"] = result["estimated_range_high"] = result["price_found"]
            # Confidence: string -> numeric for consensus weighting
            conf_str = (result.get("confidence") or "").lower().strip()
            if conf_str in ("low", "medium", "high"):
                result["confidence"] = {"low": 0.33, "medium": 0.66, "high": 0.9}[conf_str]
            elif not isinstance(result.get("confidence"), (int, float)):
                result["confidence"] = 0.5
            else:
                result["confidence"] = max(0, min(1, float(result["confidence"])))
            if not result.get("rationale"):
                result["rationale"] = result.get("evidence") or ""
            if not result.get("caveats"):
                result["caveats"] = "Estimate based on limited public signals."
            # source_count: number of distinct sources cited (default 1 per agent that contributed)
            sc = result.get("source_count")
            result["source_count"] = int(sc) if isinstance(sc, (int, float)) and sc >= 0 else (1 if result.get("price_found") is not None or (low is not None or high is not None) else 0)
            logger.info("Ollama chat end: agent=%s", agent.get("name"))
            return result

        except OllamaNotRunningError:
            raise
        except Exception as e:
            # Connection refused / unreachable -> show clear message in UI
            err_str = str(e).lower()
            if "connection" in err_str or "refused" in err_str or "11434" in err_str or "connect" in err_str:
                path = find_ollama_path()
                msg = f"Ollama not running. Run '{path} serve'" if path else "Ollama not found. Please download from https://ollama.com/download or ensure it's installed."
                raise OllamaNotRunningError(msg) from e
            return {
                'agent_name': agent['name'],
                'agent_id': agent['id'],
                'error': str(e),
                'price_found': None,
                'confidence': 0,
                'status': 'failed'
            }
        finally:
            # CRITICAL: Aggressive memory cleanup for 16GB RAM
            gc.collect()

    async def hunt(self, target_url: str, cancelled_event: Optional[asyncio.Event] = None, preview: bool = False):
        """Run all 10 agents. (preview flag ignored; full hunt only for testing.)"""
        total = len(AGENTS)
        all_findings = []
        cancelled_event = cancelled_event or asyncio.Event()
        heartbeat_state = {"current_agent": 0, "stop": False}

        async def heartbeat_loop():
            while not heartbeat_state["stop"]:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                if heartbeat_state["stop"]:
                    break
                try:
                    await self.ws.send_json({
                        "type": "heartbeat",
                        "agent": heartbeat_state["current_agent"],
                    })
                    logger.debug("Heartbeat sent agent=%s", heartbeat_state["current_agent"])
                except Exception as e:
                    logger.debug("Heartbeat send failed: %s", e)
                    break

        heartbeat_task = asyncio.create_task(heartbeat_loop())
        try:
            for i, agent in enumerate(AGENTS, 1):
                if cancelled_event.is_set():
                    break
                heartbeat_state["current_agent"] = i

                # CRITICAL: Send "running" FIRST so UI updates before any heavy work
                logger.info("Starting Agent %s: %s", i, agent['name'])
                await self.send_progress(i, total, agent['name'], "running")

                if TEST_MODE:
                    logger.info("TEST_MODE: simulating Agent %s (1s)", i)
                    await asyncio.sleep(1.0)
                    result = {
                        'agent_name': agent['name'],
                        'agent_id': agent['id'],
                        'price_found': 99 if i == 1 else None,
                        'confidence': 0.8,
                        'status': 'success',
                    }
                    self.results.append(result)
                    if result.get('price_found'):
                        all_findings.append(result)
                    await self.send_progress(i, total, agent['name'], "completed")
                    await asyncio.sleep(0.2)
                    continue

                # Scrape (async; event loop can process WebSocket)
                logger.info("Scraping for Agent %s: %s", i, agent['name'])
                if agent['type'] == 'website':
                    data = await scraper.fetch(target_url)
                elif agent['type'] == 'reddit':
                    data = await scraper.fetch_reddit(target_url)
                elif agent['type'] == 'historical':
                    data = await scraper.fetch_wayback(target_url)
                elif agent['type'] == 'reviews':
                    data = await scraper.fetch_g2_reviews(target_url)
                    if not data:
                        data = "(No G2 reviews page found for this domain.)"
                else:
                    data = f"Analyzing {target_url} for {agent['type']} intelligence..."
                logger.info("Scrape done for Agent %s, starting Ollama...", i)

                if cancelled_event.is_set():
                    break

                # Run Ollama in thread (so event loop stays free for heartbeat/WebSocket)
                try:
                    logger.info("Ollama call begin Agent %s", i)
                    result = await asyncio.wait_for(
                        asyncio.to_thread(
                            self.run_local_agent,
                            agent,
                            target_url,
                            data
                        ),
                        timeout=AGENT_TIMEOUT_SECONDS
                    )
                    logger.info("Ollama call end Agent %s", i)
                    self.results.append(result)
                    if result.get('price_found'):
                        all_findings.append(result)
                    await self.send_progress(i, total, agent['name'], "completed")
                except asyncio.TimeoutError:
                    logger.warning("Agent %s timed out after %ss", agent['name'], AGENT_TIMEOUT_SECONDS)
                    result = {
                        'agent_name': agent['name'],
                        'agent_id': agent['id'],
                        'error': f'Timeout after {AGENT_TIMEOUT_SECONDS}s',
                        'price_found': None,
                        'confidence': 0,
                        'status': 'failed'
                    }
                    self.results.append(result)
                    await self.send_progress(i, total, agent['name'], "timeout")
                except OllamaNotRunningError as e:
                    await self.ws.send_json({"error": str(e)})
                    return

                await asyncio.sleep(0.5)
        finally:
            heartbeat_state["stop"] = True
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

        if cancelled_event.is_set():
            # Partial results; no synthesis
            db_update(
                self.audit_id,
                status='cancelled',
                progress=int((len(self.results) / total) * 100),
                results=json.dumps({
                    'findings': self.results,
                    'consensus': None,
                    'url': target_url,
                    'completed_at': datetime.now().isoformat(),
                    'cancelled': True
                })
            )
            await self.ws.send_json({
                "type": "complete",
                "data": {"cancelled": True, "message": "Audit stopped by user"},
                "all_findings": _sanitize_findings(self.results),
            })
            return

        # Agent 10 (Consensus): programmatic only — no Ollama call (eliminates freeze)
        await self.send_progress(total, total, "Finalizing Report", "synthesizing")
        final_result = self._compute_consensus_programmatic()
        final_result = legal_safety_check(final_result)

        db_update(
            self.audit_id,
            status='completed',
            progress=100,
            results=json.dumps({
                'findings': self.results,
                'consensus': final_result,
                'url': target_url,
                'completed_at': datetime.now().isoformat()
            })
        )
        # Force one final status update so Agent 10 (Consensus Validator) shows "Analysis Complete" before complete
        await self.send_progress(total, total, "Consensus Validator", "completed")
        await self.ws.send_json({
            "type": "complete",
            "data": final_result,
            "all_findings": _sanitize_findings(self.results),
        })

# ============== FASTAPI APP ==============
app = FastAPI(title="Pricing Intelligence and Market Benchmarking", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AuditRequest(BaseModel):
    url: str


class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class ClaimFreeRequest(BaseModel):
    email: str
    url: str


@app.post("/api/register")
async def register(body: RegisterRequest):
    """Create account. Returns token and user."""
    if not JWT_SECRET or not pwd_ctx:
        raise HTTPException(status_code=503, detail="Auth not configured (set JWT_SECRET, install passlib)")
    email = body.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email required")
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if db_user_by_email(email):
        raise HTTPException(status_code=400, detail="Email already registered")
    import uuid
    user_id = str(uuid.uuid4())[:12]
    password_hash = _hash_password(body.password)
    db_user_create(user_id, email, password_hash)
    token = _create_token(user_id, email)
    return {"token": token, "user": {"id": user_id, "email": email, "free_tier_used": False}}


def _client_ip(request: Request) -> str:
    """Client IP for rate limiting (X-Forwarded-For or request.client.host)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.post("/api/login")
async def login(request: Request, body: LoginRequest):
    """Login. Returns token and user. Rate limited: 5 attempts per IP per hour."""
    if not JWT_SECRET or not pwd_ctx:
        raise HTTPException(status_code=503, detail="Auth not configured")
    ip = _client_ip(request)
    if not _login_rate_limit_check(ip):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again in an hour.")
    row = db_user_by_email(body.email.strip().lower())
    if not row or not _verify_password(body.password, row[2]):
        _login_rate_limit_record(ip)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = _create_token(row[0], row[1])
    return {"token": token, "user": {"id": row[0], "email": row[1], "free_tier_used": bool(row[3])}}


@app.post("/api/refresh")
async def refresh(user: Dict[str, Any] = Depends(get_current_user)):
    """Issue new token (7-day expiry)."""
    token = _create_token(user["id"], user["email"])
    return {"token": token, "user": {"id": user["id"], "email": user["email"], "free_tier_used": user["free_tier_used"]}}


@app.get("/api/me")
async def me(user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """Current user or null if not logged in."""
    return user


@app.get("/api/audits")
async def list_audits(user: Dict[str, Any] = Depends(get_current_user)):
    """List current user's audits (metadata only)."""
    rows = db_audits_by_user_id(user["id"])
    return [
        {
            "id": r[0],
            "url": r[1],
            "status": r[2],
            "created_at": r[3],
            "paid": r[4] is not None,
        }
        for r in rows
    ]


@app.post("/api/claim-free-audit")
async def claim_free_audit(body: ClaimFreeRequest):
    """Claim one free full audit: create account (if new), create audit, return audit_id + token + temp_password."""
    if not JWT_SECRET or not pwd_ctx:
        raise HTTPException(status_code=503, detail="Auth not configured (set JWT_SECRET)")
    email = body.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email required")
    url = normalize_url(body.url)
    if _is_excluded(url):
        raise HTTPException(status_code=400, detail=EXCLUSION_MESSAGE)
    import uuid
    import secrets
    audit_id = str(uuid.uuid4())[:8]
    temp_password = secrets.token_urlsafe(10)
    password_hash = _hash_password(temp_password)
    row = db_user_by_email(email)
    if row:
        user_id = row[0]
        token = _create_token(user_id, row[1])
        free_tier_used = bool(row[3])
        if free_tier_used:
            raise HTTPException(
                status_code=400,
                detail="You've already used your free audit. Upgrade for unlimited audits."
            )
    else:
        user_id = str(uuid.uuid4())[:12]
        db_user_create(user_id, email, password_hash)
        token = _create_token(user_id, email)
        free_tier_used = False
    db_create(url, audit_id, user_id=user_id)
    return {
        "audit_id": audit_id,
        "token": token,
        "temp_password": temp_password,
        "user": {"id": user_id, "email": email, "free_tier_used": free_tier_used},
    }


@app.post("/api/create-checkout")
async def create_checkout(request: Request, body: AuditRequest):
    """Create Stripe Checkout Session for $49; store audit_id in metadata; return checkout URL."""
    if not stripe or not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Stripe is not configured (set STRIPE_SECRET_KEY)")
    if db_count_audits_today() >= MAX_DAILY_AUDITS:
        raise HTTPException(
            status_code=429,
            detail=f"Daily limit reached ({MAX_DAILY_AUDITS} audits per day). Try again tomorrow."
        )
    stripe.api_key = STRIPE_SECRET_KEY
    import uuid
    url = normalize_url(body.url)
    if _is_excluded(url):
        raise HTTPException(status_code=400, detail=EXCLUSION_MESSAGE)
    audit_id = str(uuid.uuid4())[:8]
    db_create(url, audit_id)
    base = str(request.base_url).rstrip("/")
    success_url = f"{base}/audit/{audit_id}?paid=true"
    cancel_url = base + "/"
    try:
        session = stripe.checkout.Session.create(
            mode="payment",
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "unit_amount": STRIPE_PRICE_CENTS,
                    "product_data": {"name": "Market Analysis", "description": f"One-time pricing intelligence report for {url}"},
                },
                "quantity": 1,
            }],
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={"audit_id": audit_id},
        )
        return {"checkout_url": session.url, "audit_id": audit_id}
    except stripe.error.StripeError as e:
        logger.warning("Stripe checkout error: %s", e)
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/stripe-webhook")
async def stripe_webhook(request: Request):
    """Handle checkout.session.completed: mark audit paid and log email confirmation."""
    if not stripe or not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Stripe not configured")
    payload = await request.body()
    sig = request.headers.get("Stripe-Signature", "")
    if STRIPE_WEBHOOK_SECRET:
        try:
            event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
        except stripe.error.SignatureVerificationError as e:
            logger.warning("Stripe webhook signature error: %s", e)
            raise HTTPException(status_code=400, detail="Invalid signature")
    else:
        logger.warning("STRIPE_WEBHOOK_SECRET not set; webhook signature not verified")
        event = json.loads(payload)
    if event.get("type") == "checkout.session.completed":
        session = event.get("data", {}).get("object", {})
        audit_id = (session.get("metadata") or {}).get("audit_id")
        if audit_id:
            db_set_paid(audit_id)
            logger.info("Email confirmation: Payment received for audit %s (customer can run audit at /audit/%s)", audit_id, audit_id)
    return {"received": True}


@app.get("/api/health")
async def api_health():
    """Return Ollama connection status and whether the model is available."""
    return get_ollama_health()


@app.post("/api/audit")
async def create_audit(request: AuditRequest, user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """Create new audit job. Optional auth: if logged in, audit is tied to user for free-trial logic."""
    import uuid
    url = normalize_url(request.url)
    if _is_excluded(url):
        raise HTTPException(status_code=400, detail=EXCLUSION_MESSAGE)
    audit_id = str(uuid.uuid4())[:8]
    user_id = user["id"] if user else None
    db_create(url, audit_id, user_id=user_id)
    return {"audit_id": audit_id, "url": url, "status": "pending"}

@app.get("/api/audit/{audit_id}")
async def get_audit(audit_id: str, user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """Get audit status/results. Audits with user_id are only visible to the owning user."""
    row = db_get(audit_id)
    if not row:
        raise HTTPException(status_code=404, detail="Audit not found")
    audit_user_id = db_audit_get_user_id(row)
    if audit_user_id is not None:
        if not user or user["id"] != audit_user_id:
            raise HTTPException(status_code=403, detail="Not authorized to view this audit")

    return {
        "id": row[0],
        "url": row[1],
        "status": row[2],
        "progress": row[3],
        "results": json.loads(row[4]) if row[4] else None,
        "created_at": row[5],
        "paid": db_is_paid(row),
    }

@app.websocket("/ws/{audit_id}")
async def websocket_endpoint(websocket: WebSocket, audit_id: str):
    """WebSocket for real-time agent progress. Pass ?token=JWT for owned audits."""
    logger.info("WebSocket connect: audit_id=%s", audit_id)
    await websocket.accept()
    logger.info("WebSocket accepted: audit_id=%s", audit_id)

    row = db_get(audit_id)
    if not row:
        await websocket.send_json({"error": "Audit not found"})
        await websocket.close()
        return

    audit_user_id = db_audit_get_user_id(row)
    if audit_user_id is not None:
        token = websocket.query_params.get("token") or (websocket.headers.get("Authorization") or "").replace("Bearer ", "").strip()
        payload = _decode_token(token) if token else None
        if not payload or payload.get("sub") != audit_user_id:
            await websocket.send_json({"error": "Not authorized to run this audit"})
            await websocket.close()
            return

    target_url = row[1]
    if _is_excluded(target_url):
        await websocket.send_json({
            "type": "complete",
            "data": {"excluded": True, "message": EXCLUSION_MESSAGE},
            "all_findings": [],
        })
        await websocket.close()
        return
    is_paid = db_is_paid(row)
    user_id = db_audit_get_user_id(row)
    user_row = db_user_by_id(user_id) if user_id else None
    free_trial_available = user_row is not None and not bool(user_row[3])  # free_tier_used at index 3
    run_full_free = not is_paid and free_trial_available  # one free full audit per user

    # Paid: use cache or run full 10-agent hunt.
    if is_paid:
        cached = db_get_cached_result(target_url)
    else:
        cached = None
    if is_paid and cached:
        _cached_id, cached_payload = cached
        if cached_payload and isinstance(cached_payload, dict):
            db_update(
                audit_id,
                status='completed',
                progress=100,
                results=json.dumps(cached_payload)
            )
            findings = cached_payload.get('findings') or []
            consensus = cached_payload.get('consensus') or {}
            await websocket.send_json({
                "type": "complete",
                "data": consensus,
                "all_findings": findings,
                "cached": True
            })
            await websocket.close()
            return

    # Run full 10-agent hunt for all audits (paid, free trial, or preview).
    # Preview free = full audit for testing; free_tier_used only set when run_full_free and user_id.
    global _current_audit_id
    if _current_audit_id is not None:
        await websocket.send_json({"error": "Audit in progress, please wait."})
        await websocket.close()
        return

    if OLLAMA_PACKAGE_AVAILABLE and not USE_MOCK_LLM:
        health = get_ollama_health()
        if not health["connected"]:
            err = health.get("error_message") or "Ollama not running. Start it with 'ollama serve'"
            await websocket.send_json({"error": err})
            await websocket.close()
            db_update(audit_id, status='error')
            return

    _current_audit_id = audit_id
    db_update(audit_id, status='running')
    cancelled_event = asyncio.Event()

    async def receive_stop():
        try:
            while True:
                msg = await websocket.receive_text()
                try:
                    data = json.loads(msg)
                    if data.get("action") == "stop":
                        cancelled_event.set()
                        break
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

    recv_task = asyncio.create_task(receive_stop())
    try:
        logger.info("hunt() starting (full): audit_id=%s url=%s free_trial=%s", audit_id, target_url, run_full_free)
        swarm = ShadowSwarm(audit_id, websocket)
        await swarm.hunt(target_url, cancelled_event, preview=False)
        logger.info("hunt() finished: audit_id=%s", audit_id)
        if run_full_free and user_id:
            db_user_set_free_tier_used(user_id)
            logger.info("Free tier marked used for user_id=%s", user_id)
    except WebSocketDisconnect:
        cancelled_event.set()
        logger.info("Client disconnected for audit %s", audit_id)
    except OllamaNotRunningError as e:
        await websocket.send_json({"error": str(e)})
        db_update(audit_id, status='error')
    except Exception as e:
        await websocket.send_json({"error": str(e)})
        db_update(audit_id, status='error')
    finally:
        recv_task.cancel()
        try:
            await recv_task
        except asyncio.CancelledError:
            pass
        _current_audit_id = None
        await websocket.close()

# Auditor dashboard (SPA) at /app and /audit; landing page stays at /
_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


@app.get("/app")
@app.get("/audit")
async def auditor_app():
    """Serve the auditor tool UI. Landing page remains at /."""
    path = os.path.join(_STATIC_DIR, "app.html")
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Auditor app not found")
    return FileResponse(path, media_type="text/html")

# Redirect /audit/{audit_id} to /app?audit_id=xxx (preserve ?paid=true for Stripe success)
@app.get("/audit/{audit_id}")
async def audit_redirect(audit_id: str, request: Request):
    url = f"/app?audit_id={audit_id}"
    if request.query_params.get("paid") == "true":
        url += "&paid=true"
    return RedirectResponse(url=url, status_code=302)


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Return 404 page for non-API paths; API 404s return JSON."""
    from fastapi.responses import JSONResponse
    if request.url.path.startswith("/api/") or request.url.path.startswith("/ws/"):
        return JSONResponse(content={"detail": "Not found"}, status_code=404)
    path_404 = os.path.join(_STATIC_DIR, "404.html")
    if os.path.isfile(path_404):
        return FileResponse(path_404, status_code=404)
    return JSONResponse(content={"detail": "Not found"}, status_code=404)

# Serve static files (frontend) — use absolute path so it works regardless of cwd
if os.path.isdir(_STATIC_DIR):
    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="static")

def _log_startup_ollama_status():
    """Log Ollama version and model status at startup."""
    if USE_MOCK_LLM:
        logger.info("Mock mode: USE_MOCK_LLM=1. Agents return sample data.")
        return
    if not OLLAMA_PACKAGE_AVAILABLE:
        logger.info("Mock mode: Ollama package not installed. pip install ollama for real analysis.")
        return
    health = get_ollama_health()
    if health["connected"]:
        version = health.get("version") or "unknown"
        logger.info("Ollama version: %s", version)
        if health["model_available"]:
            logger.info("Model %s is loaded and ready.", MODEL_NAME)
        else:
            path = health.get("ollama_path")
            display_cmd = f'"{path}" pull {MODEL_NAME}' if path else f"ollama pull {MODEL_NAME}"
            logger.info("Model %s not found. Running pull in background (or run: %s)", MODEL_NAME, display_cmd)
            _run_ollama_pull()
    else:
        msg = health.get("error_message") or "Ollama not running. Start it with 'ollama serve'"
        logger.warning("%s — Audits will show an error until Ollama is running.", msg)


if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    logger.info("Starting Shadow Pricing Auditor — http://localhost:8000")
    if TEST_MODE:
        logger.info("TEST_MODE=1: skipping Ollama, simulating 1s per agent")
    _log_startup_ollama_status()
    uvicorn.run(app, host="0.0.0.0", port=8000)
