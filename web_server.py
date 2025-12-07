#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Server for Network Info Database

Provides a simple web UI and REST API for querying the network information database.

Usage:
    python web_server.py

    Or with uvicorn for production:
    uvicorn web_server:app --host 0.0.0.0 --port 8000

Environment Variables:
    DATABASE_URL: PostgreSQL connection string
                  Example: postgresql+psycopg://user:pass@localhost:5432/network_info

    Or individual variables:
    POSTGRES_USER: Database username (default: network_info)
    POSTGRES_PASSWORD: Database password (required)
    POSTGRES_HOST: Database host (default: localhost)
    POSTGRES_PORT: Database port (default: 5432)
    POSTGRES_DB: Database name (default: network_info)

    Rate limiting:
    RATE_LIMIT_REQUESTS: Max requests per window (default: 100)
    RATE_LIMIT_WINDOW: Window size in seconds (default: 60)
"""

import os
import re
import time
import ipaddress
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Database connection
_engine = None
_Session = None

# Rate limiting configuration
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))


class RateLimiter:
    """Simple in-memory rate limiter using sliding window."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, client_id: str) -> tuple[bool, dict]:
        """Check if request is allowed and return rate limit info."""
        now = time.time()
        window_start = now - self.window_seconds

        # Clean old requests
        self.requests[client_id] = [
            ts for ts in self.requests[client_id] if ts > window_start
        ]

        current_count = len(self.requests[client_id])
        remaining = max(0, self.max_requests - current_count)

        if current_count >= self.max_requests:
            # Calculate retry after
            oldest = min(self.requests[client_id]) if self.requests[client_id] else now
            retry_after = int(oldest + self.window_seconds - now) + 1
            return False, {
                "X-RateLimit-Limit": str(self.max_requests),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(window_start + self.window_seconds)),
                "Retry-After": str(retry_after),
            }

        # Record this request
        self.requests[client_id].append(now)

        return True, {
            "X-RateLimit-Limit": str(self.max_requests),
            "X-RateLimit-Remaining": str(remaining - 1),
            "X-RateLimit-Reset": str(int(now + self.window_seconds)),
        }


rate_limiter = RateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW)


def get_database_url() -> str:
    """Build database URL from environment variables."""
    if url := os.environ.get("DATABASE_URL"):
        return url

    user = os.environ.get("POSTGRES_USER", "network_info")
    password = os.environ.get("POSTGRES_PASSWORD")
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "network_info")

    if not password:
        raise ValueError(
            "POSTGRES_PASSWORD environment variable is required. "
            "Set DATABASE_URL or POSTGRES_PASSWORD."
        )

    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{db}"


def get_session():
    """Get a database session."""
    global _engine, _Session

    if _engine is None:
        _engine = create_engine(get_database_url())
        _Session = sessionmaker(bind=_engine)

    return _Session()


def validate_ip(ip: str) -> bool:
    """Validate an IP address (IPv4 or IPv6)."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def sanitize_search_term(term: str) -> str:
    """Sanitize search term for safe use in queries."""
    return re.sub(r"[^\w\s\-\.]", "", term)[:200]


def format_block(row) -> dict:
    """Format a database row as a dictionary."""
    return {
        "inetnum": str(row.inetnum) if row.inetnum else None,
        "netname": row.netname,
        "description": row.description,
        "country": row.country,
        "maintained_by": row.maintained_by,
        "created": str(row.created) if row.created else None,
        "last_modified": str(row.last_modified) if row.last_modified else None,
        "source": row.source,
        "status": row.status,
    }


# Pydantic models for API responses
class BlockResult(BaseModel):
    inetnum: Optional[str] = None
    netname: Optional[str] = None
    description: Optional[str] = None
    country: Optional[str] = None
    maintained_by: Optional[str] = None
    created: Optional[str] = None
    last_modified: Optional[str] = None
    source: Optional[str] = None
    status: Optional[str] = None


class SearchResponse(BaseModel):
    results: list[BlockResult]
    count: int


class StatsResponse(BaseModel):
    total_blocks: int
    by_source: dict[str, int]


class ErrorResponse(BaseModel):
    error: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: verify database connection
    try:
        session = get_session()
        session.execute(text("SELECT 1"))
        session.close()
    except Exception as e:
        print(f"Warning: Could not connect to database: {e}")
    yield
    # Shutdown
    global _engine
    if _engine:
        _engine.dispose()


app = FastAPI(
    title="Network Info API",
    description="Query WHOIS data from all Regional Internet Registries",
    version="1.0.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Apply rate limiting to API endpoints."""
    # Only rate limit API endpoints, not the web UI
    if request.url.path.startswith("/api/"):
        # Use client IP as identifier (supports X-Forwarded-For for proxies)
        client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if not client_ip:
            client_ip = request.client.host if request.client else "unknown"

        allowed, headers = rate_limiter.is_allowed(client_ip)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please try again later."},
                headers=headers,
            )

        response = await call_next(request)
        # Add rate limit headers to response
        for key, value in headers.items():
            response.headers[key] = value
        return response

    return await call_next(request)


# HTML template for the web UI
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Info Lookup</title>
    <style>
        * {
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #7f8c8d;
            margin-bottom: 30px;
        }
        .search-container {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .search-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .search-tab {
            padding: 10px 20px;
            border: none;
            background: #ecf0f1;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }
        .search-tab:hover {
            background: #bdc3c7;
        }
        .search-tab.active {
            background: #3498db;
            color: white;
        }
        .search-form {
            display: none;
        }
        .search-form.active {
            display: block;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #2c3e50;
        }
        input[type="text"], input[type="number"], select {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
        }
        input[type="text"]:focus, input[type="number"]:focus {
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2);
        }
        button[type="submit"] {
            background: #3498db;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.2s;
        }
        button[type="submit"]:hover {
            background: #2980b9;
        }
        button[type="submit"]:disabled {
            background: #bdc3c7;
            cursor: not-allowed;
        }
        .results-container {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #eee;
        }
        .results-count {
            color: #7f8c8d;
        }
        .result-card {
            border: 1px solid #eee;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            transition: box-shadow 0.2s;
        }
        .result-card:hover {
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 10px;
            flex-wrap: wrap;
            gap: 10px;
        }
        .result-inetnum {
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 16px;
            font-weight: 600;
            color: #2c3e50;
        }
        .result-badges {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        .badge {
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
        }
        .badge-source {
            background: #e8f4fd;
            color: #2980b9;
        }
        .badge-country {
            background: #e8f8f5;
            color: #27ae60;
        }
        .badge-status {
            background: #fef5e7;
            color: #f39c12;
        }
        .result-netname {
            font-weight: 500;
            color: #34495e;
            margin-bottom: 5px;
        }
        .result-description {
            color: #7f8c8d;
            font-size: 14px;
            line-height: 1.5;
        }
        .result-meta {
            display: flex;
            gap: 20px;
            margin-top: 10px;
            font-size: 12px;
            color: #95a5a6;
            flex-wrap: wrap;
        }
        .loading {
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
        }
        .error {
            background: #fee;
            border: 1px solid #fcc;
            color: #c00;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        .no-results {
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
        }
        .inline-fields {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        .inline-fields .form-group {
            flex: 1;
            min-width: 150px;
        }
        @media (max-width: 600px) {
            .search-tabs {
                flex-direction: column;
            }
            .search-tab {
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <h1>Network Info Lookup</h1>
    <p class="subtitle">Query WHOIS data from ARIN, APNIC, RIPE, LACNIC, and AfriNIC</p>

    <div class="search-container">
        <div class="search-tabs">
            <button class="search-tab active" data-tab="ip">IP Lookup</button>
            <button class="search-tab" data-tab="netname">Search by Netname</button>
            <button class="search-tab" data-tab="description">Search Description</button>
            <button class="search-tab" data-tab="country">Search by Country</button>
        </div>

        <form id="ip-form" class="search-form active" data-tab="ip">
            <div class="form-group">
                <label for="ip-input">IP Address (IPv4 or IPv6)</label>
                <input type="text" id="ip-input" name="ip" placeholder="e.g., 8.8.8.8 or 2001:db8::1" required>
            </div>
            <button type="submit">Look Up</button>
        </form>

        <form id="netname-form" class="search-form" data-tab="netname">
            <div class="form-group">
                <label for="netname-input">Network Name</label>
                <input type="text" id="netname-input" name="netname" placeholder="e.g., GOOGLE, AMAZON" required minlength="2">
            </div>
            <div class="inline-fields">
                <div class="form-group">
                    <label for="netname-limit">Max Results</label>
                    <input type="number" id="netname-limit" name="limit" value="20" min="1" max="100">
                </div>
                <div class="form-group">
                    <label for="netname-exact">Match Type</label>
                    <select id="netname-exact" name="exact_match">
                        <option value="false">Contains</option>
                        <option value="true">Exact Match</option>
                    </select>
                </div>
            </div>
            <button type="submit">Search</button>
        </form>

        <form id="description-form" class="search-form" data-tab="description">
            <div class="form-group">
                <label for="description-input">Search Text</label>
                <input type="text" id="description-input" name="search_text" placeholder="e.g., cloud hosting, data center" required minlength="2">
            </div>
            <div class="form-group">
                <label for="description-limit">Max Results</label>
                <input type="number" id="description-limit" name="limit" value="20" min="1" max="100">
            </div>
            <button type="submit">Search</button>
        </form>

        <form id="country-form" class="search-form" data-tab="country">
            <div class="form-group">
                <label for="country-input">Country Code</label>
                <input type="text" id="country-input" name="country_code" placeholder="e.g., US, DE, JP" required minlength="2" maxlength="10">
            </div>
            <div class="inline-fields">
                <div class="form-group">
                    <label for="country-netname">Netname Filter (optional)</label>
                    <input type="text" id="country-netname" name="netname_filter" placeholder="e.g., AMAZON">
                </div>
                <div class="form-group">
                    <label for="country-limit">Max Results</label>
                    <input type="number" id="country-limit" name="limit" value="20" min="1" max="100">
                </div>
            </div>
            <button type="submit">Search</button>
        </form>
    </div>

    <div id="results" class="results-container" style="display: none;">
        <div class="results-header">
            <h2>Results</h2>
            <span id="results-count" class="results-count"></span>
        </div>
        <div id="results-content"></div>
    </div>

    <script>
        // Tab switching
        document.querySelectorAll('.search-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.search-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.search-form').forEach(f => f.classList.remove('active'));
                tab.classList.add('active');
                document.querySelector(`.search-form[data-tab="${tab.dataset.tab}"]`).classList.add('active');
            });
        });

        // Form submissions
        document.getElementById('ip-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const ip = document.getElementById('ip-input').value.trim();
            await fetchResults(`/api/lookup/${encodeURIComponent(ip)}`);
        });

        document.getElementById('netname-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const netname = document.getElementById('netname-input').value.trim();
            const limit = document.getElementById('netname-limit').value;
            const exactMatch = document.getElementById('netname-exact').value;
            await fetchResults(`/api/search/netname?netname=${encodeURIComponent(netname)}&limit=${limit}&exact_match=${exactMatch}`);
        });

        document.getElementById('description-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const text = document.getElementById('description-input').value.trim();
            const limit = document.getElementById('description-limit').value;
            await fetchResults(`/api/search/description?search_text=${encodeURIComponent(text)}&limit=${limit}`);
        });

        document.getElementById('country-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const country = document.getElementById('country-input').value.trim();
            const netname = document.getElementById('country-netname').value.trim();
            const limit = document.getElementById('country-limit').value;
            let url = `/api/search/country?country_code=${encodeURIComponent(country)}&limit=${limit}`;
            if (netname) url += `&netname_filter=${encodeURIComponent(netname)}`;
            await fetchResults(url);
        });

        async function fetchResults(url) {
            const resultsDiv = document.getElementById('results');
            const contentDiv = document.getElementById('results-content');
            const countSpan = document.getElementById('results-count');

            resultsDiv.style.display = 'block';
            contentDiv.innerHTML = '<div class="loading">Loading...</div>';

            try {
                const response = await fetch(url);
                const data = await response.json();

                if (!response.ok) {
                    contentDiv.innerHTML = `<div class="error">${data.detail || data.error || 'An error occurred'}</div>`;
                    countSpan.textContent = '';
                    return;
                }

                if (data.count === 0) {
                    contentDiv.innerHTML = '<div class="no-results">No results found</div>';
                    countSpan.textContent = '0 results';
                    return;
                }

                countSpan.textContent = `${data.count} result${data.count !== 1 ? 's' : ''}`;
                contentDiv.innerHTML = data.results.map(block => `
                    <div class="result-card">
                        <div class="result-header">
                            <span class="result-inetnum">${escapeHtml(block.inetnum || 'N/A')}</span>
                            <div class="result-badges">
                                ${block.source ? `<span class="badge badge-source">${escapeHtml(block.source)}</span>` : ''}
                                ${block.country ? `<span class="badge badge-country">${escapeHtml(block.country.split(' ')[0])}</span>` : ''}
                                ${block.status ? `<span class="badge badge-status">${escapeHtml(block.status)}</span>` : ''}
                            </div>
                        </div>
                        ${block.netname ? `<div class="result-netname">${escapeHtml(block.netname)}</div>` : ''}
                        ${block.description ? `<div class="result-description">${escapeHtml(block.description)}</div>` : ''}
                        <div class="result-meta">
                            ${block.maintained_by ? `<span>Maintained by: ${escapeHtml(block.maintained_by)}</span>` : ''}
                            ${block.last_modified ? `<span>Updated: ${escapeHtml(block.last_modified)}</span>` : ''}
                        </div>
                    </div>
                `).join('');
            } catch (error) {
                contentDiv.innerHTML = `<div class="error">Failed to fetch results: ${escapeHtml(error.message)}</div>`;
                countSpan.textContent = '';
            }
        }

        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def home():
    """Serve the web UI."""
    return HTML_TEMPLATE


@app.get("/api/lookup/{ip_address}", response_model=SearchResponse)
async def lookup_ip(ip_address: str):
    """
    Look up network blocks containing a specific IP address.

    Returns all CIDR ranges from WHOIS databases that contain the given IP,
    ordered from most specific (smallest range) to least specific.
    """
    if not validate_ip(ip_address):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    session = get_session()
    try:
        query = text("""
            SELECT inetnum, netname, description, country, maintained_by,
                   created, last_modified, source, status
            FROM block
            WHERE inetnum >> :ip
            ORDER BY inetnum DESC
            LIMIT 50
        """)
        result = session.execute(query, {"ip": ip_address})
        rows = result.fetchall()

        blocks = [format_block(row) for row in rows]
        return {"results": blocks, "count": len(blocks)}
    finally:
        session.close()


@app.get("/api/search/netname", response_model=SearchResponse)
async def search_by_netname(
    netname: str = Query(..., min_length=2, description="Network name to search for"),
    limit: int = Query(20, ge=1, le=100, description="Maximum number of results"),
    exact_match: bool = Query(False, description="If true, match exact name"),
):
    """Search for network blocks by network name."""
    netname = sanitize_search_term(netname)

    session = get_session()
    try:
        if exact_match:
            query = text("""
                SELECT inetnum, netname, description, country, maintained_by,
                       created, last_modified, source, status
                FROM block
                WHERE netname = :netname
                ORDER BY last_modified DESC NULLS LAST
                LIMIT :limit
            """)
            result = session.execute(query, {"netname": netname, "limit": limit})
        else:
            query = text("""
                SELECT inetnum, netname, description, country, maintained_by,
                       created, last_modified, source, status
                FROM block
                WHERE netname ILIKE :pattern
                ORDER BY last_modified DESC NULLS LAST
                LIMIT :limit
            """)
            result = session.execute(query, {"pattern": f"%{netname}%", "limit": limit})

        rows = result.fetchall()
        blocks = [format_block(row) for row in rows]
        return {"results": blocks, "count": len(blocks)}
    finally:
        session.close()


@app.get("/api/search/description", response_model=SearchResponse)
async def search_by_description(
    search_text: str = Query(..., min_length=2, description="Text to search for"),
    limit: int = Query(20, ge=1, le=100, description="Maximum number of results"),
):
    """Full-text search on network block descriptions."""
    search_text = sanitize_search_term(search_text)

    session = get_session()
    try:
        query = text("""
            SELECT inetnum, netname, description, country, maintained_by,
                   created, last_modified, source, status
            FROM block
            WHERE to_tsvector('english', description) @@ plainto_tsquery('english', :search_text)
            ORDER BY ts_rank(to_tsvector('english', description), plainto_tsquery('english', :search_text)) DESC
            LIMIT :limit
        """)
        result = session.execute(query, {"search_text": search_text, "limit": limit})
        rows = result.fetchall()

        blocks = [format_block(row) for row in rows]
        return {"results": blocks, "count": len(blocks)}
    finally:
        session.close()


@app.get("/api/search/country", response_model=SearchResponse)
async def search_by_country(
    country_code: str = Query(..., min_length=2, description="ISO country code"),
    limit: int = Query(20, ge=1, le=100, description="Maximum number of results"),
    netname_filter: Optional[str] = Query(None, description="Optional netname filter"),
):
    """Search for network blocks by country code."""
    country_code = sanitize_search_term(country_code).upper()

    session = get_session()
    try:
        if netname_filter:
            netname_filter = sanitize_search_term(netname_filter)
            query = text("""
                SELECT inetnum, netname, description, country, maintained_by,
                       created, last_modified, source, status
                FROM block
                WHERE country ILIKE :country_pattern
                  AND netname ILIKE :netname_pattern
                ORDER BY last_modified DESC NULLS LAST
                LIMIT :limit
            """)
            result = session.execute(
                query,
                {
                    "country_pattern": f"{country_code}%",
                    "netname_pattern": f"%{netname_filter}%",
                    "limit": limit,
                },
            )
        else:
            query = text("""
                SELECT inetnum, netname, description, country, maintained_by,
                       created, last_modified, source, status
                FROM block
                WHERE country ILIKE :country_pattern
                ORDER BY last_modified DESC NULLS LAST
                LIMIT :limit
            """)
            result = session.execute(query, {"country_pattern": f"{country_code}%", "limit": limit})

        rows = result.fetchall()
        blocks = [format_block(row) for row in rows]
        return {"results": blocks, "count": len(blocks)}
    finally:
        session.close()


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """Get statistics about the network info database."""
    session = get_session()
    try:
        total_result = session.execute(text("SELECT COUNT(*) FROM block"))
        total_count = total_result.scalar()

        source_result = session.execute(
            text("SELECT source, COUNT(*) as count FROM block GROUP BY source ORDER BY count DESC")
        )
        sources = {row.source: row.count for row in source_result.fetchall()}

        return {"total_blocks": total_count, "by_source": sources}
    finally:
        session.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
