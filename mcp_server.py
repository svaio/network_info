#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MCP Server for Network Info Database

Provides tools for AI assistants to query the network information database
containing WHOIS data from all Regional Internet Registries (RIRs).

Usage:
    python mcp_server.py

Environment Variables:
    DATABASE_URL: PostgreSQL connection string (required)
                  Example: postgresql+psycopg://user:pass@localhost:5432/network_info

    Or individual variables:
    POSTGRES_USER: Database username (default: network_info)
    POSTGRES_PASSWORD: Database password (required)
    POSTGRES_HOST: Database host (default: localhost)
    POSTGRES_PORT: Database port (default: 5432)
    POSTGRES_DB: Database name (default: network_info)
"""

import os
import re
import ipaddress
from typing import Optional

from mcp.server.fastmcp import FastMCP
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Initialize MCP server
mcp = FastMCP(name="Network Info")

# Database connection
_engine = None
_Session = None


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
    # Remove any characters that could be problematic
    # Allow alphanumeric, spaces, hyphens, underscores, dots
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


@mcp.tool()
def lookup_ip(ip_address: str) -> dict:
    """
    Look up network blocks containing a specific IP address.

    Finds all CIDR ranges from WHOIS databases that contain the given IP,
    ordered from most specific (smallest range) to least specific.

    Args:
        ip_address: IPv4 or IPv6 address to look up (e.g., "8.8.8.8" or "2001:db8::1")

    Returns:
        Dictionary with 'results' list of matching network blocks and 'count'.
        Each block contains: inetnum, netname, description, country,
        maintained_by, created, last_modified, source, status.
    """
    if not validate_ip(ip_address):
        return {"error": "Invalid IP address format", "results": [], "count": 0}

    session = get_session()
    try:
        # Use PostgreSQL's >> operator for CIDR containment
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


@mcp.tool()
def search_by_netname(
    netname: str, limit: int = 20, exact_match: bool = False
) -> dict:
    """
    Search for network blocks by network name.

    Args:
        netname: Network name to search for (e.g., "GOOGLE", "AMAZON")
        limit: Maximum number of results (default: 20, max: 100)
        exact_match: If True, match exact name. If False, use pattern matching.

    Returns:
        Dictionary with 'results' list of matching network blocks and 'count'.
    """
    if not netname or len(netname.strip()) < 2:
        return {"error": "Search term must be at least 2 characters", "results": [], "count": 0}

    netname = sanitize_search_term(netname)
    limit = min(max(1, limit), 100)

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


@mcp.tool()
def search_by_description(search_text: str, limit: int = 20) -> dict:
    """
    Full-text search on network block descriptions.

    Uses PostgreSQL full-text search to find blocks with matching descriptions.
    Supports natural language queries.

    Args:
        search_text: Text to search for in descriptions (e.g., "cloud hosting")
        limit: Maximum number of results (default: 20, max: 100)

    Returns:
        Dictionary with 'results' list of matching network blocks and 'count'.
    """
    if not search_text or len(search_text.strip()) < 2:
        return {"error": "Search term must be at least 2 characters", "results": [], "count": 0}

    search_text = sanitize_search_term(search_text)
    limit = min(max(1, limit), 100)

    session = get_session()
    try:
        # Use PostgreSQL full-text search with the GIN index
        # Convert search text to tsquery format (words joined by &)
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


@mcp.tool()
def search_by_country(
    country_code: str, limit: int = 20, netname_filter: Optional[str] = None
) -> dict:
    """
    Search for network blocks by country code.

    Args:
        country_code: ISO country code (e.g., "US", "DE", "JP")
        limit: Maximum number of results (default: 20, max: 100)
        netname_filter: Optional additional filter on network name

    Returns:
        Dictionary with 'results' list of matching network blocks and 'count'.
    """
    if not country_code or len(country_code.strip()) < 2:
        return {"error": "Country code must be at least 2 characters", "results": [], "count": 0}

    country_code = sanitize_search_term(country_code).upper()
    limit = min(max(1, limit), 100)

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


@mcp.tool()
def get_stats() -> dict:
    """
    Get statistics about the network info database.

    Returns:
        Dictionary with total block count and count per source registry.
    """
    session = get_session()
    try:
        # Total count
        total_result = session.execute(text("SELECT COUNT(*) FROM block"))
        total_count = total_result.scalar()

        # Count per source
        source_result = session.execute(
            text("SELECT source, COUNT(*) as count FROM block GROUP BY source ORDER BY count DESC")
        )
        sources = {row.source: row.count for row in source_result.fetchall()}

        return {
            "total_blocks": total_count,
            "by_source": sources,
        }
    finally:
        session.close()


if __name__ == "__main__":
    mcp.run()
