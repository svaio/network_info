# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Network Info Parser parses WHOIS databases from all five Regional Internet Registries (ARIN, APNIC, LACNIC, AfriNIC, RIPE) into a local PostgreSQL database. The parsed data enables IP address lookups and network range searches by company.

## Common Commands

### Docker (Recommended)

```bash
# Full run: build, start db, download dumps, parse
./bin/network_info

# Force rebuild images first
REBUILD=1 ./bin/network_info

# Query an IP address
./bin/query 8.8.8.8
./bin/query 2001:db8::1

# Interactive PostgreSQL prompt
./bin/psql

# Export block table to gzipped CSV
./bin/export_to_gzip
```

### Manual/Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Download database dumps (required before parsing)
./download_dumps.sh

# Run the parser
python create_db.py -c "postgresql+psycopg://user:pass@host:5432/database"
python create_db.py -c "..." -d  # Enable debug logging

# Run tests
pytest tests/ -v
```

## Architecture

### Database Schema

Single `block` table storing IP network blocks with PostgreSQL CIDR type for efficient IP lookups:
- `inetnum`: CIDR notation (indexed, supports `>>` containment operator)
- `netname`, `description`, `country`, `maintained_by`, `status`, `source`
- `created`, `last_modified`: timestamps
- Full-text search GIN index on `description`

### Code Structure

- `create_db.py`: Main parser using multiprocessing (workers = CPU count). Reads gzipped WHOIS dumps, parses blocks with regex, inserts via SQLAlchemy in batches of 10,000.
- `web_server.py`: FastAPI web server with REST API and web UI (see Web Server section below)
- `mcp_server.py`: MCP server for AI assistant integration (see MCP Server section below)
- `db/model.py`: SQLAlchemy `Block` model with PostgreSQL-specific CIDR column
- `db/helper.py`: Database connection setup with `create_db=True` option to reset schema
- `bin/`: Docker Compose wrapper scripts

### Data Sources

Parser processes these files from `./databases/`:
- `afrinic.db.gz`, `arin.db.gz`, `lacnic.db.gz`
- `apnic.db.inetnum.gz`, `apnic.db.inet6num.gz`
- `ripe.db.inetnum.gz`, `ripe.db.inet6num.gz`

### IP Lookup Query Pattern

```sql
SELECT * FROM block WHERE block.inetnum >> '8.8.8.8' ORDER BY block.inetnum DESC;
```

The `>>` operator finds all CIDR ranges containing the IP, ordered most-specific first.

## Web Server

FastAPI web server providing both a REST API and web UI.

### Running the Web Server

```bash
# Set environment variables
export POSTGRES_PASSWORD=your_password

# Run with uvicorn (development)
python web_server.py

# Or run with uvicorn directly (production)
uvicorn web_server:app --host 0.0.0.0 --port 8000
```

Access the web UI at `http://localhost:8000`

### REST API Endpoints

- `GET /api/lookup/{ip}` - Look up network blocks containing an IP
- `GET /api/search/netname?netname=...&limit=20&exact_match=false` - Search by network name
- `GET /api/search/description?search_text=...&limit=20` - Full-text search
- `GET /api/search/country?country_code=...&limit=20&netname_filter=...` - Search by country
- `GET /api/stats` - Get database statistics

API documentation available at `http://localhost:8000/docs` (Swagger UI)

## MCP Server

The MCP (Model Context Protocol) server allows AI assistants to query the network database.

### Running the MCP Server

```bash
# Set environment variables
export POSTGRES_PASSWORD=your_password
export POSTGRES_HOST=localhost

# Or use DATABASE_URL
export DATABASE_URL="postgresql+psycopg://user:pass@localhost:5432/network_info"

# Run the server
python mcp_server.py
```

### Available Tools

- `lookup_ip(ip_address)`: Find network blocks containing an IP (IPv4/IPv6)
- `search_by_netname(netname, limit, exact_match)`: Search by network name
- `search_by_description(search_text, limit)`: Full-text search on descriptions
- `search_by_country(country_code, limit, netname_filter)`: Filter by country code
- `get_stats()`: Get database statistics (total blocks, count per source)

### Claude Desktop Configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "network-info": {
      "command": "python",
      "args": ["/path/to/network_info/mcp_server.py"],
      "env": {
        "POSTGRES_PASSWORD": "your_password",
        "POSTGRES_HOST": "localhost"
      }
    }
  }
}
```
