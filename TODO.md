# TODO

## Security

### Completed
- [x] Fix SQL injection vulnerability in `bin/query` - now validates IP format before query
- [x] Fix SQL injection vulnerability in `query_db.sh` - now validates IP format before query
- [x] Use environment variables instead of hardcoded credentials - credentials now read from `.env` file
- [x] Add network segmentation - database now on internal-only `backend` network, not exposed to host
- [x] Add rate limiting middleware - sliding window rate limiter (default: 100 requests/60s per IP)

## Features

### API / Programmatic Access
- [x] Add REST API (`web_server.py`) with endpoints:
  - `GET /api/lookup/{ip}` - lookup IP address
  - `GET /api/search/netname` - search by network name
  - `GET /api/search/description` - full-text search
  - `GET /api/search/country` - search by country code
  - `GET /api/stats` - database statistics
  - Input validation using Pydantic
  - Rate limiting with `X-RateLimit-*` headers

### MCP Server (AI Integration)
- [x] Create MCP server (`mcp_server.py`) to allow AI assistants to query the database
  - Tool: `lookup_ip` - find network blocks containing an IP
  - Tool: `search_by_netname` - search by network name
  - Tool: `search_by_description` - full-text search on descriptions
  - Tool: `search_by_country` - filter by country code
  - Tool: `get_stats` - get database statistics

### Web Frontend
- [x] Add simple web UI for IP lookups (`web_server.py` serves at `/`)
  - Single HTML page with tabbed search forms
  - IP lookup, netname search, description search, country search
  - Responsive design with result cards

## Code Quality

### Completed
- [x] Update deprecated `declarative_base()` import in `db/helper.py`
- [x] Refactor global mutable state in `create_db.py` - now uses `ParserContext` dataclass
- [x] Add type hints throughout codebase (`create_db.py`, `db/helper.py`, `db/model.py`)
- [x] Add unit tests for parsing functions (`tests/test_parser.py`)
