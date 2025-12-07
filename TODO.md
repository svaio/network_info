# TODO

## Security

### High Priority
- [ ] Add rate limiting if API is exposed publicly

### Completed
- [x] Fix SQL injection vulnerability in `bin/query` - now validates IP format before query
- [x] Fix SQL injection vulnerability in `query_db.sh` - now validates IP format before query
- [x] Use environment variables instead of hardcoded credentials - credentials now read from `.env` file
- [x] Add network segmentation - database now on internal-only `backend` network, not exposed to host

## Features

### API / Programmatic Access
- [ ] Add REST API (FastAPI recommended) with endpoints:
  - `GET /lookup/{ip}` - lookup IP address
  - `GET /search?netname=...&country=...` - search by fields
  - Input validation using Pydantic
  - Rate limiting middleware

### MCP Server (AI Integration)
- [x] Create MCP server (`mcp_server.py`) to allow AI assistants to query the database
  - Tool: `lookup_ip` - find network blocks containing an IP
  - Tool: `search_by_netname` - search by network name
  - Tool: `search_by_description` - full-text search on descriptions
  - Tool: `search_by_country` - filter by country code
  - Tool: `get_stats` - get database statistics

### Web Frontend
- [ ] Add simple web UI for IP lookups
  - Single HTML page with search form
  - Display results in readable format
  - Could be served by FastAPI static files

## Code Quality

### Low Priority
- [ ] Update deprecated `declarative_base()` import in `db/helper.py` to `from sqlalchemy.orm import declarative_base`
- [ ] Refactor global mutable state (`NUM_BLOCKS`, `CURRENT_FILENAME`) in `create_db.py` to pass state explicitly
- [ ] Add type hints throughout codebase
- [ ] Add unit tests for parsing functions
