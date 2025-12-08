#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database parser for Regional Internet Registry WHOIS data.

Parses WHOIS database dumps from ARIN, APNIC, LACNIC, AfriNIC, and RIPE
into a PostgreSQL database for IP address lookups.
"""

import argparse
import gzip
import logging
import os.path
import re
import time
from dataclasses import dataclass
from datetime import datetime
from multiprocessing import Process, Queue, cpu_count, current_process
from typing import Callable, Optional, Union

from netaddr import IPNetwork, iprange_to_cidrs
from sqlalchemy.dialects.postgresql import insert

from db.helper import setup_connection
from db.model import Base, Block

VERSION = "2.0"
FILELIST = [
    "afrinic.db.gz",
    "apnic.db.inet6num.gz",
    "apnic.db.inetnum.gz",
    "arin.db.gz",
    "lacnic.db.gz",
    "ripe.db.inetnum.gz",
    "ripe.db.inet6num.gz",
]
NUM_WORKERS = cpu_count()
LOG_FORMAT = "%(asctime)-15s - %(name)-9s - %(levelname)-8s - %(processName)-11s - %(filename)s - %(message)s"
COMMIT_COUNT = 10000


@dataclass
class ParserContext:
    """Context for tracking parser state across the application."""

    current_filename: str = "empty"
    num_blocks: int = 0


class ContextFilter(logging.Filter):
    """Logging filter that adds the current filename to log records."""

    def __init__(self, context: ParserContext):
        super().__init__()
        self.context = context

    def filter(self, record: logging.LogRecord) -> bool:
        record.filename = self.context.current_filename
        return True


def create_logger(context: ParserContext) -> logging.Logger:
    """
    Create and configure the logger for the parser.

    Args:
        context: Parser context for tracking current filename

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("create_db")
    logger.setLevel(logging.INFO)
    logger.addFilter(ContextFilter(context))
    formatter = logging.Formatter(LOG_FORMAT)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def get_source(filename: str) -> Optional[bytes]:
    """
    Determine the RIR source from the filename.

    Args:
        filename: Name of the database file

    Returns:
        Source identifier as bytes, or None if unknown
    """
    if filename.startswith("afrinic"):
        return b"afrinic"
    elif filename.startswith("apnic"):
        return b"apnic"
    elif filename.startswith("arin"):
        return b"arin"
    elif "lacnic" in filename:
        return b"lacnic"
    elif filename.startswith("ripe"):
        return b"ripe"
    return None


def parse_property(block: bytes, name: bytes) -> Optional[str]:
    """
    Extract a property value from a WHOIS block.

    Args:
        block: Raw WHOIS block data
        name: Property name to extract

    Returns:
        Property value as string, or None if not found
    """
    match = re.findall(b"^%s:\\s?(.+)$" % name, block, re.MULTILINE)
    if match:
        # Remove empty lines and multiple name occurrences
        x = b" ".join(
            list(
                filter(
                    None,
                    (
                        x.strip().replace(b"%s: " % name, b"").replace(b"%s: " % name, b"")
                        for x in match
                    ),
                )
            )
        )
        # Remove multiple whitespaces and decode to latin-1
        return " ".join(x.decode("latin-1").split())
    return None


def parse_property_inetnum(block: bytes) -> Optional[Union[list[IPNetwork], bytes]]:
    """
    Extract the IP range/CIDR from a WHOIS block.

    Handles various formats from different RIRs:
    - IPv4 ranges (start - end)
    - IPv4 CIDR notation
    - IPv6 CIDR notation
    - Route objects

    Args:
        block: Raw WHOIS block data

    Returns:
        List of IPNetwork objects, bytes CIDR, or None if not found
    """
    # IPv4 range format
    match = re.findall(
        rb"^inetnum:[\s]*((?:\d{1,3}\.){3}\d{1,3})[\s]*-[\s]*((?:\d{1,3}\.){3}\d{1,3})",
        block,
        re.MULTILINE,
    )
    if match:
        ip_start = match[0][0].decode("utf-8")
        ip_end = match[0][1].decode("utf-8")
        cidrs = iprange_to_cidrs(ip_start, ip_end)
        return cidrs

    # Direct CIDR in LACNIC db
    match = re.findall(
        rb"^inetnum:[\s]*((?:\d{1,3}\.){3}\d{1,3}/\d+)", block, re.MULTILINE
    )
    if match:
        return match[0]

    # LACNIC with incomplete IP (177.46.7/24)
    match = re.findall(
        rb"^inetnum:[\s]*((?:\d{1,3}\.){2}\d{1,3}/\d+)", block, re.MULTILINE
    )
    if match:
        tmp = match[0].split(b"/")
        return f"{tmp[0].decode('utf-8')}.0/{tmp[1].decode('utf-8')}".encode("utf-8")

    # LACNIC with incomplete IP (148.204/16)
    match = re.findall(
        rb"^inetnum:[\s]*((?:\d{1,3}\.){1}\d{1,3}/\d+)", block, re.MULTILINE
    )
    if match:
        tmp = match[0].split(b"/")
        return f"{tmp[0].decode('utf-8')}.0.0/{tmp[1].decode('utf-8')}".encode("utf-8")

    # IPv6
    match = re.findall(
        rb"^inet6num:[\s]*([0-9a-fA-F:\/]{1,43})", block, re.MULTILINE
    )
    if match:
        return match[0]

    # ARIN route IPv4
    match = re.findall(
        rb"^route:[\s]*((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})", block, re.MULTILINE
    )
    if match:
        return match[0]

    # ARIN route6 IPv6
    match = re.findall(
        rb"^route6:[\s]*([0-9a-fA-F:\/]{1,43})", block, re.MULTILINE
    )
    if match:
        return match[0]

    return None


def read_blocks(filename: str, logger: logging.Logger) -> list[bytes]:
    """
    Read and parse WHOIS blocks from a database file.

    Args:
        filename: Path to the database file (plain or gzipped)
        logger: Logger instance for output

    Returns:
        List of raw WHOIS blocks as bytes
    """
    open_method: Callable = gzip.open if filename.endswith(".gz") else open
    cust_source = get_source(filename.split("/")[-1])
    single_block = b""
    blocks: list[bytes] = []

    with open_method(filename, mode="rb") as f:
        for line in f:
            # Skip comments
            if line.startswith(b"%") or line.startswith(b"#") or line.startswith(b"remarks:"):
                continue
            # Block end
            if line.strip() == b"":
                if (
                    single_block.startswith(b"inetnum:")
                    or single_block.startswith(b"inet6num:")
                    or single_block.startswith(b"route:")
                    or single_block.startswith(b"route6:")
                ):
                    single_block += b"cust_source: %s" % cust_source
                    blocks.append(single_block)
                    if len(blocks) % 1000 == 0:
                        logger.debug(f"parsed another 1000 blocks ({len(blocks)} so far)")
                single_block = b""
            else:
                single_block += line

    logger.info(f"Got {len(blocks)} blocks")
    return blocks


def upsert_block(session, block_data: dict) -> None:
    """
    Insert or update a block record using PostgreSQL ON CONFLICT.

    Args:
        session: SQLAlchemy session
        block_data: Dictionary of block attributes
    """
    stmt = insert(Block).values(**block_data)
    stmt = stmt.on_conflict_do_update(
        constraint="uq_block_inetnum_source",
        set_={
            "netname": stmt.excluded.netname,
            "description": stmt.excluded.description,
            "country": stmt.excluded.country,
            "maintained_by": stmt.excluded.maintained_by,
            "created": stmt.excluded.created,
            "last_modified": stmt.excluded.last_modified,
            "status": stmt.excluded.status,
            "import_date": stmt.excluded.import_date,
        },
    )
    session.execute(stmt)


def parse_blocks(
    jobs: Queue,
    connection_string: str,
    num_blocks: int,
    num_workers: int,
    logger: logging.Logger,
    incremental: bool = False,
) -> None:
    """
    Worker function to parse WHOIS blocks and insert into database.

    Args:
        jobs: Queue of blocks to process
        connection_string: Database connection string
        num_blocks: Total number of blocks (for progress calculation)
        num_workers: Number of worker processes
        logger: Logger instance
        incremental: If True, use upsert; otherwise use simple insert
    """
    session = setup_connection(connection_string)
    counter = 0
    blocks_done = 0
    start_time = time.time()
    import_date = datetime.now()

    while True:
        block = jobs.get()
        if block is None:
            break

        inetnum = parse_property_inetnum(block)
        if not inetnum:
            logger.warning(f"Could not parse inetnum on block {block}. skipping")
            continue

        netname = parse_property(block, b"netname")
        if not netname:
            netname = parse_property(block, b"origin")

        description = parse_property(block, b"descr")
        country = parse_property(block, b"country")

        city = parse_property(block, b"city")
        if city:
            country = f"{country} - {city}"

        maintained_by = parse_property(block, b"mnt-by")
        created = parse_property(block, b"created")
        last_modified = parse_property(block, b"last-modified")

        if not last_modified:
            changed = parse_property(block, b"changed")
            if changed and re.match(r"^.+?@.+? \d+", changed):
                date = changed.split(" ")[1].strip()
                if len(date) == 8:
                    year = int(date[0:4])
                    month = int(date[4:6])
                    day = int(date[6:8])
                    if 1 <= month <= 12 and 1 <= day <= 31:
                        last_modified = f"{year}-{month}-{day}"
                    else:
                        logger.debug(f"ignoring invalid changed date {date}")
                else:
                    logger.debug(f"ignoring invalid changed date {date}")
            elif changed and "@" in changed:
                logger.debug(f"ignoring invalid changed date {changed}")
            else:
                last_modified = changed

        status = parse_property(block, b"status")
        source = parse_property(block, b"cust_source")

        if isinstance(inetnum, list):
            for cidr in inetnum:
                block_data = {
                    "inetnum": str(cidr),
                    "netname": netname,
                    "description": description,
                    "country": country,
                    "maintained_by": maintained_by,
                    "created": created,
                    "last_modified": last_modified,
                    "source": source,
                    "status": status,
                    "import_date": import_date,
                }
                if incremental:
                    upsert_block(session, block_data)
                else:
                    session.add(Block(**block_data))
        else:
            block_data = {
                "inetnum": inetnum.decode("utf-8"),
                "netname": netname,
                "description": description,
                "country": country,
                "maintained_by": maintained_by,
                "created": created,
                "last_modified": last_modified,
                "source": source,
                "status": status,
                "import_date": import_date,
            }
            if incremental:
                upsert_block(session, block_data)
            else:
                session.add(Block(**block_data))

        counter += 1
        blocks_done += 1

        if counter % COMMIT_COUNT == 0:
            session.commit()
            session.close()
            session = setup_connection(connection_string)
            percent = min((blocks_done * num_workers * 100) / num_blocks, 100)
            logger.debug(
                f"committed {counter} blocks ({round(time.time() - start_time, 2)} seconds) {percent:.1f}% done."
            )
            counter = 0
            start_time = time.time()

    session.commit()
    logger.debug("committed last blocks")
    session.close()
    logger.debug(f"{current_process().name} finished")


def main(
    connection_string: str,
    context: ParserContext,
    logger: logging.Logger,
    incremental: bool = False,
) -> None:
    """
    Main function to orchestrate the database parsing.

    Args:
        connection_string: PostgreSQL connection string
        context: Parser context for tracking state
        logger: Logger instance
        incremental: If True, update existing records instead of dropping table
    """
    overall_start_time = time.time()

    if incremental:
        logger.info("Running in incremental mode - will update existing records")
        setup_connection(connection_string, create_db=True, drop_existing=False)
    else:
        logger.info("Running in full refresh mode - dropping and recreating table")
        setup_connection(connection_string, create_db=True, drop_existing=True)

    for entry in FILELIST:
        context.current_filename = entry
        f_name = f"./databases/{entry}"

        if os.path.exists(f_name):
            logger.info(f"parsing database file: {f_name}")
            start_time = time.time()
            blocks = read_blocks(f_name, logger)
            context.num_blocks = len(blocks)
            logger.info(f"database parsing finished: {round(time.time() - start_time, 2)} seconds")

            logger.info("parsing blocks")
            start_time = time.time()

            jobs: Queue = Queue()
            workers: list[Process] = []

            logger.debug(f"starting {NUM_WORKERS} processes")
            for _ in range(NUM_WORKERS):
                p = Process(
                    target=parse_blocks,
                    args=(
                        jobs,
                        connection_string,
                        context.num_blocks,
                        NUM_WORKERS,
                        logger,
                        incremental,
                    ),
                    daemon=True,
                )
                p.start()
                workers.append(p)

            for b in blocks:
                jobs.put(b)
            for _ in range(NUM_WORKERS):
                jobs.put(None)
            jobs.close()
            jobs.join_thread()

            for p in workers:
                p.join()

            logger.info(f"block parsing finished: {round(time.time() - start_time, 2)} seconds")
        else:
            logger.info(f"File {f_name} not found. Please download using download_dumps.sh")

    context.current_filename = "empty"
    logger.info(f"script finished: {round(time.time() - overall_start_time, 2)} seconds")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create DB")
    parser.add_argument(
        "-c",
        dest="connection_string",
        type=str,
        required=True,
        help="Connection string to the postgres database",
    )
    parser.add_argument("-d", "--debug", action="store_true", help="set loglevel to DEBUG")
    parser.add_argument(
        "-i",
        "--incremental",
        action="store_true",
        help="Update existing records instead of dropping table (uses upsert)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    ctx = ParserContext()
    log = create_logger(ctx)

    if args.debug:
        log.setLevel(logging.DEBUG)

    main(args.connection_string, ctx, log, incremental=args.incremental)
