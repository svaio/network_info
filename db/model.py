#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SQLAlchemy model for network block data."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, Index, Integer, String, literal_column
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql import func

from db.helper import get_base

Base = get_base()


class Block(Base):
    """
    Represents a network block from RIR WHOIS data.

    Attributes:
        id: Primary key
        inetnum: CIDR notation of the network block
        netname: Network name
        description: Description of the network
        country: Country code
        maintained_by: Maintainer identifier
        created: Creation timestamp
        last_modified: Last modification timestamp
        source: RIR source (afrinic, apnic, arin, lacnic, ripe)
        status: Allocation status
    """

    __tablename__ = "block"

    id: int = Column(Integer, primary_key=True)
    inetnum: str = Column(postgresql.CIDR, nullable=False, index=True)
    netname: Optional[str] = Column(String, nullable=True, index=True)
    description: Optional[str] = Column(String)
    country: Optional[str] = Column(String, index=True)
    maintained_by: Optional[str] = Column(String, index=True)
    created: Optional[datetime] = Column(DateTime, index=True)
    last_modified: Optional[datetime] = Column(DateTime, index=True)
    source: Optional[str] = Column(String, index=True)
    status: Optional[str] = Column(String, index=True)

    __table_args__ = (
        Index(
            "ix_block_description",
            func.to_tsvector(literal_column("'english'"), description),
            postgresql_using="gin",
        ),
    )

    def __str__(self) -> str:
        """Return string representation of the block."""
        return (
            f"inetnum: {self.inetnum}, netname: {self.netname}, "
            f"desc: {self.description}, status: {self.status}, "
            f"country: {self.country}, maintained: {self.maintained_by}, "
            f"created: {self.created}, updated: {self.last_modified}, "
            f"source: {self.source}"
        )

    def __repr__(self) -> str:
        """Return repr of the block."""
        return self.__str__()
