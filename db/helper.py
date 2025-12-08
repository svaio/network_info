#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

Base = declarative_base()


def get_base():
    """Return the SQLAlchemy declarative base."""
    return Base


def setup_connection(
    connection_string: str, create_db: bool = False, drop_existing: bool = True
) -> Session:
    """
    Set up a database connection and return a session.

    Args:
        connection_string: PostgreSQL connection string
        create_db: If True, create tables (behavior depends on drop_existing)
        drop_existing: If True and create_db is True, drop tables first.
                      If False, only create tables if they don't exist.

    Returns:
        SQLAlchemy Session instance
    """
    engine = create_postgres_pool(connection_string)
    session = sessionmaker()
    session.configure(bind=engine)

    if create_db:
        if drop_existing:
            Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)

    return session()


def create_postgres_pool(connection_string: str) -> Engine:
    """
    Create a SQLAlchemy engine for PostgreSQL.

    Args:
        connection_string: PostgreSQL connection string

    Returns:
        SQLAlchemy Engine instance
    """
    engine = create_engine(connection_string)
    return engine
