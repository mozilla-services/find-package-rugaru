import argparse
import contextlib

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@contextlib.contextmanager
def create_session(engine: sqlalchemy.engine.Engine) -> sqlalchemy.orm.Session:
    Session = sessionmaker(bind=engine)
    try:
        session = Session()
        yield session
    finally:
        session.close()
