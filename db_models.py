import logging
from sqlalchemy import Column, Integer, String, SmallInteger
from sqlalchemy.orm import DeclarativeBase


logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class Users(Base):
    __tablename__ = "Users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, nullable=False)
    failed_attempts = Column(SmallInteger, default=0)
    status = Column(SmallInteger, default=0) # 0 - unauth, 1 - auth, 2 - blocked
    comment = Column(String, nullable=True)


class Md5Hashes(Base):
    __tablename__ = "MD5Hashes"
    id = Column(Integer, primary_key=True, autoincrement=True)
    hash = Column(String, nullable=False)
    user_id = Column(Integer, nullable=True)


class OVPNKeys(Base):
    __tablename__ = "OvpnKeys"
    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String, nullable=False)
    name = Column(String, nullable=False)
    user_id = Column(Integer, nullable=False)


def create_tables(engine):
    Base.metadata.create_all(engine)
    logger.info("Tables successfully created.")
