import sqlalchemy
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    LargeBinary,
    Index,
    Integer,
    Sequence,
    String,
    Table,
    UniqueConstraint,
)
from sqlalchemy.sql import func
from sqlalchemy.orm import deferred, relationship
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.dialects.postgresql import ARRAY, ENUM, JSONB

from sqlalchemy.sql import expression
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.types import DateTime


class utcnow(expression.FunctionElement):
    type = DateTime()


@compiles(utcnow, "postgresql")
def pg_utcnow(element, compiler, **kw):
    return "TIMEZONE('utc', CURRENT_TIMESTAMP)"


Base: sqlalchemy.ext.declarative.declarative_base = declarative_base()


lang_enum = ENUM("node", "rust", "python", name="language_enum")
package_manager_enum = ENUM("npm", "yarn", name="package_manager_enum")


class PackageVersion(Base):
    __tablename__ = "package_versions"

    id = Column(Integer, Sequence("package_version_id_seq"), primary_key=True)

    # has a name, resolved version, and language
    name = Column(String, nullable=False, primary_key=True)
    version = Column(String, nullable=False, primary_key=True)
    language = Column(lang_enum, nullable=False, primary_key=True)

    # has a source repository and commit
    repo_url = deferred(Column(String, nullable=True))
    repo_commit = deferred(Column(LargeBinary, nullable=True))

    # has unstructured metadata from various sources
    extra = deferred(Column(JSONB, nullable=True))

    # track when it was created and changed
    created_at = deferred(Column(DateTime(timezone=False), server_default=utcnow()))
    updated_at = deferred(Column(DateTime(timezone=False), onupdate=utcnow()))

    @declared_attr
    def __table_args__(cls):
        return (
            Index(
                f"{cls.__tablename__}_unique_idx",
                "name",
                "version",
                "language",
                unique=True,
            ),
            Index(
                f"{cls.__tablename__}_created_idx",
                "created_at",
                expression.desc(cls.created_at),
            ),
        )


class PackageLink(Base):
    __tablename__ = "package_version_links"

    id = Column(
        Integer, Sequence("package_version_link_id_seq"), primary_key=True, unique=True
    )

    child_package_id = Column(
        Integer, ForeignKey("package_versions.id"), primary_key=True
    )
    parent_package_id = Column(
        Integer, ForeignKey("package_versions.id"), primary_key=True
    )

    # track when it was created
    created_at = deferred(Column(DateTime(timezone=False), server_default=utcnow()))

    @declared_attr
    def __table_args__(cls):
        return (
            Index(
                f"{cls.__tablename__}_unique_idx",
                "child_package_id",
                "parent_package_id",
                unique=True,
            ),
            Index(
                f"{cls.__tablename__}_created_idx",
                "created_at",
                expression.desc(cls.created_at),
            ),
        )


class PackageGraph(Base):
    __tablename__ = "package_graphs"

    id = Column(Integer, Sequence("package_graphs_id_seq"), primary_key=True)

    # package version did we resolved
    root_package_version_id = Column(
        Integer, ForeignKey("package_versions.id"), nullable=False, primary_key=True
    )

    # link ids of direct and transitive deps
    link_ids = Column(ARRAY(Integer))  # ForeignKey("package_version_links.id"))

    # what resolved it
    package_manager = deferred(Column(package_manager_enum, nullable=False))
    package_manager_version = deferred(Column(String, nullable=False))

    # track when it was created
    created_at = deferred(Column(DateTime(timezone=False), server_default=utcnow()))


# TODO: add indexes
# Index('', mytable.c.col5, mytable.c.col6, unique=True)
