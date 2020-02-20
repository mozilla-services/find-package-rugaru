import sqlalchemy
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
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


# TODO: harmonize with stuff defined in models/languages
lang_enum = ENUM("node", "rust", "python", name="language_enum")
package_manager_enum = ENUM("npm", "yarn", name="package_manager_enum")


class PackageVersion(Base):
    __tablename__ = "package_versions"

    id = Column(Integer, Sequence("package_version_id_seq"), primary_key=True)

    # has a name, resolved version, and language
    name = Column(String, nullable=False, primary_key=True)
    version = Column(String, nullable=False, primary_key=True)
    language = Column(lang_enum, nullable=False, primary_key=True)

    # has an optional distribution URL
    url = deferred(Column(String, nullable=True))

    # has an optional source repository and commit
    repo_url = deferred(Column(String, nullable=True))
    repo_commit = deferred(Column(LargeBinary, nullable=True))

    # track when it was inserted and changed
    inserted_at = deferred(Column(DateTime(timezone=False), server_default=utcnow()))
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
                f"{cls.__tablename__}_inserted_idx",
                "inserted_at",
                expression.desc(cls.inserted_at),
            ),
        )


class PackageLink(Base):
    __tablename__ = "package_links"

    id = Column(
        Integer, Sequence("package_version_link_id_seq"), primary_key=True, unique=True
    )

    child_package_id = Column(
        Integer, primary_key=True, nullable=False,  # ForeignKey("package_versions.id"),
    )
    parent_package_id = Column(
        Integer, primary_key=True, nullable=False,  # ForeignKey("package_versions.id"),
    )

    # track when it was inserted
    inserted_at = deferred(Column(DateTime(timezone=False), server_default=utcnow()))

    @declared_attr
    def __table_args__(cls):
        return (
            # ForeignKeyConstraint(
            #     ["child_package_id"],
            #     [
            #         "package_versions.id",
            #     ],
            # ),
            # ForeignKeyConstraint(
            #     ["parent_package_id"],
            #     [
            #         "package_versions.id",
            #     ],
            # ),
            Index(
                f"{cls.__tablename__}_unique_idx",
                "child_package_id",
                "parent_package_id",
                unique=True,
            ),
            Index(
                f"{cls.__tablename__}_inserted_idx",
                "inserted_at",
                expression.desc(cls.inserted_at),
            ),
        )


class PackageGraph(Base):
    __tablename__ = "package_graphs"

    id = Column(Integer, Sequence("package_graphs_id_seq"), primary_key=True)

    # package version we resolved
    root_package_version_id = Column(
        Integer, nullable=False, primary_key=True,  # ForeignKey("package_versions.id"),
    )

    # link ids of direct and transitive deps
    link_ids = deferred(Column(ARRAY(Integer)))  # ForeignKey("package_links.id"))

    # what resolved it
    package_manager = deferred(Column(package_manager_enum, nullable=True))
    package_manager_version = deferred(Column(String, nullable=True))

    # track when it was inserted
    inserted_at = deferred(Column(DateTime(timezone=False), server_default=utcnow()))

    @declared_attr
    def __table_args__(cls):
        return (
            Index(
                f"{cls.__tablename__}_root_package_id_idx", "root_package_version_id",
            ),
            Index(
                f"{cls.__tablename__}_link_ids_idx", "link_ids", postgresql_using="gin",
            ),
            Index(f"{cls.__tablename__}_package_manager_idx", "package_manager",),
            Index(
                f"{cls.__tablename__}_package_manager_version_idx",
                "package_manager_version",
            ),
            Index(
                f"{cls.__tablename__}_inserted_idx",
                "inserted_at",
                expression.desc(cls.inserted_at),
            ),
        )


class Advisory(Base):
    __tablename__ = "advisories"

    id = Column(Integer, Sequence("advisories_id_seq"), primary_key=True, unique=True)
    language = Column(lang_enum, nullable=False, primary_key=True)

    # has optional name, npm advisory id, and url
    package_name = Column(
        String, nullable=True
    )  # included in case vulnerable_package_version_ids is empty
    npm_advisory_id = Column(Integer, nullable=True)
    url = Column(String, nullable=True)

    severity = Column(String, nullable=True)
    cwe = Column(Integer, nullable=True)
    cves = deferred(Column(ARRAY(String), nullable=True))

    exploitability = Column(Integer, nullable=True)
    title = Column(String, nullable=True)

    # vulnerable and patched versions from the advisory as a string
    vulnerable_versions = deferred(Column(String, nullable=True))
    patched_versions = deferred(Column(String, nullable=True))

    # vulnerable package versions from our resolved package versions
    # TODO: validate affected deps. from findings[].paths[] for a few graphs
    vulnerable_package_version_ids = deferred(
        Column(ARRAY(Integer))
    )  # ForeignKey("package_versions.id"))

    # advisory publication info
    created = deferred(Column(DateTime(timezone=False), nullable=True))
    updated = deferred(Column(DateTime(timezone=False), nullable=True))

    # track when it was inserted or last updated in our DB
    inserted_at = deferred(Column(DateTime(timezone=False), server_default=utcnow()))
    updated_at = deferred(Column(DateTime(timezone=False), onupdate=utcnow()))

    @declared_attr
    def __table_args__(cls):
        return (
            Index(f"{cls.__tablename__}_language_idx", "language"),
            Index(f"{cls.__tablename__}_pkg_name_idx", "package_name"),
            Index(f"{cls.__tablename__}_npm_advisory_id_idx", "npm_advisory_id"),
            Index(
                f"{cls.__tablename__}_vulnerable_package_version_ids_idx",
                "vulnerable_package_version_ids",
                postgresql_using="gin",
            ),
            Index(
                f"{cls.__tablename__}_inserted_idx",
                "inserted_at",
                expression.desc(cls.inserted_at),
            ),
        )
