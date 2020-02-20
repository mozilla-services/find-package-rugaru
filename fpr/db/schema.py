import sqlalchemy
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    LargeBinary,
    Numeric,
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


class NPMSIOScore(Base):
    __tablename__ = "npmsio_scores"

    """
    Score of a package version at the analyzed_at time

    many to one with package_versions, so join on package_name and package_version
    and pick an analyzed_at date or compare over time
    """
    # TODO: make sure we aren't truncating data

    id = Column(Integer, Sequence("npmsio_score_id_seq"), primary_key=True)

    package_name = Column(
        String, nullable=False, primary_key=True
    )  # from .collected.metadata.name
    package_version = Column(
        String, nullable=False, primary_key=True
    )  # from .collected.metadata.version
    analyzed_at = Column(
        DateTime(timezone=False), nullable=False, primary_key=True
    )  # from .analyzedAt e.g. "2019-11-27T19:31:42.541Z

    # e.g. https://api.npms.io/v2/package/{package_name} might change if the API changes
    source_url = Column(String, nullable=False)

    # overall score from .score.final on the interval [0, 1]
    score = Column(Numeric, nullable=True)  # from .score.final

    # score components on the interval [0, 1]
    quality = Column(Numeric, nullable=True)  # from .detail.quality
    popularity = Column(Numeric, nullable=True)  # from .detail.popularity
    maintenance = Column(Numeric, nullable=True)  # from .detail.maintenance

    # score subcomponent/detail fields from .evaluation.<component>.<subcomponent>

    # all on the interval [0, 1]
    branding = Column(Numeric, nullable=True)  # from .evaluation.quality.branding
    carefulness = Column(Numeric, nullable=True)  # from .evaluation.quality.carefulness
    health = Column(Numeric, nullable=True)  # from .evaluation.quality.health
    tests = Column(Numeric, nullable=True)  # from .evaluation.quality.tests

    community_interest = Column(
        Integer, nullable=True
    )  # 0+ from .evaluation.popularity.communityInterest
    dependents_count = Column(
        Integer, nullable=True
    )  # 0+ from .evaluation.popularity.dependentsCount
    downloads_count = Column(
        Numeric, nullable=True
    )  # some of these are fractional? from .evaluation.popularity.downloadsCount
    downloads_acceleration = Column(
        Numeric, nullable=True
    )  # signed decimal (+/-) from .evaluation.popularity.downloadsAcceleration

    # all on the interval [0, 1]
    commits_frequency = Column(
        Numeric, nullable=True
    )  # from .evaluation.maintenance.commitsFrequency
    issues_distribution = Column(
        Numeric, nullable=True
    )  # from .evaluation.maintenance.issuesDistribution
    open_issues = Column(
        Numeric, nullable=True
    )  # from .evaluation.maintenance.openIssues
    releases_frequency = Column(
        Numeric, nullable=True
    )  # from .evaluation.maintenance.releasesFrequency

    # TODO: add .collected fields that feed into the score

    # track when it was inserted or last updated in our DB
    inserted_at = deferred(Column(DateTime(timezone=False), server_default=utcnow()))
    updated_at = deferred(Column(DateTime(timezone=False), onupdate=utcnow()))

    @declared_attr
    def __table_args__(cls):
        return (
            # TODO: add indexes on interesting score columns?
            Index(
                f"{cls.__tablename__}_unique_idx",
                "package_name",
                "package_version",
                "analyzed_at",
                unique=True,
            ),
            Index(
                f"{cls.__tablename__}_analyzed_idx",
                "analyzed_at",
                expression.desc(cls.analyzed_at),
            ),
            Index(
                f"{cls.__tablename__}_updated_idx",
                "updated_at",
                expression.desc(cls.updated_at),
            ),
            Index(
                f"{cls.__tablename__}_inserted_idx",
                "inserted_at",
                expression.desc(cls.inserted_at),
            ),
        )
