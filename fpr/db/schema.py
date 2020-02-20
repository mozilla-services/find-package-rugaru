import sqlalchemy
from sqlalchemy import (
    Boolean,
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


class NPMRegistryEntry(Base):
    __tablename__ = "npm_registry_entries"

    """
    package and version info from the npm registry

    many to one with package_versions, so join on package_name and package_version
    and pick or aggregate tarball and shasums
    """
    id = Column(Integer, Sequence("npm_registry_entry_id_seq"), primary_key=True)

    # "The name, version, and dist fields will always be present."
    #
    # https://github.com/npm/registry/blob/master/docs/responses/package-metadata.md#abbreviated-version-object
    #
    # the package name from .versions[<version>].name
    package_name = Column(String, nullable=False, primary_key=True)
    # the version string for this version from .versions[<version>].version
    package_version = Column(String, nullable=False, primary_key=True)

    # https://github.com/npm/registry/blob/master/docs/responses/package-metadata.md#dist
    #
    # from .versions[<version>].dist.shasum e.g. f616eda9d3e4b66b8ca7fca79f695722c5f8e26f
    shasum = deferred(Column(String, nullable=False, primary_key=True))
    # from .versions[<version>].dist.tarball e.g. https://registry.npmjs.org/backoff/-/backoff-2.5.0.tgz
    tarball = deferred(Column(String, nullable=False, primary_key=True))

    # from .versions[<version>].gitHead e.g. '811118fd1f89e9ca4e6b67292b9ef5da6c4f60e9'
    git_head = deferred(Column(String, nullable=True))

    # https://github.com/npm/registry/blob/master/docs/responses/package-metadata.md#repository
    #
    # from .versions[<version>].repository.type e.g. 'git'
    repository_type = deferred(Column(String, nullable=True))
    # from .versions[<version>].repository.url e.g. 'git+https://github.com/MathieuTurcotte/node-backoff.git'
    repository_url = deferred(Column(String, nullable=True))

    # a short description of the package from .versions[<version>].description
    description = deferred(Column(String, nullable=True))

    # url from .versions[<version>].url
    url = deferred(Column(String, nullable=True))

    # the SPDX identifier https://spdx.org/licenses/ of the package's license
    # from .versions[<version>].license
    license = Column(String, nullable=True)

    # array of string keywords e.g. ['backoff', 'retry', 'fibonacci', 'exponential']
    keywords = deferred(Column(ARRAY(String)))

    # _hasShrinkwrap: true if this version is known to have a shrinkwrap that
    # must be used to install it; false if this version is known not to have a
    # shrinkwrap. If this field is undefined, the client must determine through
    # other means if a shrinkwrap exists.
    has_shrinkwrap = Column(Boolean, nullable=True)

    # bugs: url e.g. {'url': 'https://github.com/MathieuTurcotte/node-backoff/issues'}
    bugs_url = deferred(Column(String, nullable=True))

    # https://github.com/npm/registry/blob/master/docs/responses/package-metadata.md#human
    #
    # "Historically no validation has been performed on those fields; they are
    # generated by parsing user-provided data in package.json at publication
    # time."
    #
    # TODO: de-dupe humans?
    #
    # author is a human object
    # e.g. {'name': 'Mathieu Turcotte', 'email': 'turcotte.mat@gmail.com'}
    author_name = deferred(Column(String, nullable=True))
    author_email = deferred(Column(String, nullable=True))
    author_url = deferred(Column(String, nullable=True))

    # array of human objects for people with permission to publish this package; not authoritative but informational
    # e.g. [{'name': 'mathieu', 'email': 'turcotte.mat@gmail.com'}]
    maintainers = deferred(Column(JSONB, nullable=True))

    # array of human objects
    contributors = deferred(Column(JSONB, nullable=True))

    # publication info
    # _npmUser: the author object for the npm user who published this version
    # e.g. {'name': 'mathieu', 'email': 'turcotte.mat@gmail.com'}
    publisher_name = deferred(Column(String, nullable=True))
    publisher_email = deferred(Column(String, nullable=True))
    publisher_url = deferred(Column(String, nullable=True))
    # _nodeVersion: the version of node used to publish this
    publisher_node_version = deferred(Column(String, nullable=True))
    # _npmVersion: the version of the npm client used to publish this
    publisher_npm_version = deferred(Column(String, nullable=True))

    # published_at .time[<version>] e.g. '2014-05-23T21:21:04.170Z' (not from
    # the version info object)
    #
    # where time: an object mapping versions to the time published, along with created and modified timestamps
    published_at = Column(DateTime(timezone=False, nullable=True))

    # when ANY VERSION of the package was last modified (i.e. how fresh is this entry)
    package_modified_at = Column(DateTime(timezone=False, nullable=True))

    # metadata about how we fetched it

    # where we fetched it from e.g. https://registry.npmjs.org/backoff might change if the API changes
    source_url = Column(String, nullable=False)

    # track when it was inserted or last updated in our DB
    inserted_at = deferred(Column(DateTime(timezone=False), server_default=utcnow()))
    updated_at = deferred(Column(DateTime(timezone=False), onupdate=utcnow()))

    # TODO: add the following fields?
    #
    # main: the package's entry point (e.g., index.js or main.js)
    # deprecated: the deprecation warnings message of this version
    # dependencies: a mapping of other packages this version depends on to the required semver ranges
    # optionalDependencies: an object mapping package names to the required semver ranges of optional dependencies
    # devDependencies: a mapping of package names to the required semver ranges of development dependencies
    # bundleDependencies: an array of dependencies bundled with this version
    # peerDependencies: a mapping of package names to the required semver ranges of peer dependencies
    # bin: a mapping of bin commands to set up for this version
    # directories: an array of directories included by this version
    # engines: the node engines required for this version to run, if specified e.g. {'node': '>= 0.6'}
    # readme: the first 64K of the README data for the most-recently published version of the package
    # readmeFilename: The name of the file from which the readme data was taken.
    #
    # scripts e.g. {'docco': 'docco lib/*.js lib/strategy/* index.js',
    #               'pretest': 'jshint lib/ tests/ examples/ index.js',
    #               'test': 'node_modules/nodeunit/bin/nodeunit tests/'}
    # files e.g. ['index.js', 'lib', 'tests']

    @declared_attr
    def __table_args__(cls):
        return (
            Index(
                f"{cls.__tablename__}_unique_idx",
                "package_name",
                "package_version",
                "shasum",
                "tarball",
                unique=True,
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
