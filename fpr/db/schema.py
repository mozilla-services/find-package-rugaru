import sqlalchemy
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    Sequence,
    String,
    Table,
    UniqueConstraint,
)
from sqlalchemy.orm import deferred, relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import JSONB


Base: sqlalchemy.ext.declarative.declarative_base = declarative_base()


class Repo(Base):
    __tablename__ = "repos"

    id = Column(Integer, Sequence("repo_id_seq"), primary_key=True)
    url = Column(String, nullable=False, unique=True)

    # each repo has one or more refs
    refs = relationship("Ref", backref="repo")


ref_dep_files = Table(
    "ref_dep_files",
    Base.metadata,
    Column("ref_id", Integer, ForeignKey("refs.id")),
    Column("dep_file_id", Integer, ForeignKey("dep_files.id")),
)

task_dep_files = Table(
    "task_dep_files",
    Base.metadata,
    Column("repo_task_id", Integer, ForeignKey("repo_tasks.id")),
    Column("dep_file_id", Integer, ForeignKey("dep_files.id")),
)

# dep_vulns = Table(
#     "dep_vulns",
#     Base.metadata,
#     Column("dep_id", Integer, ForeignKey("deps.id")),
#     Column("vuln_id", Integer, ForeignKey("vulns.id")),
# )


class Ref(Base):
    __tablename__ = "refs"

    id = Column(Integer, Sequence("ref_id_seq"), primary_key=True)

    # each repo ref has an optional branch, tag, commit hash, and commit time
    branch = Column(String, nullable=True)
    tag = Column(String, nullable=True)
    commit = Column(String(length=40), nullable=True)
    commit_ts = Column(DateTime(timezone=False), nullable=True)

    # has a repo
    repo_id = Column(Integer, ForeignKey("repos.id"))

    # has one or more dep files
    dep_files = relationship(
        "DependencyFile", secondary=ref_dep_files, back_populates="refs"
    )


class DependencyFile(Base):
    __tablename__ = "dep_files"
    __tableargs__ = (UniqueConstraint("sha2", "path"),)

    # a dependency file (manifest or lock) has one or more refs
    id = Column(Integer, Sequence("dep_files_id_seq"), primary_key=True)

    # has a path including a directory and filename
    path = Column(String, nullable=False)
    # has a SHA2 sum
    sha2 = Column(String, nullable=False)

    # has one or more refs
    refs = relationship("Ref", secondary=ref_dep_files, back_populates="dep_files")

    # has one or more tasks
    repo_tasks = relationship(
        "RepoTask", secondary=task_dep_files, back_populates="dep_files"
    )


class RepoTask(Base):
    __tablename__ = "repo_tasks"

    id = Column(Integer, Sequence("repo_task_id_seq"), primary_key=True)

    # has one or more dep files
    dep_files = relationship(
        "DependencyFile", secondary=task_dep_files, back_populates="repo_tasks"
    )

    # has one or deps
    deps = relationship("Dependency", backref="repo_tasks")

    # has a name (e.g. list_metadata, audit)
    name = Column(String, nullable=False)

    # has a command (e.g. yarn audit --json and exit code)
    command = Column(String, nullable=False)
    exit_code = Column(Integer)

    # has jsonb stdout output
    stdout = deferred(Column(JSONB, nullable=False))

    # has a jsonb versions object
    versions = deferred(Column(JSONB))


class Dependency(Base):
    __tablename__ = "deps"

    # from postprocess output

    id = Column(Integer, Sequence("dep_id_seq"), primary_key=True)

    # has a name and resolved version
    name = Column(String, nullable=False, primary_key=True)
    version = Column(String, nullable=False)
    url = Column(String)

    # has an inserting task (with one or more dep files)
    task = relationship("RepoTask")
    repo_task_id = Column(Integer, ForeignKey("repo_tasks.id"))

    # has dependents possibly without fully resolved versions
    dependents = deferred(Column(JSONB))

    # vulns = relationship("Vulnerability", secondary=dep_vulns, back_populates="deps")
    ref_id = Column("ref_id", Integer, ForeignKey("refs.id"))

    # join by ref_id to dep files to find dep_files


class Vulnerability(Base):
    __tablename__ = "vulns"

    # from postprocess output

    id = Column(Integer, Sequence("vuln_id_seq"), primary_key=True)

    # has optional name, version, npm advisory id, and url
    name = Column(String)
    version = Column(String)
    npm_advisory_id = Column(Integer)
    url = Column(String)

    # has an inserting task (with one or more dep files)
    task = relationship("RepoTask")
    repo_task_id = Column(Integer, ForeignKey("repo_tasks.id"))

    # the advisory JSON at .advisories{k, v} for npm; .advisories[].advisory for yarn
    advisory = deferred(Column(JSONB))

    ref_id = Column("ref_id", Integer, ForeignKey("refs.id"))

    # has one or more affected deps
    # TODO: pull and populate this from findings[].paths[] (use version)
    # deps = relationship("Dependency", secondary=dep_vulns, back_populates="vulns")

    # join by ref_id to dep files to find dep_files


class DependencyMetadata(Base):
    __tablename__ = "deps_meta"  # has a name and version

    id = Column(Integer, Sequence("deps_meta_id_seq"), primary_key=True)

    package_name = Column(String, nullable=False)

    # optional version
    package_version = Column(String)

    # has a source e.g. github, npms.io, npm reg., crates.io
    source_name = Column(String, nullable=False)

    source_url = Column(String)

    # has a jsonb result
    result = deferred(Column(JSONB, nullable=False))
