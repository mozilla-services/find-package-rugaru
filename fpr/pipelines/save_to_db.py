import argparse
import asyncio
from collections import ChainMap
from datetime import datetime
import logging
import pathlib
from random import randrange
import sys
import time
from typing import (
    AbstractSet,
    Any,
    AnyStr,
    AsyncGenerator,
    Dict,
    Generator,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)
import typing

from sqlalchemy import tuple_
from sqlalchemy.orm import Load, load_only

from fpr.db.connect import create_engine, create_session
from fpr.db.schema import (
    Base,
    # DependencyFile,
    # Ref,
    # Repo,
    # RepoTask,
    # Dependency,
    # DependencyMetadata,
    # Vulnerability,
)
from fpr.models.pipeline import Pipeline
from fpr.models.pipeline import add_infile_and_outfile, add_db_arg
from fpr.pipelines.postprocess import parse_stdout_as_json, parse_stdout_as_jsonlines
from fpr.rx_util import on_next_save_to_jsonl
from fpr.serialize_util import iter_jsonlines


NAME = "save_to_db"

log = logging.getLogger(f"fpr.pipelines.{NAME}")


__doc__ = """Saves JSON lines to a postgres DB"""


def parse_args(pipeline_parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser = add_infile_and_outfile(pipeline_parser)
    parser = add_db_arg(parser)
    parser.add_argument(
        "--create-tables",
        action="store_true",
        required=False,
        default=False,
        help="Creates tables in the DB.",
    )
    parser.add_argument(
        "--create-views",
        action="store_true",
        required=False,
        default=False,
        help="Creates materialized views in the DB.",
    )
    parser.add_argument(
        "--input-type", type=str, required=True, help="Input type to save.",
    )
    return parser


VIEWS_AND_INDEXES = [
    # CREATE MATERIALIZED VIEW IF NOT EXISTS <table_name> AS <query>
    """CREATE INDEX IF NOT EXISTS deps_name_v_idx ON deps (cast(name as TEXT), version)""",
    """
CREATE MATERIALIZED VIEW IF NOT EXISTS refs_with_repo AS (
SELECT
  refs.id AS id,
  refs.commit AS commit,
  refs.tag AS tag,
  refs.commit_ts AS commit_ts,
  repos.url AS url
FROM repos
INNER JOIN refs ON repos.id = refs.repo_id
)
""",
    """CREATE INDEX IF NOT EXISTS rwr_tag_commit_url ON refs_with_repo (tag, commit, url)""",
    # join table from ref to task (taking dep files away)
    #     """
    # CREATE MATERIALIZED VIEW IF NOT EXISTS refs_with_tasks AS (
    # SELECT
    #   repo_tasks.id AS repo_task_id,
    #   refs_with_repo.id AS ref_id
    # FROM repo_tasks
    # INNER JOIN task_dep_files ON repo_tasks.id = task_dep_files.repo_task_id
    # INNER JOIN dep_files ON task_dep_files.dep_file_id = dep_files.id
    # INNER JOIN ref_dep_files ON dep_files.id = ref_dep_files.dep_file_id
    # INNER JOIN refs_with_repo ON refs_with_repo.id = ref_dep_files.ref_id
    # )
    # """,
    # flatten advisory findings
    # TODO: figure out syntax error for JOIN instead of implicit comma join (NB is implicit lateral)
    """
CREATE MATERIALIZED VIEW IF NOT EXISTS vuln_findings AS (
SELECT
  vulns.ref_id AS ref_id,
  vulns.repo_task_id AS repo_task_id,
  vulns.name AS name,
  vulns.npm_advisory_id AS npm_advisory_id,
  ((advisory->'created')::text)::timestamp without time zone AS advisory_created,
  ((advisory->'updated')::text)::timestamp without time zone AS advisory_updated,
  advisory->'severity' AS severity,
  advisory->'metadata'->'exploitability' AS exploitability,
  advisory->'cwe' AS cwe,
  findings->'version' AS affected_version,
  findings->'paths' AS paths
FROM
vulns, jsonb_array_elements(vulns.advisory->'findings') AS findings
)
""",
    """CREATE INDEX IF NOT EXISTS vuln_findings_idx ON vuln_findings (name, affected_version, advisory_created, advisory_updated, severity)""",
    # finally join deps and vulns with refs
    """
CREATE MATERIALIZED VIEW IF NOT EXISTS deps_refs_vulns AS (
SELECT
  deps.name AS name,
  deps.version AS version,
  refs_with_repo.url AS repo_url,
  refs_with_repo.tag AS tag,
  refs_with_repo.commit_ts AS commit_ts,
  refs_with_repo.id AS ref_id,
  vuln_findings.npm_advisory_id AS npm_advisory_id,
  vuln_findings.advisory_created AS advisory_created,
  vuln_findings.advisory_updated AS advisory_updated,
  replace(vuln_findings.severity::text, '"', '') AS severity,
  vuln_findings.exploitability AS exploitability,
  replace(vuln_findings.cwe::text, '"', '') AS cwe,
  replace(vuln_findings.affected_version::text, '"', '') AS affected_version
FROM deps
INNER JOIN refs_with_repo ON refs_with_repo.id = deps.ref_id
INNER JOIN vuln_findings ON refs_with_repo.id = vuln_findings.ref_id
WHERE vuln_findings.name = deps.name
  AND replace(vuln_findings.affected_version::text, '"', '') = deps.version
)
""",
    """CREATE INDEX IF NOT EXISTS deps_refs_vulns_idx ON deps_refs_vulns (name, version, commit_ts, advisory_created, advisory_updated, severity, ref_id)""",
    """CREATE INDEX IF NOT EXISTS deps_meta_npm_reg_maintainers ON deps_meta USING GIN ((result -> 'maintainers'))""",
    """CREATE INDEX IF NOT EXISTS deps_ref_id_idx ON deps (ref_id)""",
    # This is 140GB on disk :(
    #     """
    # CREATE MATERIALIZED VIEW IF NOT EXISTS deps_ref_vulns_all AS (
    # SELECT
    #   deps.name AS name,
    #   deps.version AS version,
    #   refs_with_repo.url AS repo_url,
    #   refs_with_repo.tag AS tag,
    #   refs_with_repo.commit_ts AS commit_ts,
    #   refs_with_repo.id AS ref_id,
    #   vuln_findings.npm_advisory_id AS npm_advisory_id,
    #   vuln_findings.advisory_created AS advisory_created,
    #   vuln_findings.advisory_updated AS advisory_updated,
    #   replace(vuln_findings.severity::text, '"', '') AS severity,
    #   vuln_findings.exploitability AS exploitability,
    #   replace(vuln_findings.cwe::text, '"', '') AS cwe,
    #   replace(vuln_findings.affected_version::text, '"', '') AS affected_version
    # FROM deps
    # INNER JOIN refs_with_repo ON refs_with_repo.id = deps.ref_id
    # LEFT OUTER JOIN vuln_findings ON refs_with_repo.id = vuln_findings.ref_id
    # )
    # """,
    """CREATE INDEX IF NOT EXISTS deps_refs_vulns_all_idx ON deps_ref_vulns_all (name, version, commit_ts, advisory_created, advisory_updated, severity, ref_id)""",
]


async def run_pipeline(
    source: Generator[Dict[str, Any], None, None], args: argparse.Namespace
) -> None:
    log.info(f"{pipeline.name} pipeline started")
    engine = create_engine(args.db_url)
    if args.create_tables:
        Base.metadata.create_all(engine)

    if args.create_views:
        # TODO: with contextlib.closing
        # connection = engine.connect()
        # for command in VIEWS_AND_INDEXES:
        #     _ = connection.execute(command)
        #     log.info(f"ran: {command}")
        # connection.close()
        pass

    # use input type since it could write to multiple tables
    with create_session(engine) as session:
        for line in source:
            await asyncio.sleep(0)
            yield None
            break
        pass
        # if args.input_type == "repo_url":
        #     rows = (Repo(url=line["repo_url"], refs=[]) for line in source)
        #     session.add_all(rows)
        #     session.commit()
        # elif args.input_type == "git_ref":
        #     rows = (
        #         Ref(
        #             tag=line["ref"]["value"] if line["ref"]["kind"] == "tag" else None,
        #             commit=line["ref"]["value"]
        #             if line["ref"]["kind"] == "commit"
        #             else None,  # TODO: add ref commit back from repo task run versions output?
        #             commit_ts=datetime.utcfromtimestamp(int(line["ref"]["commit_ts"])),
        #             repo_id=session.query(Repo)
        #             .filter_by(url=line["repo_url"].replace(".git", ""))[0]
        #             .id,
        #             dep_files=[],
        #         )
        #         for line in source
        #     )
        #     session.add_all(rows)
        #     session.commit()
        # elif args.input_type == "dep_file":
        #     for line in source:
        #         # TODO: replace with DB IDs?
        #         assert line["ref"]["kind"] == "tag"
        #         repo_id = (
        #             session.query(Repo)
        #             .filter_by(url=line["repo_url"].replace(".git", ""))
        #             .first()
        #             .id
        #         )
        #         ref = (
        #             session.query(Ref)
        #             .filter_by(repo_id=repo_id, tag=line["ref"]["value"],)
        #             .first()
        #         )

        #         # find the dep file
        #         dep_files = session.query(DependencyFile).filter_by(
        #             path=line["dependency_file"]["path"],
        #             sha2=line["dependency_file"]["sha256"],
        #         )
        #         if dep_files.count() == 0:
        #             session.add(
        #                 DependencyFile(
        #                     path=line["dependency_file"]["path"],
        #                     sha2=line["dependency_file"]["sha256"],
        #                     refs=[ref],
        #                 )
        #             )
        #         else:
        #             assert dep_files.count() == 1
        #             dep_file = (
        #                 session.query(DependencyFile)
        #                 .filter_by(
        #                     path=line["dependency_file"]["path"],
        #                     sha2=line["dependency_file"]["sha256"],
        #                 )
        #                 .first()
        #             )
        #             dep_file.refs.append(ref)
        #         session.commit()
        # elif args.input_type == "repo_task":
        #     for line in source:
        #         if line["task"]["name"] not in ["audit", "list_metadata"]:
        #             continue

        #         dep_files = session.query(DependencyFile).filter(
        #             tuple_(DependencyFile.sha2, DependencyFile.path).in_(
        #                 [
        #                     (dep_file["sha256"], dep_file["path"])
        #                     for dep_file in line["dependency_files"]
        #                 ]
        #             )
        #         )

        #         stdout = (
        #             parse_stdout_as_jsonlines(line["task"]["stdout"])
        #             if ("yarn" in line["task"]["command"])
        #             else parse_stdout_as_json(line["task"]["stdout"])
        #         )
        #         task = RepoTask(
        #             name=line["task"]["name"],
        #             command=line["task"]["command"],
        #             exit_code=line["task"]["exit_code"],
        #             versions=line["versions"],
        #             stdout=stdout,
        #             dep_files=list(dep_files),
        #         )
        #         session.add(task)
        #     session.commit()
        # elif args.input_type == "postprocessed_repo_task":
        #     for line in source:
        #         # TODO: save dep with vuln info pointing the same ref or repo task
        #         repo_id = (
        #             session.query(Repo)
        #             .filter_by(url=line["repo_url"].replace(".git", ""))
        #             .first()
        #             .id
        #         )
        #         ref_id = (
        #             session.query(Ref)
        #             .filter_by(tag=line["ref"]["value"], repo_id=repo_id,)
        #             .first()
        #             .id
        #         )

        #         for task_data in line["tasks"].values():
        #             if task_data["name"] == "list_metadata":
        #                 rows = (
        #                     Dependency(
        #                         name=dep.get("name", None),
        #                         version=dep.get("version", None),
        #                         url=dep.get(
        #                             "resolved", None
        #                         ),  # is null for the root for npm list and yarn list output
        #                         # repo_task_id=task.id,
        #                         dependents=list(
        #                             dep.get("dependencies", [])
        #                         ),  # is fully qualified for npm, semver for yarn
        #                         ref_id=ref_id,
        #                     )
        #                     for dep in task_data.get("dependencies", [])
        #                 )
        #                 session.add_all(rows)
        #                 session.commit()
        #             elif task_data["name"] == "audit":
        #                 # yarn has .advisory and .resolution
        #                 adv_iter = (
        #                     (
        #                         item.get("advisory", None)
        #                         for item in task_data.get("advisories", [])
        #                     )
        #                     if "yarn" in task_data["command"]
        #                     else task_data.get("advisories", dict()).values()
        #                 )
        #                 rows = (
        #                     Vulnerability(
        #                         name=adv.get("module_name", None),
        #                         npm_advisory_id=adv.get("id", None),
        #                         version=adv.get("version", None),
        #                         url=adv.get("url", None),
        #                         # repo_task_id=task.id,
        #                         advisory=adv,
        #                         ref_id=ref_id,
        #                     )
        #                     for adv in adv_iter
        #                     if adv
        #                 )
        #                 session.add_all(rows)
        #                 session.commit()
        # elif args.input_type == "dep_meta_npm_reg":
        #     for line in source:
        #         rows = (
        #             DependencyMetadata(
        #                 package_name=line["name"],
        #                 package_version=version,
        #                 source_name="npm_registry",
        #                 source_url=f"https://registry.npmjs.com/{line['name']}",
        #                 result=version_data,
        #             )
        #             for version, version_data in line["versions"].items()
        #         )
        #         session.add_all(rows)
        #         # save version specific data and all data
        #         session.add(
        #             DependencyMetadata(
        #                 package_name=line["name"],
        #                 source_name="npm_registry",
        #                 source_url=f"https://registry.npmjs.com/{line['name']}",
        #                 result=line,
        #             )
        #         )
        #     session.commit()
        # elif args.input_type == "dep_meta_npmsio":
        #     rows = (
        #         DependencyMetadata(
        #             package_name=line["collected"]["metadata"]["name"],
        #             package_version=line["collected"]["metadata"]["version"],
        #             source_name="npmsio",
        #             source_url=f"https://api.npms.io/v2/package/{line['collected']['metadata']['name']}",
        #             result=line,
        #         )
        #         for line in source
        #     )
        #     session.add_all(rows)
        #     session.commit()
        # else:
        #     raise NotImplementedError()


FIELDS: AbstractSet = set()


pipeline = Pipeline(
    name=NAME,
    desc=__doc__,
    fields=FIELDS,
    argparser=parse_args,
    reader=iter_jsonlines,
    runner=run_pipeline,
    writer=on_next_save_to_jsonl,
)
