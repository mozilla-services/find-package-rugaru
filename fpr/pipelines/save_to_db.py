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
    PackageVersion,
    PackageLink,
    PackageGraph,
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
    # CREATE MATERIALIZED VIEW IF NOT EXISTS refs_with_repo AS (
    # SELECT
    #   refs.id AS id,
    #   refs.commit AS commit,
    #   refs.tag AS tag,
    #   refs.commit_ts AS commit_ts,
    #   repos.url AS url
    # FROM repos
    # INNER JOIN refs ON repos.id = refs.repo_id
    # )
    # """,
]


async def run_pipeline(
    source: Generator[Dict[str, Any], None, None], args: argparse.Namespace
) -> None:
    await asyncio.sleep(0)
    yield None
    log.info(f"{pipeline.name} pipeline started")
    engine = create_engine(args.db_url)
    if args.create_tables:
        Base.metadata.create_all(engine)

    if args.create_views:
        # TODO: with contextlib.closing
        connection = engine.connect()
        for command in VIEWS_AND_INDEXES:
            _ = connection.execute(command)
            log.info(f"ran: {command}")
        connection.close()
        pass

    # use input type since it could write to multiple tables
    with create_session(engine) as session:
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
        if args.input_type == "repo_task":
            for line in source:
                if line["task"]["name"] not in ["audit", "list_metadata"]:
                    continue

                dep_files = session.query(DependencyFile).filter(
                    tuple_(DependencyFile.sha2, DependencyFile.path).in_(
                        [
                            (dep_file["sha256"], dep_file["path"])
                            for dep_file in line["dependency_files"]
                        ]
                    )
                )

                stdout = (
                    parse_stdout_as_jsonlines(line["task"]["stdout"])
                    if ("yarn" in line["task"]["command"])
                    else parse_stdout_as_json(line["task"]["stdout"])
                )
                task = RepoTask(
                    name=line["task"]["name"],
                    command=line["task"]["command"],
                    exit_code=line["task"]["exit_code"],
                    versions=line["versions"],
                    stdout=stdout,
                    dep_files=list(dep_files),
                )
                session.add(task)
            session.commit()
        if args.input_type == "postprocessed_repo_task":
            for line in source:
                for task_data in line["tasks"].values():
                    if task_data["name"] == "list_metadata":
                        rows = (
                            PackageVersion(
                                name=dep.get("name", None),
                                version=dep.get("version", None),
                                language="node",
                                # extra=dict(
                                #     source_url=dep.get("resolved", None),  # is null for the root for npm list and yarn list output
                                #     # repo_task_id=task.id,
                                # )
                                # dependents=list(
                                #     dep.get("dependencies", [])
                                # ),  # is fully qualified for npm, semver for yarn
                            )
                            for dep in task_data.get("dependencies", [])
                        )
                        session.add_all(rows)
                        session.commit()
                    elif task_data["name"] == "audit":
                        pass
                        # # yarn has .advisory and .resolution
                        # adv_iter = (
                        #     (
                        #         item.get("advisory", None)
                        #         for item in task_data.get("advisories", [])
                        #     )
                        #     if "yarn" in task_data["command"]
                        #     else task_data.get("advisories", dict()).values()
                        # )
                        # rows = (
                        #     Vulnerability(
                        #         name=adv.get("module_name", None),
                        #         npm_advisory_id=adv.get("id", None),
                        #         version=adv.get("version", None),
                        #         url=adv.get("url", None),
                        #         # repo_task_id=task.id,
                        #         advisory=adv,
                        #         ref_id=ref_id,
                        #     )
                        #     for adv in adv_iter
                        #     if adv
                        # )
                        # session.add_all(rows)
                        # session.commit()
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
        else:
            raise NotImplementedError()


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
