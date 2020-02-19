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

import sqlalchemy
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


def get_package_version_link_id_query(
    session: sqlalchemy.orm.Session, link: Tuple[int, int]
) -> None:  # some sort of query
    parent_package_id, child_package_id = link
    return session.query(PackageLink.id).filter_by(
        parent_package_id=parent_package_id, child_package_id=child_package_id,
    )


def get_package_version_id_query(
    session: sqlalchemy.orm.Session, pkg: Dict
) -> None:  # some sort of query
    return session.query(PackageVersion.id).filter_by(
        name=pkg["name"], version=pkg["version"], language="node",
    )


def add_new_package_version(session: sqlalchemy.orm.Session, pkg: Dict) -> None:
    get_package_version_id_query(session, pkg).one_or_none() or session.add(
        PackageVersion(
            name=pkg.get("name", None),
            version=pkg.get("version", None),
            language="node",
            url=pkg.get(
                "resolved", None
            ),  # is null for the root for npm list and yarn list output
        )
    )


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
        if args.input_type == "postprocessed_repo_task":
            for line in source:
                for task_data in line["tasks"].values():
                    if task_data["name"] == "list_metadata":

                        link_ids = []
                        for task_dep in task_data.get("dependencies", []):
                            add_new_package_version(session, task_dep)
                            session.commit()
                            parent_package_id = get_package_version_id_query(
                                session, task_dep
                            ).first()

                            for dep in task_dep.get("dependencies", []):
                                # is fully qualified semver for npm (or file: or github: url), semver for yarn
                                name, version = dep.rsplit("@", 1)
                                child_package_id = get_package_version_id_query(
                                    session, dict(name=name, version=version)
                                ).first()

                                link_id = get_package_version_link_id_query(
                                    session, (parent_package_id, child_package_id)
                                ).one_or_none()
                                if not link_id:
                                    session.add(
                                        PackageLink(
                                            child_package_id=child_package_id,
                                            parent_package_id=parent_package_id,
                                        )
                                    )
                                    session.commit()
                                    link_id = get_package_version_link_id_query(
                                        session, (parent_package_id, child_package_id)
                                    ).first()
                                link_ids.append(link_id)

                        session.add(
                            PackageGraph(
                                root_package_version_id=get_package_version_id_query(
                                    session, task_data["root"]
                                ).first()
                                if task_data["root"]
                                else None,
                                link_ids=link_ids,
                                package_manager="yarn"
                                if "yarn" in task_data["command"]
                                else "npm",
                                package_manager_version=None,
                            )
                        )
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
