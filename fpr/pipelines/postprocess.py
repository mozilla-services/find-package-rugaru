import argparse
import asyncio
from collections import ChainMap
from dataclasses import asdict, dataclass
import functools
import itertools
import json
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

from fpr.rx_util import on_next_save_to_jsonl
from fpr.graph_util import npm_packages_to_networkx_digraph, get_graph_stats
from fpr.serialize_util import (
    get_in,
    extract_fields,
    extract_nested_fields,
    iter_jsonlines,
    REPO_FIELDS,
)
from fpr.models import GitRef, OrgRepo, Pipeline
from fpr.models.language import (
    DependencyFile,
    languages,
    ContainerTask,
    package_managers,
)
from fpr.models.pipeline import add_infile_and_outfile
from fpr.models.nodejs import NPMPackage, flatten_deps
from fpr.pipelines.util import exc_to_str


NAME = "postprocess"

log = logging.getLogger(f"fpr.pipelines.{NAME}")


__doc__ = """Post processes tasks for various outputs e.g. flattening deps,
filtering and extracting fields, etc.

Does not spin up containers or hit the network.
"""


def parse_args(pipeline_parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser = add_infile_and_outfile(pipeline_parser)
    parser.add_argument(
        "--repo-task",
        type=str,
        action="append",
        required=False,
        default=[],
        help="postprocess install, list_metadata, or audit tasks."
        "Defaults to none of them.",
    )
    return parser


# want: (repo, ref/tag, dep_files w/ hashes, deps, [dep. stats or vuln. stats] (join for final analysis))

DepFileRow = Tuple[OrgRepo, GitRef, DependencyFile, Dict]


def group_by_org_repo_ref_path(
    source: Generator[Dict[str, Any], None, None]
) -> Generator[Tuple[Tuple[str, str, pathlib.Path], List[DepFileRow]], None, None]:
    # read all input rows into memory
    rows: List[DepFileRow] = [
        (
            OrgRepo(item["org"], item["repo"]),
            GitRef.from_dict(item["ref"]),
            [DependencyFile.from_dict(df) for df in item["dependency_files"]],
            item,
        )
        for item in source
    ]
    # sort in-place by org repo then ref value (sorted is stable)
    sorted(rows, key=lambda row: row[0].org_repo)
    sorted(rows, key=lambda row: row[1].value)

    for row in rows:
        sorted(row[2], key=lambda r: r.path)

    if all(len(row[2]) > 0 for row in rows):
        sorted(rows, key=lambda row: row[2][0].sha256)
    if all(len(row[2]) > 1 for row in rows):
        sorted(rows, key=lambda row: row[2][1].sha256)

    # group by org repo then ref value
    for org_repo_ref_key, group_iter in itertools.groupby(
        rows,
        key=lambda row: (
            row[0].org_repo,
            row[1].value,
            row[2][0].sha256,
            row[2][1].sha256 if len(row[2]) > 1 else None,
        ),
    ):
        (
            org_repo_key,
            ref_value_key,
            first_dep_file_sha256,
            second_dep_file_sha256,
        ) = org_repo_ref_key
        org_repo_ref_rows = list(group_iter)

        yield (
            org_repo_key,
            ref_value_key,
            first_dep_file_sha256,
            second_dep_file_sha256,
        ), org_repo_ref_rows


def parse_stdout_as_json(stdout: Optional[str]) -> Optional[Dict]:
    if stdout is None:
        return None

    try:
        parsed_stdout = json.loads(stdout)
        return parsed_stdout
    except json.decoder.JSONDecodeError as e:
        log.warn(f"error parsing stdout as JSON: {e}")

    return None


def parse_stdout_as_jsonlines(stdout: Optional[str]) -> Optional[Sequence[Dict]]:
    if stdout is None:
        return None

    try:
        return list(
            line
            for line in iter_jsonlines(stdout.split("\n"))
            if isinstance(line, dict)
        )
    except json.decoder.JSONDecodeError as e:
        log.warn(f"error parsing stdout as JSON: {e}")

    return None


def parse_npm_list(parsed_stdout: Dict) -> Dict:
    deps = [dep for dep in flatten_deps(parsed_stdout)]
    updates = {"problems": get_in(parsed_stdout, ["problems"], [])}
    updates["dependencies"] = [asdict(dep) for dep in deps]
    updates["dependencies_count"] = len(deps)
    updates["problems_count"] = len(updates["problems"])

    updates["root"] = asdict(deps[-1]) if len(deps) else None
    updates["direct_dependencies_count"] = (
        len(deps[-1].dependencies) if len(deps) else None
    )
    updates["graph_stats"] = (
        get_graph_stats(npm_packages_to_networkx_digraph(deps)) if deps else dict()
    )
    return updates


def parse_yarn_list(parsed_stdout: Sequence[Dict]) -> Optional[Dict]:
    updates: Dict = dict(dependencies=[])
    deps: List[NPMPackage] = []
    for line in parsed_stdout:
        line_type, line_data = line.get("type", None), line.get("data", dict())
        if line_type == "tree":
            deps.extend(
                NPMPackage.from_yarn_tree_line(dep) for dep in line_data["trees"]
            )
        else:
            # TODO: populate "problems" to match npm list field?
            log.warn(
                f"got unexpected yarn list line type: {line_type} with data {line_data}"
            )
    updates["dependencies"] = [asdict(dep) for dep in deps]
    updates["dependencies_count"] = len(deps)

    # yarn list doesn't include the root e.g. taskcluster
    updates["root"] = None
    updates["direct_dependencies_count"] = None

    # TODO: make sure we're actually resolving a graph
    updates["graph_stats"] = dict()
    return updates


def parse_npm_audit(parsed_stdout: Dict) -> Dict:
    # has format:
    # {
    #   actions: ...
    #   advisories: null or {
    #     <npm adv. id>: {
    # metadata: null also has an exploitablity score
    #
    # } ...
    #   }
    #   metadata: null or e.g. {
    #     "vulnerabilities": {
    #         "info": 0,
    #         "low": 0,
    #         "moderate": 6,
    #         "high": 0,
    #         "critical": 0
    #     },
    #     "dependencies": 896680,
    #     "devDependencies": 33885,
    #     "optionalDependencies": 10215,
    #     "totalDependencies": 940274
    #   }
    # }
    updates = extract_nested_fields(
        parsed_stdout,
        {
            "dependencies_count": ["metadata", "dependencies"],
            "dev_dependencies_count": ["metadata", "devDependencies"],
            "optional_dependencies_count": ["metadata", "optionalDependencies"],
            "total_dependencies_count": ["metadata", "totalDependencies"],
            "vulnerabilities": ["metadata", "vulnerabilities"],
            "advisories": ["advisories"],
            "error": ["error"],
        },
    )
    updates["advisories"] = (
        dict() if updates["advisories"] is None else updates["advisories"]
    )
    updates["vulnerabilities"] = (
        dict() if updates["vulnerabilities"] is None else updates["vulnerabilities"]
    )
    updates["vulnerabilities_count"] = sum(updates["vulnerabilities"].values())
    return updates


def parse_yarn_audit(parsed_stdout: Sequence[Dict]) -> Optional[Dict]:
    updates: Dict = dict(advisories=[])
    for line in parsed_stdout:
        line_type, line_data = line.get("type", None), line.get("data", dict())
        if line_type == "auditAdvisory":
            # TODO: normalize w/ npm advisory output
            updates["advisories"].append(line_data)
        elif line_type == "auditSummary":
            updates.update(
                extract_nested_fields(
                    line_data,
                    {
                        "dependencies_count": ["dependencies"],
                        "dev_dependencies_count": ["devDependencies"],
                        "optional_dependencies_count": ["optionalDependencies"],
                        "total_dependencies_count": ["totalDependencies"],
                        "vulnerabilities": ["vulnerabilities"],
                    },
                )
            )
            updates["vulnerabilities_count"] = sum(updates["vulnerabilities"].values())
        else:
            # TODO: populate "error": ["error"], to match npm audit error field?
            log.warn(
                f"got unexpected yarn audit line type: {line_type} with data {line_data}"
            )
    return updates


def parse_npm_task(task_name: str, line: Dict) -> Optional[Dict]:
    # TODO: reuse cached results for each set of dep files w/ hashes and task name
    parsed_stdout = parse_stdout_as_json(get_in(line, ["task", "stdout"], None))
    if parsed_stdout is None:
        log.warn("got non-JSON stdout for npm")
        return None

    if task_name == "list_metadata":
        return parse_npm_list(parsed_stdout)
    elif task_name == "audit":
        return parse_npm_audit(parsed_stdout)
    elif task_name == "install":
        return None
    else:
        raise NotImplementedError()


def parse_yarn_task(task_name: str, line: Dict) -> Optional[Dict]:
    parsed_stdout = parse_stdout_as_jsonlines(get_in(line, ["task", "stdout"], None))
    if parsed_stdout is None:
        log.warn("got non-JSON lines stdout for yarn")
        return None

    if task_name == "list_metadata":
        return parse_yarn_list(parsed_stdout)
    elif task_name == "audit":
        return parse_yarn_audit(parsed_stdout)
    elif task_name == "install":
        return None
    else:
        raise NotImplementedError()


async def run_pipeline(
    source: Generator[Dict[str, Any], None, None], args: argparse.Namespace
) -> AsyncGenerator[Dict, None]:
    log.info(f"{pipeline.name} pipeline started")

    for (
        (org_repo_key, ref_value_key, first_dep_file_sha256, second_dep_file_sha256),
        rows,
    ) in group_by_org_repo_ref_path(source):
        task_names = [get_in(row[-1], ["task", "name"], None) for row in rows]
        dep_files = [row[2] for row in rows]
        # print(
        #     f"{org_repo_key} {ref_value_key} {first_dep_file_sha256} {second_dep_file_sha256}"
        #     f" task ns: {task_names}"
        # )
        result = extract_fields(
            rows[0][-1],
            [
                "branch",
                "commit",
                "tag",
                "org",
                "repo",
                "repo_url",
                "ref",
                "dependency_files",
            ],
        )
        result["tasks"] = dict()
        for *_, line in rows:
            task_name = get_in(line, ["task", "name"], None)
            if task_name not in args.repo_task:
                continue

            result["tasks"][task_name] = extract_fields(
                line["task"],
                [
                    "command",
                    "container_name",
                    "exit_code",
                    "name",
                    "relative_path",
                    "working_dir",
                ],
            )

            task_command = get_in(line, ["task", "command"], None)
            if any(
                task_command == task.command
                for task in package_managers["npm"].tasks.values()
            ):
                updates = parse_npm_task(task_name, line)
            elif any(
                task_command == task.command
                for task in package_managers["yarn"].tasks.values()
            ):
                updates = parse_yarn_task(task_name, line)
            else:
                continue

            if updates:
                if task_name == "list_metadata":
                    log.info(
                        f"wrote {result['tasks'][task_name]['name']} {result['org']}/{result['repo']} {result['tasks'][task_name]['relative_path']}"
                        f" {result['ref']['value']} w/"
                        f" {updates['dependencies_count']} deps and {updates.get('problems_count', 0)} problems"
                        # f" {updates['graph_stats']}"
                    )
                elif task_name == "audit":
                    log.info(
                        f"wrote {result['tasks'][task_name]['name']} {result['org']}/{result['repo']} {result['tasks'][task_name]['relative_path']}"
                        f" {result['ref']['value']} w/"
                        f" {updates['vulnerabilities_count']} vulns"
                    )
                result["tasks"][task_name].update(updates)
        yield result


FIELDS: AbstractSet = set()


pipeline = Pipeline(
    # TODO: make generic over langs and package managers and rename
    name=NAME,
    desc=__doc__,
    fields=FIELDS,
    argparser=parse_args,
    reader=iter_jsonlines,
    runner=run_pipeline,
    writer=on_next_save_to_jsonl,
)
