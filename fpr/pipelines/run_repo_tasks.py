import argparse
import asyncio
from collections import ChainMap
from dataclasses import asdict
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
    Iterable,
    List,
    Optional,
    Tuple,
    Union,
)
import typing

from fpr.rx_util import on_next_save_to_jsonl
from fpr.serialize_util import get_in, extract_fields, iter_jsonlines, REPO_FIELDS
import fpr.docker.containers as containers
import fpr.docker.volumes as volumes
from fpr.models import GitRef, OrgRepo, Pipeline
from fpr.models.language import (
    ContainerTask,
    DependencyFile,
    DockerImage,
    Language,
    PackageManager,
    docker_images,
    docker_image_names,
    language_names,
    languages,
    package_manager_names,
    package_managers,
)
from fpr.models.pipeline import add_infile_and_outfile, add_volume_arg
from fpr.pipelines.util import exc_to_str

log = logging.getLogger("fpr.pipelines.run_repo_tasks")

__doc__ = """Runs tasks on a checked out git ref with dep. files"""


def parse_args(pipeline_parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser = add_infile_and_outfile(pipeline_parser)
    parser = add_volume_arg(parser)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        required=False,
        default=False,
        help="Print commands we would run and their context, but don't run them.",
    )
    parser.add_argument(
        "--git-clean",
        action="store_true",
        required=False,
        default=False,
        help="Run 'git clean -fdx' for each ref to clear package manager caches. "
        "Slower but better isolation. Defaults to false.",
    )
    parser.add_argument(
        "--use-cache",
        action="store_true",
        required=False,
        default=True,
        help="Cache and results for the same repo, and dep file directory and SHA2"
        "sums for multiple git refs (NB: ignores changes to non-dep files e.g. to "
        "node.js install hook scripts).",
    )
    parser.add_argument(
        "--docker-pull",
        action="store_true",
        required=False,
        default=False,
        help="Pull base docker images before building them. Default to False.",
    )
    parser.add_argument(
        "--docker-build",
        action="store_true",
        required=False,
        default=False,
        help="Build docker images. Default to False.",
    )
    parser.add_argument(
        "--dir",
        type=str,
        required=False,
        default=None,
        help="Only run against matching directory. "
        "e.g. './' for root directory or './packages/fxa-js-client/' for a subdirectory",
    )
    parser.add_argument(
        "--language",
        type=str,
        action="append",
        required=False,
        choices=language_names,
        default=[],
        help="Package managers to run commands for. Defaults to all of them.",
    )
    parser.add_argument(
        "--package-manager",
        type=str,
        action="append",
        required=False,
        choices=package_manager_names,
        default=[],
        help="Package managers to run commands for. Defaults to all of them.",
    )
    parser.add_argument(
        "--docker-image",
        type=str,
        action="append",
        required=False,
        choices=docker_image_names,
        default=[],
        help="Docker images to run commands in. Defaults to all of them.",
    )
    parser.add_argument(
        "--repo-task",
        type=str,
        action="append",
        required=False,
        default=[],
        help="Run install, list_metadata, or audit tasks in the order provided. "
        "Defaults to none of them.",
    )
    return parser


async def run_in_repo_at_ref(
    args: argparse.Namespace,
    item: Tuple[OrgRepo, GitRef, pathlib.Path],
    tasks: List[ContainerTask],
    version_commands: typing.Mapping[str, str],
    dry_run: bool,
    cwd_files: AbstractSet[str],
    file_rows: List[DependencyFile],
    image: DockerImage,
) -> AsyncGenerator[Dict[str, Any], None]:
    (org_repo, git_ref, path) = item

    name = f"dep-obs-nodejs-metadata-{org_repo.org}-{org_repo.repo}-{hex(randrange(1 << 32))[2:]}"
    async with containers.run(
        image.local.repo_name_tag,
        name=name,
        cmd="/bin/bash",
        volumes=[
            volumes.DockerVolumeConfig(
                name=f"fpr-org_{org_repo.org}-repo_{org_repo.repo}",
                mount_point="/repos",
                labels=asdict(org_repo),
                delete=not args.keep_volumes,
            )
        ],
    ) as c:
        await containers.ensure_repo(
            c,
            org_repo.github_clone_url,
            git_clean=args.git_clean,
            working_dir="/repos/",
        )
        await containers.ensure_ref(c, git_ref, working_dir="/repos/repo")
        branch, commit, tag, *version_results = await asyncio.gather(
            *(
                [
                    containers.get_branch(c, working_dir="/repos/repo"),
                    containers.get_commit(c, working_dir="/repos/repo"),
                    containers.get_tag(c, working_dir="/repos/repo"),
                ]
                + [
                    containers.run_container_cmd_no_args_return_first_line_or_none(
                        command, c, working_dir="/repos/repo"
                    )
                    for command in version_commands.values()
                ]
            )
        )
        versions = {
            command_name: version_results[i]
            for (i, (command_name, command)) in enumerate(version_commands.items())
        }

        working_dir = str(pathlib.Path("/repos/repo") / path)
        for task in tasks:
            last_inspect = dict(ExitCode=None)
            stdout = "dummy-stdout"

            if dry_run:
                log.info(
                    f"{name} in {working_dir} for task {task.name} skipping running {task.command} for dry run"
                )
                continue

            # use getattr since mypy thinks we're passing a self arg otherwise
            if not getattr(task, "has_files_check")(cwd_files):
                log.warn(
                    f"Missing files to run {task.name} {task.command} in {working_dir!r}"
                )
                continue
            else:
                log.debug(
                    f"have files to run {task.name} in {working_dir!r}: {cwd_files}"
                )

            log.info(
                f"{name} at {git_ref} in {working_dir} for task {task.name} running {task.command}"
            )
            try:
                job_run = await c.run(
                    cmd=task.command,
                    working_dir=working_dir,
                    wait=True,
                    check=task.check,
                )
                last_inspect = await job_run.inspect()
            except containers.DockerRunException as e:
                log.error(
                    f"{name} in {working_dir} for task {task.name} error running {task.command}: {e}"
                )
                break

            stdout = "\n".join(job_run.decoded_start_result_stdout)

            result: Dict[str, Any] = dict(
                org=org_repo.org,
                repo=org_repo.repo,
                ref=git_ref.to_dict(),
                repo_url=org_repo.github_clone_url,
                versions=versions,
                branch=branch,
                commit=commit,
                tag=tag,
                dependency_files=[fr.to_dict() for fr in file_rows],
                task={
                    "name": task.name,
                    "command": task.command,
                    "container_name": name,
                    "working_dir": working_dir,
                    "relative_path": str(path),
                    "exit_code": last_inspect["ExitCode"],
                    "stdout": stdout,
                },
            )
            c_stdout, c_stderr = await asyncio.gather(
                c.log(stdout=True), c.log(stderr=True)
            )
            log.debug(f"{name} stdout: {c_stdout}")
            log.debug(f"{name} stderr: {c_stderr}")
            yield result


DepFileRow = Tuple[OrgRepo, GitRef, DependencyFile]


def group_by_org_repo_ref_path(
    source: Generator[Dict[str, Any], None, None]
) -> Generator[Tuple[Tuple[str, str, pathlib.Path], List[DepFileRow]], None, None]:
    # read all input rows into memory
    rows: List[DepFileRow] = [
        (
            OrgRepo(item["org"], item["repo"]),
            GitRef.from_dict(item["ref"]),
            DependencyFile.from_dict(item["dependency_file"]),
        )
        for item in source
    ]

    # sort in-place by org repo then ref value (sorted is stable)
    sorted(rows, key=lambda row: row[0].org_repo)
    sorted(rows, key=lambda row: row[1].value)

    # group by org repo then ref value
    for org_repo_ref_key, group_iter in itertools.groupby(
        rows, key=lambda row: (row[0].org_repo, row[1].value)
    ):
        org_repo_key, ref_value_key = org_repo_ref_key
        org_repo_ref_rows = list(group_iter)

        # sort and group by path parent e.g. /foo/bar for /foo/bar/package.json
        sorted(org_repo_ref_rows, key=lambda row: row[2].path.parent)
        for dep_file_parent_key, inner_group_iter in itertools.groupby(
            org_repo_ref_rows, key=lambda row: row[2].path.parent
        ):
            file_rows = list(inner_group_iter)
            yield (org_repo_key, ref_value_key, dep_file_parent_key), file_rows


def iter_task_envs(
    args: argparse.Namespace,
) -> Generator[
    Tuple[Language, PackageManager, DockerImage, ChainMap, List[ContainerTask]],
    None,
    None,
]:
    enabled_languages = args.language or language_names
    if not args.language:
        log.debug(f"languages not specified using all of {enabled_languages}")

    enabled_package_managers = args.package_manager or package_manager_names
    if not args.package_manager:
        log.debug(
            f"package managers not specified using all of {enabled_package_managers}"
        )

    enabled_image_names = args.docker_image or docker_image_names
    if not args.docker_image:
        log.debug(
            f"docker image names not specified using all of {enabled_image_names}"
        )

    for language_name, package_manager_name, image_name in itertools.product(
        enabled_languages, enabled_package_managers, enabled_image_names
    ):
        if language_name not in languages:
            continue
        language = languages[language_name]
        if package_manager_name not in language.package_managers:
            continue
        package_manager = language.package_managers[package_manager_name]
        if image_name not in language.images:
            continue
        image = language.images[image_name]

        version_commands = ChainMap(
            language.version_commands,
            *[pm.version_commands for pm in language.package_managers.values()],
        )
        tasks: List[ContainerTask] = [
            package_manager.tasks[task_name] for task_name in args.repo_task
        ]
        yield language, package_manager, image, version_commands, tasks


async def build_images(
    args: argparse.Namespace, image_keys: Iterable[str]
) -> Iterable[str]:
    images = [docker_images[image_key] for image_key in image_keys]

    log.info(
        f"building images: {[image.base.repo_name_tag + ' as ' + image.local.repo_name_tag for image in images]}"
    )
    try:
        built_image_tags: Iterable[str] = await asyncio.gather(
            *[
                containers.build(
                    image.dockerfile_bytes, image.local.repo_name, pull=args.docker_pull
                )
                for image in images
            ]
        )
        log.info(f"successfully built and tagged images {built_image_tags}")
        return built_image_tags
    except Exception as err:
        log.error(f"error occurred building images: {err}\n{exc_to_str()}")
        raise err


async def run_pipeline(
    source: Generator[Dict[str, Any], None, None], args: argparse.Namespace
) -> AsyncGenerator[Dict, None]:
    log.info(f"{pipeline.name} pipeline started with args {args}")
    task_envs = list(iter_task_envs(args))
    if args.docker_build:
        await build_images(
            args, {image.local.repo_name_tag for (_, _, image, _, _) in task_envs}
        )

    # cache of results by lang name, package manager name,
    # image.local.repo_name_tag, org/repo, dep files dir path, dep file sha256s
    cache: Dict[Tuple[str, str, str, str, pathlib.Path, str], List[Dict]] = {}
    for (
        (org_repo_key, ref_value_key, dep_file_parent_key),
        file_rows,
    ) in group_by_org_repo_ref_path(source):
        files = {fr[2].path.parts[-1] for fr in file_rows}
        file_hashes = sorted([fr[2].sha256 for fr in file_rows])
        dep_files = [fr[2] for fr in file_rows]

        org_repo, git_ref = file_rows[0][0:2]

        log.debug(f"in {dep_file_parent_key!r} with files {files}")
        if args.dir is not None:
            if pathlib.PurePath(args.dir) != dep_file_parent_key:
                log.debug(
                    f"Skipping non-matching folder {dep_file_parent_key} for glob {args.dir}"
                )
                continue
            else:
                log.debug(
                    f"matching folder {dep_file_parent_key!r} for glob {args.dir!r}"
                )

        for lang, pm, image, version_commands, tasks in task_envs:
            if args.dry_run:
                log.info(
                    f"for {lang.name} {pm.name} would run in {image.local.repo_name_tag}"
                    f" {org_repo_key} {git_ref.kind.name} {git_ref.value} {dep_file_parent_key}"
                    f" {list(version_commands.values())} concurrently then"
                    f" {[t.command for t in tasks]} "
                )
                continue

            # TODO: use caching decorator
            cache_key = (
                lang.name,
                pm.name,
                image.local.repo_name_tag,
                org_repo_key,
                dep_file_parent_key,
                "-".join(file_hashes),
            )
            if args.use_cache and cache_key in cache:
                log.debug(f"using cached result for {cache_key}")
                for cached_result in cache[cache_key]:
                    cached_result["data_source"] = "in_memory_cache"
                    yield cached_result
                continue

            cache[cache_key] = []
            try:
                async for result in run_in_repo_at_ref(
                    args,
                    (org_repo, git_ref, dep_file_parent_key),
                    tasks,
                    version_commands,
                    args.dry_run,
                    files,
                    dep_files,
                    image,
                ):
                    cache[cache_key].append(result)
                    yield result
                log.debug(f"saved cached result for {cache_key}")
            except Exception as e:
                log.error(f"error running tasks {tasks!r}:\n{exc_to_str()}")


# TODO: improve validation and specify field providers
IN_FIELDS: Dict[str, Union[type, str, Dict[str, str]]] = {
    "repo_url": str,
    **asdict(
        OrgRepo.from_github_repo_url(
            "https://github.com/mozilla-services/syncstorage-rs.git"
        )
    ),
    **{"ref": GitRef.from_dict(dict(value="dummy", kind="tag")).to_dict()},
    **{"dependency_file": DependencyFile(path=pathlib.Path("./"), sha256="").to_dict()},
}
OUT_FIELDS = {**{k: v for k, v in IN_FIELDS.items() if k != "dependency_file"}}

pipeline = Pipeline(
    name="run_repo_tasks",
    desc=__doc__,
    fields=set(OUT_FIELDS.keys()),
    argparser=parse_args,
    reader=iter_jsonlines,
    runner=run_pipeline,
    writer=on_next_save_to_jsonl,
)
