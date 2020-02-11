import asyncio
import argparse
import logging
import sys
import time
import json
import functools
from dataclasses import dataclass
from random import randrange
from typing import Any, AnyStr, Dict, Tuple, AsyncGenerator, Generator, Union


from fpr.rx_util import sleep_by_index, on_next_save_to_jsonl
from fpr.serialize_util import (
    get_in,
    extract_fields,
    iter_jsonlines,
    REPO_FIELDS,
    RUST_FIELDS,
)
import fpr.docker.containers as containers
from fpr.models import GitRef, OrgRepo, Pipeline, SerializedCargoMetadata
from fpr.pipelines.util import exc_to_str

log = logging.getLogger("fpr.pipelines.cargo_metadata")

__doc__ = """
Given a repo_url and git ref, clones the repo, finds Cargo.lock files, and runs cargo metadata on them.
"""


@dataclass
class CargoMetadataBuildArgs:
    base_image_name: str = "rust"
    base_image_tag: str = "1-slim"

    # NB: for buster variants a ripgrep package is available
    _DOCKERFILE = """
FROM {0.base_image}
RUN apt-get -y update && apt-get install -y curl git
RUN curl -LO https://github.com/BurntSushi/ripgrep/releases/download/11.0.2/ripgrep_11.0.2_amd64.deb
RUN dpkg -i ripgrep_11.0.2_amd64.deb
CMD ["cargo", "metadata"]
"""

    repo_tag = "dep-obs/cargo-metadata"

    @property
    def base_image(self) -> str:
        return "{0.base_image_name}:{0.base_image_tag}".format(self)

    @property
    def dockerfile(self) -> bytes:
        return CargoMetadataBuildArgs._DOCKERFILE.format(self).encode("utf-8")


async def build_container(args: CargoMetadataBuildArgs = None) -> str:
    # NB: can shell out to docker build if this doesn't work
    if args is None:
        args = CargoMetadataBuildArgs()
    await containers.build(args.dockerfile, args.repo_tag, pull=True)
    log.info("successfully built and tagged image {}".format(args.repo_tag))
    return args.repo_tag


async def run_cargo_metadata(item: Tuple[OrgRepo, GitRef]):
    org_repo, git_ref = item
    log.debug(
        "running cargo-metadata on repo {!r} ref {!r}".format(
            org_repo.github_clone_url, git_ref
        )
    )
    name = "dep-obs-cargo-metadata-{0.org}-{0.repo}-{1}".format(
        org_repo, hex(randrange(1 << 32))[2:]
    )
    results = []
    async with containers.run(
        "dep-obs/cargo-metadata:latest", name=name, cmd="/bin/bash"
    ) as c:
        await containers.ensure_repo(c, org_repo.github_clone_url)
        await containers.ensure_ref(c, git_ref, working_dir="/repo")
        (
            branch,
            commit,
            tag,
            ripgrep_version,
            cargo_version,
            rustc_version,
        ) = await asyncio.gather(
            containers.get_branch(c),
            containers.get_commit(c),
            containers.get_tag(c),
            containers.get_ripgrep_version(c),
            containers.get_cargo_version(c),
            containers.get_rustc_version(c),
        )

        log.debug("{} stdout: {}".format(name, await c.log(stdout=True)))
        log.debug("{} stderr: {}".format(name, await c.log(stderr=True)))

        cargo_tomlfiles = await containers.find_files(
            ["Cargo.toml"], c, working_dir="/repo"
        )
        log.info("{} found Cargo.toml files: {}".format(c["Name"], cargo_tomlfiles))

        for cargo_tomlfile in cargo_tomlfiles:
            working_dir = str(
                containers.path_relative_to_working_dir(
                    working_dir="/repo", file_path=cargo_tomlfile
                )
            )
            log.info("working_dir: {}".format(working_dir))
            try:
                cargo_meta = await containers.cargo_metadata(c, working_dir=working_dir)
            except containers.DockerRunException as e:
                log.debug(
                    "in {} error running cargo metadata in {}: {}".format(
                        name, working_dir, e
                    )
                )
                continue

            result = dict(
                org=org_repo.org,
                repo=org_repo.repo,
                commit=commit,
                branch=branch,
                tag=tag,
                ref=git_ref.to_dict(),
                cargo_tomlfile_path=cargo_tomlfile,
                cargo_version=cargo_version,
                ripgrep_version=ripgrep_version,
                rustc_version=rustc_version,
                metadata_output=cargo_meta,
            )
            log.debug("{} metadata result {}".format(name, result))
            log.debug("{} stdout: {}".format(name, await c.log(stdout=True)))
            log.debug("{} stderr: {}".format(name, await c.log(stderr=True)))
            results.append(result)
    return results


async def run_pipeline(
    source: Generator[Dict[str, Any], None, None], _: argparse.Namespace
) -> AsyncGenerator[Dict, None]:
    log.info("pipeline started")
    try:
        await build_container()
    except Exception as e:
        log.error(
            "error occurred building the cargo metadata image: {0}\n{1}".format(
                e, exc_to_str()
            )
        )

    for i, item in enumerate(source):
        log.debug("processing {!r}".format(item))
        org_repo, git_ref = (
            OrgRepo.from_github_repo_url(item["repo_url"]),
            GitRef.from_dict(item["ref"]),
        )
        await sleep_by_index(sleep_per_index=5.0, item=(i, item))
        try:
            for result in await run_cargo_metadata((org_repo, git_ref)):
                yield result
        except Exception as e:
            log.error("error running cargo metadata:\n{}".format(exc_to_str()))


def serialize_cargo_metadata_output(metadata_output: AnyStr) -> SerializedCargoMetadata:
    metadata_json = json.loads(metadata_output)
    result = {}

    for read_key_path, output_key in [
        [["version"], "version"],  # str should be 1
        [["resolve", "root"], "root"],  # can be null str of pkg id
        [["packages"], "packages"],  # additional data parsed from the Cargo.toml file
    ]:
        result[output_key] = get_in(metadata_json, read_key_path)

    result["nodes"] = [
        extract_fields(node, NODE_FIELDS)
        for node in get_in(metadata_json, ["resolve", "nodes"])
    ]
    return result


# id: str, features: Seq[str], deps[{}]
NODE_FIELDS = {"id", "features", "deps"}

FIELDS = RUST_FIELDS | REPO_FIELDS | {"cargo_tomlfile_path", "ripgrep_version"}


def serialize(_: argparse.Namespace, metadata_result: Dict):
    r = extract_fields(metadata_result, FIELDS)
    r["metadata"] = serialize_cargo_metadata_output(metadata_result["metadata_output"])
    return r


pipeline = Pipeline(
    name="cargo_metadata",
    desc=__doc__,
    fields=FIELDS,
    reader=iter_jsonlines,
    runner=run_pipeline,
    serializer=serialize,
    writer=on_next_save_to_jsonl,
)
