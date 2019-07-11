#!/usr/bin/env python

import os
import sys

from collections import namedtuple
import asyncio
import argparse
from dataclasses import dataclass, field
import functools
import json
import io
import itertools
import pathlib
import random

import rx
import rx.operators as op
from rx.scheduler.eventloop import AsyncIOScheduler
from rx.subject import AsyncSubject

import gh_meta_client as gh_client
@dataclass
class OrgRepo:
    org: str
    repo: str
    languages: list = field(default_factory=list)
    dep_files: list = field(default_factory=list)


# TODO: run in container or use builder containers? i.e. as fetcher blah...
# TODO: script to run in container with sysdig capture
# TODO: script to compare built version against uploaded
# TODO: list tags and sample commits per time period in a cloned repo
# TODO: fetch image from docker registry


def parse_args():
    parser = argparse.ArgumentParser(
        description="Fetch github repo metadata", usage=__doc__
    )

    parser.add_argument(
        "-a",
        "--auth-token",
        default=os.environ.get("GITHUB_PAT", None),
        help="A github personal access token. Defaults GITHUB_PAT env var. It should have most of the scopes from https://developer.github.com/v4/guides/forming-calls/#authenticating-with-graphql",
    )

    parser.add_argument(
        "org_repos",
        type=str,
        nargs="+",
        help="GH :org/:repo names e.g. 'mozilla-services/screenshots'",
    )
    return parser.parse_args()


def org_repo_to_OrgRepo(org_repo):
    return OrgRepo(*org_repo.split("/", 1))


async def aio_delay(item):
    sleep_dur = random.choice([1, 3])
    print("sleep", sleep_dur, item)
    await asyncio.sleep(sleep_dur)
    return item


def do_async(func, *args, **kwargs):
    return rx.from_future(asyncio.ensure_future(func(*args, **kwargs)))


def on_completed(loop):
    loop.stop()
    print("on_completed Done!")


def main():
    args = parse_args()
    # print(args)

    loop = asyncio.get_event_loop()
    aio_scheduler = AsyncIOScheduler(loop=loop)  # NB: not thread safe


    get_org_repo_langs = functools.partial(gh_client.get_org_repo_langs, args.auth_token, 50)
    async_get_org_repo_langs = functools.partial(do_async, get_org_repo_langs)

    get_dep_files = functools.partial(gh_client.get_dep_files, args.auth_token, 3)
    async_get_dep_files = functools.partial(do_async, get_dep_files)

    get_deps = functools.partial(gh_client.get_deps, args.auth_token, 100)
    async_get_deps = functools.partial(do_async, get_deps)

    # NB: must flat_map to materialize the futures otherwise we receive type rx.core.observable.observable.Observable
    org_repos = rx.from_iterable(args.org_repos).pipe(
        op.map(org_repo_to_OrgRepo),
        op.flat_map(async_get_org_repo_langs),
        op.flat_map(async_get_dep_files),

        # op.do_action(lambda org_repo: print('!!!', len(org_repo.dep_files))),
        op.flat_map(lambda org_repo: rx.from_iterable(zip(itertools.repeat(org_repo), (df.node for df in org_repo.dep_files)))),
        op.filter(lambda x: x[1].dependencies.nodes and x[1].dependencies.nodes[0].packageManager == 'NPM'),
        op.flat_map(async_get_deps),
    ).subscribe(
        on_next=lambda item: print("Received {0}".format(item)),
        on_error=lambda e: print("Error Occurred: {0}".format(e)),
        on_completed=functools.partial(on_completed, loop=loop),
        scheduler=aio_scheduler,
    )
    loop.run_forever()
    print("main done")


if __name__ == "__main__":
    main()
