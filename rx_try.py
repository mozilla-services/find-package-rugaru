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
from typing import Dict, Tuple, Sequence

import rx
import rx.operators as op
from rx.scheduler.eventloop import AsyncIOScheduler
from rx.subject import AsyncSubject

import gh_meta_client as gh_client
import npmsio_client


@dataclass
class OrgRepo:
    org: str
    repo: str
    languages: list = field(default_factory=list)
    dep_files: list = field(default_factory=list)
    dep_file_deps: dict = field(default_factory=dict)

    # map of manifest/dep_file_id to the query params (end cursor and page
    # size) to fetch it (since GH's GQL API doesn't let us query by node id
    # yet)
    dep_file_query_params: dict = field(default_factory=dict)

    def iter_dep_files(self) -> Dict:
        for df in self.dep_files:
            if df and df.node:
                yield self, df.node

    def iter_dep_file_deps(self) -> Tuple[Dict, Dict]:
        for _, df in self.iter_dep_files():
            if df.id not in self.dep_file_deps:
                continue

            for dep in self.dep_file_deps[df.id]:
                yield self, df, dep


# TODO: list tags and sample commits per time period in a cloned repo
# TODO: fetch image from docker registry
# TODO: run in container or use builder containers? i.e. as fetcher blah...
# TODO: script to run in container with sysdig capture
# TODO: script to list files in fetched version (and flag sketch filenames)
# TODO: script to compare built version against uploaded


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


def do_async(func, *args, **kwds):
    """
    """

    @functools.wraps(func)
    def wrapper(*fargs, **fkwds):
        return rx.from_future(asyncio.create_task(func(*fargs, **fkwds)))

    return wrapper


def map_async(func, *args, **kwds):
    return op.flat_map(do_async(func, *args, **kwds))


def main():
    args = parse_args()
    # print(args)

    loop = asyncio.get_event_loop()
    aio_scheduler = AsyncIOScheduler(loop=loop)  # NB: not thread safe
    ghc = gh_client.GHClient(
        auth_token=args.auth_token,
        lang_page_size=50,
        dep_file_page_size=3,
        dep_page_size=5,
    )

    # NB: must flat_map to materialize the futures otherwise we receive type rx.core.observable.observable.Observable
    org_repos = rx.from_iterable(args.org_repos).pipe(
        op.map(org_repo_to_OrgRepo), map_async(ghc.get_org_repo_langs)
    )

    dep_files = org_repos.pipe(
        map_async(ghc.get_dep_files),
        op.flat_map(lambda org_repo: rx.from_iterable(org_repo.iter_dep_files())),
    )

    deps = dep_files.pipe(
        map_async(ghc.get_deps),
        op.flat_map(lambda org_repo: rx.from_iterable(org_repo.iter_dep_file_deps())),
    )

    npm_deps = deps.pipe(
        op.filter(
            lambda org_repo_dep_file_dep: org_repo_dep_file_dep[2].packageManager
            == "NPM"
        )
    )

    # npm_deps.pipe(op.count(npm_deps)).subscribe(
    #     on_completed=lambda x: print("found {} npm deps".format(x)),
    #     on_error=lambda e: print("Count error Occurred: {0}".format(e)),
    #     scheduler=aio_scheduler,
    # )

    npmsio_scores = npm_deps.pipe(
        op.map(lambda org_repo_dep_file_dep: org_repo_dep_file_dep[2]),
        op.buffer_with_time_or_count(3.0, 50),  # 3 seconds or 50 items
        # op.do_action(lambda item: print("!!!", item)),
        map_async(
            lambda deps: npmsio_client.async_main([dep.packageName for dep in deps])
        ),
        op.do_action(do_async(ghc.close)),
    )

    def on_next(item):
        # print("Received {0}".format(item))
        print("Received {0} {1}".format(type(item), len(item)))
        # print("Received {0.org}/{0.repo} {1.blobPath} {2}".format(*item))
        pass

    def on_completed(loop, gh_client):
        loop.stop()
        print("on_completed Done!")

    npmsio_scores.subscribe(
        on_next=on_next,
        on_error=lambda e: print("Error Occurred: {0}".format(e)),
        on_completed=functools.partial(on_completed, loop=loop, gh_client=ghc),
        scheduler=aio_scheduler,
    )

    loop.run_forever()
    print("main done")


if __name__ == "__main__":
    main()
