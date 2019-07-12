import sys

import asyncio
import aiohttp
import time
from typing import Dict, Tuple, Sequence

import snug
import quiz

# https://developer.github.com/v4/previews/#access-to-a-repositories-dependency-graph
DEP_GRAPH_PREVIEW = "application/vnd.github.hawkgirl-preview+json"

# https://developer.github.com/v4/previews/#repository-vulnerability-alerts
VULN_ALERT_PREVIEW = "application/vnd.github.vixen-preview+json"


def auth_factory(auth):
    """Add an HTTP Authorization header from a Github PAT"""
    assert isinstance(auth, str)
    return snug.header_adder(dict(Authorization="bearer {auth}".format(auth=auth)))


def aiohttp_session():
    headers = dict(Accept=",".join([DEP_GRAPH_PREVIEW, VULN_ALERT_PREVIEW]))
    headers["User-Agent"] = "Mozilla-Dependency-Observatory/g-k"
    return aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=4), headers=headers
    )


async def async_query(async_executor, query):
    max_tries = 15
    try_num = 0
    while try_num < max_tries:
        try:
            result = await async_executor(query)
            # status = result.__metadata__.response.status_code
            # print(status, result.rateLimit, file=sys.stderr)
            break
        except quiz.ErrorResponse as err:
            # err.data,
            print("got a quiz.ErrorResponse", err, err.errors, file=sys.stderr)
            result = None
            if len(err.errors) and err.errors[0].get("type", None) == "NOT_FOUND":
                break

            # if len(err.errors) and err.errors[0].get('message', None) == 'timedout':
            # exponential backoff
            backoff_sleep_seconds = 2 ** try_num + 60
            print(
                "on try {} sleeping for backoff {}".format(
                    try_num, backoff_sleep_seconds
                ),
                file=sys.stderr,
            )
            await asyncio.sleep(backoff_sleep_seconds)
        except quiz.HTTPError as err:
            print("got a quiz.HTTPError", err, err.response, file=sys.stderr)
            result = None
            if err.response.status_code == 404:
                break
            # if we hit the rate limit or the server is down
            elif err.response.status_code in {403, 503}:
                # exponential backoff
                backoff_sleep_seconds = 2 ** try_num + 60

                retry_after = err.response.headers.get("Retry-After", None)
                reset_at = err.response.headers.get("X-RateLimit-Reset", None)
                if retry_after and int(retry_after) > 0:
                    retry_after_seconds = int(retry_after)
                    print(
                        "on try {} sleeping for retry {}".format(
                            try_num, retry_after_seconds
                        ),
                        file=sys.stderr,
                    )
                    await asyncio.sleep(retry_after_seconds)
                elif reset_at:
                    # wait for the window to reset
                    # https://developer.github.com/v3/#rate-limiting
                    reset_sleep_seconds = int(reset_at) - int(time.time())
                    if reset_sleep_seconds > 0:
                        print(
                            "on try {} sleeping until reset {}".format(
                                try_num, reset_sleep_seconds
                            ),
                            file=sys.stderr,
                        )
                        await asyncio.sleep(reset_sleep_seconds)
                    else:
                        print(
                            "on try {} sleeping for backoff {}".format(
                                try_num, backoff_sleep_seconds
                            ),
                            file=sys.stderr,
                        )
                        await asyncio.sleep(backoff_sleep_seconds)
                else:
                    print(
                        "on try {} sleeping for backoff {}".format(
                            try_num, backoff_sleep_seconds
                        ),
                        file=sys.stderr,
                    )
                    await asyncio.sleep(backoff_sleep_seconds)

        try_num += 1
    return result


async def async_github_schema_from_cache_or_url(schema_path, async_exec):
    # TODO: save E-Tag or Last-Modified then send If-Modified-Since or
    # If-None-Match and check for HTTP 304 Not Modified
    # https://developer.github.com/v3/#conditional-requests
    # NB: this might not be supported https://developer.github.com/v4/guides/resource-limitations/
    try:
        schema = quiz.Schema.from_path(schema_path)
    except IOError:
        print("Fetching github schema", file=sys.stderr)
        result = await async_exec(quiz.INTROSPECTION_QUERY)
        schema = quiz.Schema.from_raw(result["__schema"], scalars=(), module=None)
        schema.to_path(schema_path)
    return schema


def repo_query(schema, org_name, repo_name, first=10):
    _ = quiz.SELECTOR
    return schema.query[
        _.rateLimit[_.limit.cost.remaining.resetAt].repository(
            owner=org_name, name=repo_name
        )[
            _.createdAt.updatedAt.description.isArchived.isPrivate.isFork.languages(
                first=first
            )[
                _.pageInfo[_.hasNextPage.endCursor].totalCount.totalSize.edges[
                    _.node[_.id.name]
                ]
            ]
            .dependencyGraphManifests(first=first)[
                _.pageInfo[_.hasNextPage.endCursor].totalCount.edges[
                    _.node[
                        _.id.blobPath.dependenciesCount.exceedsMaxSize.filename.parseable.dependencies(
                            first=first
                        )[
                            _.pageInfo[_.hasNextPage.endCursor].totalCount.nodes[
                                _.packageName.packageManager.hasDependencies.requirements
                            ]
                        ]
                    ]
                ]
            ]
            .vulnerabilityAlerts(first=first)[
                _.pageInfo[_.hasNextPage.endCursor].totalCount.edges[
                    _.node[
                        _.id.dismissReason.dismissedAt.dismisser[
                            _.id.name  # need user:email oauth scope for .email
                        ]
                        .securityAdvisory[
                            _.id.ghsaId.summary.description.severity.publishedAt.updatedAt.withdrawnAt.identifiers[
                                _.type.value
                            ].vulnerabilities(
                                first=first
                            )[
                                _.pageInfo[_.hasNextPage.endCursor].totalCount.nodes[
                                    _.package[
                                        _.name.ecosystem
                                    ].severity.updatedAt.vulnerableVersionRange
                                ]
                            ]
                        ]
                        .vulnerableManifestFilename.vulnerableManifestPath.vulnerableRequirements
                    ]
                ]
            ]
        ]
    ]


def repo_langs_query(schema, org_name, repo_name, first=10, after=None):
    _ = quiz.SELECTOR
    if after:
        return schema.query[
            _.rateLimit[_.limit.cost.remaining.resetAt].repository(
                owner=org_name, name=repo_name
            )[
                _.languages(after=after, first=first)[
                    _.pageInfo[_.hasNextPage.endCursor].edges[_.node[_.id.name]]
                ]
            ]
        ]
    else:
        return schema.query[
            _.rateLimit[_.limit.cost.remaining.resetAt].repository(
                owner=org_name, name=repo_name
            )[
                _.createdAt.updatedAt.description.isArchived.isPrivate.isFork.languages(
                    first=first
                )[
                    _.pageInfo[_.hasNextPage.endCursor].totalCount.totalSize.edges[
                        _.node[_.id.name]
                    ]
                ]
            ]
        ]


def repo_manifests_query(schema, org_name, repo_name, first=10, after=None):
    _ = quiz.SELECTOR
    if after:
        return schema.query[
            _.rateLimit[_.limit.cost.remaining.resetAt].repository(
                owner=org_name, name=repo_name
            )[
                _.dependencyGraphManifests(first=first, after=after)[
                    _.pageInfo[_.hasNextPage.endCursor].totalCount.edges[
                        _.node[
                            _.id.blobPath.dependenciesCount.exceedsMaxSize.filename.parseable.dependencies(
                                first=first
                            )[
                                _.pageInfo[_.hasNextPage.endCursor].totalCount.nodes[
                                    _.packageName.packageManager.hasDependencies.requirements
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ]
    else:
        return schema.query[
            _.rateLimit[_.limit.cost.remaining.resetAt].repository(
                owner=org_name, name=repo_name
            )[
                _.dependencyGraphManifests(first=first)[
                    _.pageInfo[_.hasNextPage.endCursor].totalCount.edges[
                        _.node[
                            _.id.blobPath.dependenciesCount.exceedsMaxSize.filename.parseable.dependencies(
                                first=first
                            )[
                                _.pageInfo[_.hasNextPage.endCursor].totalCount.nodes[
                                    _.packageName.packageManager.hasDependencies.requirements
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ]


def repo_manifest_deps_query(
    schema,
    org_name,
    repo_name,
    manifest_first=5,
    manifest_after=None,
    first=100,
    after=None,
):
    _ = quiz.SELECTOR
    if after is None:
        return schema.query[
            _.rateLimit[_.limit.cost.remaining.resetAt].repository(
                owner=org_name, name=repo_name
            )[
                _.dependencyGraphManifests(first=manifest_first)[
                    _.pageInfo[_.hasNextPage.endCursor].totalCount.edges[
                        _.node[
                            _.id.blobPath.dependenciesCount.exceedsMaxSize.filename.parseable.dependencies(
                                first=first, after=after
                            )[
                                _.pageInfo[_.hasNextPage.endCursor].totalCount.nodes[
                                    _.packageName.packageManager.hasDependencies.requirements
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ]
    else:
        return schema.query[
            _.rateLimit[_.limit.cost.remaining.resetAt].repository(
                owner=org_name, name=repo_name
            )[
                _.dependencyGraphManifests(first=manifest_first, after=manifest_after)[
                    _.pageInfo[_.hasNextPage.endCursor].totalCount.edges[
                        _.node[
                            _.id.blobPath.dependenciesCount.exceedsMaxSize.filename.parseable.dependencies(
                                first=first, after=after
                            )[
                                _.pageInfo[_.hasNextPage.endCursor].totalCount.nodes[
                                    _.packageName.packageManager.hasDependencies.requirements
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ]


class GHClient:
    def __init__(
        self,
        auth_token: str,
        lang_page_size: int,
        dep_file_page_size: int,
        dep_page_size: int,
    ):
        self.auth_token = auth_token
        self.lang_page_size = lang_page_size
        self.dep_file_page_size = dep_file_page_size
        self.dep_page_size = dep_page_size

    async def _async_init(self):
        if not all(
            [
                hasattr(self, "session"),
                hasattr(self, "async_exec"),
                hasattr(self, "schema"),
            ]
        ):
            self.session = aiohttp_session()
            self.async_exec = quiz.async_executor(
                url="https://api.github.com/graphql",
                auth=auth_factory(self.auth_token),
                client=self.session,
            )
            self.schema = await async_github_schema_from_cache_or_url(
                "github_graphql_schema.json", self.async_exec
            )
        return self.session

    async def close(self, *args):
        # see: https://aiohttp.readthedocs.io/en/stable/client_advanced.html#graceful-shutdown
        self.session.close()
        await asyncio.sleep(0.25)

    async def get_org_repo_langs(self, org_repo, first=None):
        if first is None:
            first = self.lang_page_size

        await self._async_init()
        query = repo_langs_query(self.schema, org_repo.org, org_repo.repo, first=first)
        print(org_repo, "fetching repo page", file=sys.stderr)
        repo = await async_query(self.async_exec, query)
        if repo is None or repo.repository is None:
            raise Exception(
                org_repo, "fetching repo page returned repo.repository None"
            )
        # TODO: paginate
        assert not repo.repository.languages.pageInfo.hasNextPage
        org_repo.languages.extend(repo.repository.languages.edges)
        return org_repo

    async def get_dep_files(self, org_repo, first=None):
        if first is None:
            first = self.dep_file_page_size

        await self._async_init()
        query = repo_manifests_query(
            self.schema, org_repo.org, org_repo.repo, first=first
        )
        print(
            "fetching dep files page for {0.org} {0.repo}".format(org_repo),
            file=sys.stderr,
        )
        repo = await async_query(self.async_exec, query)
        # TODO: paginate
        assert not repo.repository.dependencyGraphManifests.pageInfo.hasNextPage

        cursor = repo.repository.dependencyGraphManifests.pageInfo.endCursor
        org_repo.dep_files.extend(repo.repository.dependencyGraphManifests.edges)

        for edge in repo.repository.dependencyGraphManifests.edges:
            org_repo.dep_file_query_params[edge.node.id] = dict(
                cursor=cursor, first=self.dep_file_page_size
            )
        return org_repo

    async def get_deps(self, org_repo_dep_file, first=None):
        if first is None:
            first = self.dep_page_size

        await self._async_init()

        org_repo, dep_file = org_repo_dep_file
        query_params = org_repo.dep_file_query_params[dep_file.id]
        print(org_repo.org, org_repo.repo, dep_file, query_params)

        query = repo_manifest_deps_query(
            self.schema,
            org_repo.org,
            org_repo.repo,
            manifest_first=query_params["first"],
            manifest_after=query_params["cursor"],
            first=first,
            after=None,
        )
        print(
            "fetching {2} manifest deps for {0.org}/{0.repo} {1.blobPath}".format(
                org_repo, dep_file, first
            ),
            file=sys.stderr,
        )
        repo = await async_query(self.async_exec, query)
        # print('hi', len(repo.repository.dependencyGraphManifests.edges))

        for manifest_edge in repo.repository.dependencyGraphManifests.edges:
            if manifest_edge.node.id == dep_file.id:
                org_repo.dep_file_deps[
                    dep_file.id
                ] = manifest_edge.node.dependencies.nodes

        # TODO: paginate
        # assert not repo.repository.dependencyGraphManifests.pageInfo.hasNextPage
        print(
            "found {2} manifest deps for {0.org}/{0.repo} {1.blobPath}".format(
                org_repo, dep_file, len(org_repo.dep_file_deps[dep_file.id])
            ),
            file=sys.stderr,
        )

        return org_repo
