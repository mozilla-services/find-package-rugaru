import sys

import asyncio
import aiohttp
import time

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


def repo_langs_query_next_page(schema, org_name, repo_name, after, first=10):
    _ = quiz.SELECTOR
    return schema.query[
        _.rateLimit[_.limit.cost.remaining.resetAt].repository(
            owner=org_name, name=repo_name
        )[
            _.languages(after=after, first=first)[
                _.pageInfo[_.hasNextPage.endCursor].edges[_.node[_.id.name]]
            ]
        ]
    ]


def repo_manifests_query_next_page(schema, org_name, repo_name, after, first=10):
    _ = quiz.SELECTOR
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


def repo_manifest_deps_query_next_page(
    schema, org_name, repo_name, manifest_first, manifest_after, after, first=10
):
    _ = quiz.SELECTOR
    if manifest_after is None:
        return schema.query[
            _.rateLimit[_.limit.cost.remaining.resetAt].repository(
                owner=org_name, name=repo_name
            )[
                _.dependencyGraphManifests(first=first)[
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
                _.dependencyGraphManifests(first=first, after=after)[
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



    )











async def get_org_repo_langs(auth_token, org_repo):
    async with aiohttp_session() as s:
        async_exec = quiz.async_executor(
            url="https://api.github.com/graphql",
            auth=auth_factory(auth_token),
            client=s,
        )
        schema = await async_github_schema_from_cache_or_url(
            "github_graphql_schema.json", async_exec
        )
        return await query_repo_data(schema, org_repo, async_exec)
