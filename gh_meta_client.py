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


async def query_repo_data(schema, org_repo, async_exec):
    repo_page_size = 100
    lang_page_size = 30
    manifests_page_size = 50
    dep_page_size = 100

    # fetch top-level repo info w/ first repo_page_size of linked nodes except manifests
    query = repo_query(schema, org_repo.org, org_repo.repo, first=repo_page_size)
    print(org_repo, "fetching repo page", file=sys.stderr)
    repo = await async_query(async_exec, query)
    if repo is None or repo.repository is None:
        print(
            org_repo,
            "fetching repo page returned repo.repository None",
            file=sys.stderr,
        )
        return None

    print(
        org_repo,
        "fetched repo page with %d/%d langs, %d/%d dep manifests, and %d/%d vuln alerts"
        % (
            len(repo.repository.languages.edges),
            repo.repository.languages.totalCount,
            len(repo.repository.dependencyGraphManifests.edges),
            repo.repository.dependencyGraphManifests.totalCount,
            len(repo.repository.vulnerabilityAlerts.edges),
            repo.repository.vulnerabilityAlerts.totalCount,
        ),
        file=sys.stderr,
    )
    if repo.repository.vulnerabilityAlerts.totalCount > repo_page_size:
        print(
            org_repo,
            "warning: missing %d vuln alerts"
            % repo.repository.vulnerabilityAlerts.totalCount
            - len(repo.repository.vulnerabilityAlerts.edges),
            file=sys.stderr,
        )

    for e in repo.repository.dependencyGraphManifests.edges:
        print(
            org_repo,
            e.node.filename,
            "fetched %d/%d deps"
            % (len(e.node.dependencies.nodes), e.node.dependenciesCount),
            file=sys.stderr,
        )
        if e.node.exceedsMaxSize or not e.node.parseable:
            print(
                org_repo,
                e.node.filename,
                "warning: not parseable? %s or exceedsMaxSize? %s"
                % (not e.node.parseable, e.node.exceedsMaxSize),
                file=sys.stderr,
            )

    response = repo
    while response.repository.languages.pageInfo.hasNextPage:
        cursor = response.repository.languages.pageInfo.endCursor
        query = repo_langs_query_next_page(
            schema, org_repo.org, org_repo.repo, first=lang_page_size, after=cursor
        )
        print(
            org_repo,
            "fetching lang page of size %d w/ cursor %s" % (lang_page_size, cursor),
            file=sys.stderr,
        )
        response = await async_query(async_exec, query)
        if response is None:
            print(
                org_repo,
                "failed to fetch lang page of size %d w/ cursor %s"
                % (lang_page_size, cursor),
                file=sys.stderr,
            )
            break

        repo.repository.languages.edges.extend(response.repository.languages.edges)
        print(
            org_repo,
            "fetched lang page w/ %d langs for %d/%d"
            % (
                len(response.repository.languages.edges),
                len(repo.repository.languages.edges),
                repo.repository.languages.totalCount,
            ),
            file=sys.stderr,
        )
    assert len(repo.repository.languages.edges) == repo.repository.languages.totalCount

    # TODO: figure out why we only getting one manifest back when first=1 in repo query (i.e. pagination seems to be broken)
    response = repo
    while response.repository.dependencyGraphManifests.pageInfo.hasNextPage:
        cursor = response.repository.dependencyGraphManifests.pageInfo.endCursor
        query = repo_manifests_query_next_page(
            schema, org_repo.org, org_repo.repo, first=manifests_page_size, after=cursor
        )
        print(
            org_repo,
            "fetching %d manifests from cursor %s" % (manifests_page_size, cursor),
            file=sys.stderr,
        )
        response = await async_query(async_exec, query)
        if response is None:
            print(
                org_repo,
                "failed to fetch manifests of size %d w/ cursor %s"
                % (manifests_page_size, cursor),
                file=sys.stderr,
            )
            break

        print(
            org_repo,
            "fetched %d/%d manifests"
            % (
                len(repo.repository.dependencyGraphManifests.edges),
                repo.repository.dependencyGraphManifests.totalCount,
            ),
            file=sys.stderr,
        )
        repo.repository.dependencyGraphManifests.edges.extend(
            response.repository.dependencyGraphManifests.edges
        )
    assert (
        len(repo.repository.dependencyGraphManifests.edges)
        == repo.repository.dependencyGraphManifests.totalCount
    )

    for manifest_edge in repo.repository.dependencyGraphManifests.edges:
        manifest = manifest_edge.node
        manifest_id = manifest.id
        response = repo
        while manifest_edge.node.dependencies.pageInfo.hasNextPage:
            cursor = manifest_edge.node.dependencies.pageInfo.endCursor
            manifest_cursor = None
            query = repo_manifest_deps_query_next_page(
                schema,
                org_repo.org, org_repo.repo,
                manifest_first=manifests_page_size,
                manifest_after=manifest_cursor,  # response.repository.dependencyGraphManifests.pageInfo.endCursor,
                first=dep_page_size,
                after=cursor
            )
            print(
                org_repo,
                manifest.filename,
                "fetching %d deps from manifest cursor %s and dep cursor %s"
                % (dep_page_size, manifest_cursor, cursor),
                file=sys.stderr,
            )

            response = await async_query(async_exec, query)
            if response is None:
                print(
                    org_repo,
                    manifest.filename,
                    "failed to fetch %d deps from manifest cursor %s and dep cursor %s"
                    % (dep_page_size, manifest_cursor, cursor),
                    file=sys.stderr,
                )
                break

            for response_edge in response.repository.dependencyGraphManifests.edges:
                if response_edge.node.id == manifest_id:
                    manifest.dependencies.nodes.extend(
                        response_edge.node.dependencies.nodes
                    )

            print(
                org_repo,
                manifest_edge.node.filename,
                "fetched dep page w/ %d deps for %d/%d"
                % (
                    next(
                        len(e.node.dependencies.nodes)
                        for e in response.repository.dependencyGraphManifests.edges
                        if e.node.id == manifest_id
                    ),
                    next(
                        len(e.node.dependencies.nodes)
                        for e in repo.repository.dependencyGraphManifests.edges
                        if e.node.id == manifest_id
                    ),
                    next(
                        e.node.dependenciesCount
                        for e in repo.repository.dependencyGraphManifests.edges
                        if e.node.id == manifest_id
                    ),
                ),
                file=sys.stderr,
            )

            manifest_edge = next(
                e
                for e in response.repository.dependencyGraphManifests.edges
                if e.node.id == manifest_id
            )
        assert next(
            len(e.node.dependencies.nodes)
            for e in repo.repository.dependencyGraphManifests.edges
            if e.node.id == manifest_id
        ) == next(
            e.node.dependenciesCount
            for e in repo.repository.dependencyGraphManifests.edges
            if e.node.id == manifest_id
        )
    assert (
        len(repo.repository.vulnerabilityAlerts.edges)
        == repo.repository.vulnerabilityAlerts.totalCount
    )

    return repo


async def async_main(auth_token, org_repos):
    async with aiohttp_session() as s:
        async_exec = quiz.async_executor(
            url="https://api.github.com/graphql",
            auth=auth_factory(auth_token),
            client=s,
        )
        schema = await async_github_schema_from_cache_or_url(
            "github_graphql_schema.json", async_exec
        )
        return query_repo_data(schema, org_repo, async_exec)


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
