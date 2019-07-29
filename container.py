import contextlib
import sys
import os
import subprocess
import time

import docker
from docker.types import LogConfig


@contextlib.contextmanager
def run(repository_tag, name, cmd=None, pull=False, tty=True, stream=False):
    # TODO: create a volume and save results to it

    client = docker.from_env()

    repository, tag = repository_tag.split(":", 1)
    if pull:
        image = client.images.pull(repository=repository, tag=tag)

    if cmd is None:
        cmd = "/bin/bash"

    lc = LogConfig(type=LogConfig.types.JSON, config={"max-size": "1g", "labels": ""})
    # breakpoint()
    container = client.containers.run(
        repository_tag, cmd, detach=True, log_config=lc, name=name, tty=tty, stream=stream
    )
    try:
        yield container
    finally:
        container.kill()
        container.remove(force=True)


def ensure_repo(container, repo_url, workdir="repo", commit=None):
    for cmd in [
        "rm -rf repo",
        'git clone --depth=1 "{repo_url}" repo'.format(repo_url=repo_url),
    ]:
        print(container.exec_run(cmd))

    if commit:
        container.exec_run(
            'git checkout "{commit}"'.format(commit=commit, workdir=workdir)
        )


def get_commit(container, workdir="/repo"):
    result = container.exec_run("git rev-parse HEAD", workdir="/repo", demux=True)
    if result.exit_code != 0:
        raise Exception("Error getting commit from container: {!r}".format(result))
    return result.output[0].strip()


def get_cargo_version(container, workdir="/repo"):
    result = container.exec_run("cargo --version", workdir="/repo", demux=True)
    if result.exit_code != 0:
        raise Exception(
            "Error getting cargo version from container: {!r}".format(result)
        )
    return result.output[0].strip()


def get_cargo_audit_version(container, workdir="/repo"):
    result = container.exec_run("cargo audit --version", workdir="/repo", demux=True)
    if result.exit_code != 0:
        raise Exception(
            "Error getting cargo audit version from container: {!r}".format(result)
        )
    return result.output[0].strip()


def get_rustc_version(container, workdir="/repo"):
    result = container.exec_run("rustc --version", workdir="/repo", demux=True)
    if result.exit_code != 0:
        raise Exception(
            "Error getting rustc version from container: {!r}".format(result)
        )
    return result.output[0].strip()


def build_cargo_audit_container(base_image="rust:1", cargo_audit_version=None):
    # TODO: cleanup "do-cargo-audit-install" container (if any) and do-cargo-audit:latest

    cmd = "cargo install cargo-audit"
    if cargo_audit_version:
        cmd += ' --version "{}"'.format(cargo_audit_version)

    name = "do-cargo-audit-install"
    repo, tag = "do-cargo-audit", "latest"

    with run(base_image, name="do-cargo-audit-install", stream=True) as c:
        install_run = c.exec_run(cmd, detach=True, stream=True)
        print('waiting for cargo audit install', file=sys.stderr)
        i = 0
        while True:
            for l in install_run.output:
                print(l.strip(), file=sys.stderr)

            for l in c.logs():
                print(l.strip(), file=sys.stderr)
            print('.', file=sys.stderr)
            time.sleep(1)
            i += 1
            if i > 60:
                break
        print(c.commit(repo, tag), file=sys.stderr)

    return repo, tag


def cargo_audit_repo(org_repo, commit="master", cargo_lockfile_path=None):
    if cargo_lockfile_path is None:
        cargo_lockfile_path = ""

    with run(
        "do-cargo-audit:latest",
        pull=False,
        name="do-cargo-audit-{0.org}-{0.repo}-{1}".format(org_repo, cargo_lockfile_path),
    ) as c:
        ensure_repo(c, org_repo.github_clone_url, commit=commit)

        return dict(
            cmd="cargo audit --json",
            org=org_repo.org,
            repo=org_repo.repo,
            cargo_version=get_cargo_version(c),
            rustc_version=get_rustc_version(c),
            cargo_audit_version=get_cargo_audit_version(c),
            commit=get_commit(c),
            audit_output=None,
            base=dict(
                image=c.image.attrs["RepoDigests"][0],
                collection_date="$(date +%F)",
                repo_url=repo_url,
                manifest_path=cargo_lockfile_path,
            ),
        )
