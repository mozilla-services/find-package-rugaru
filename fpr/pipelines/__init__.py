from fpr.pipelines.cargo_audit import pipeline as cargo_audit
from fpr.pipelines.cargo_metadata import pipeline as cargo_metadata
from fpr.pipelines.crate_graph import pipeline as crate_graph
from fpr.pipelines.crates_io_metadata import pipeline as crates_io_metadata
from fpr.pipelines.find_git_refs import pipeline as find_git_refs
from fpr.pipelines.rust_changelog import pipeline as rust_changelog
from fpr.pipelines.github_metadata import pipeline as github_metadata

pipelines = [
    cargo_audit,
    cargo_metadata,
    crate_graph,
    crates_io_metadata,
    find_git_refs,
    github_metadata,
    rust_changelog,
]
