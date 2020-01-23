
RUN := python fpr/run_pipeline.py

IN_VENV := PYTHONPATH=$$PYTHONPATH:fpr/ bash bin/in_venv.sh
IN_IMAGE := docker run --rm -i -v /var/run/docker.sock:/var/run/docker.sock fpr:build
ifeq ($(USE_IMAGE),1)
	FPR := $(IN_IMAGE) $(RUN)
else
	FPR := $(IN_VENV) $(RUN)
endif

build-image:
	docker build -t fpr:build .

rust-changelog:
	printf '{"repo_url": "https://github.com/mozilla-services/channelserver"}' | \
		$(FPR) find_git_refs | tee channelserver_tags.jsonl | \
		$(FPR) cargo_metadata | tee channelserver_tags_metadata.jsonl | \
		$(FPR) rust_changelog | tee channelserver_changelog.jsonl

check-rust-changelog:
	test -f channelserver_tags.jsonl
	diff channelserver_tags.jsonl tests/fixtures/channelserver_tags.jsonl
	test -f channelserver_tags_metadata.jsonl
	test -f channelserver_changelog.jsonl

rust-changelog-from-diff:
	printf "{\"org\": \"mozilla-services\", \"repo\": \"syncstorage-rs\", \"ref\": {\"value\": \"master\", \"kind\": \"branch\"}, \"repo_url\": \"https://github.com/mozilla-services/syncstorage-rs.git\"}\n{\"org\": \"mozilla-services\", \"repo\": \"syncstorage-rs\", \"ref\": {\"value\": \"5a3e3967e90d65ca0d7a17b0466a3385898c3b6b\", \"kind\": \"commit\"}, \"repo_url\": \"https://github.com/mozilla-services/syncstorage-rs.git\"}\n" | \
	    $(FPR) cargo_metadata | \
	    $(FPR) rust_changelog

install:
	bash ./bin/install.sh

install-dev:
	DEV=1 bash ./bin/install.sh

format:
	$(IN_VENV) black fpr/*.py fpr/**/*.py tests/**/*.py

type-check:
	$(IN_VENV) mypy fpr/

style-check:
	$(IN_VENV) pytest -v -o codestyle_max_line_length=120 --codestyle fpr/ tests/

shellcheck:
	shellcheck -s bash -x bin/*.sh

test:
	$(IN_VENV) pytest -vv --cov-branch --cov=fpr/ fpr/ tests/

unit-test: format style-check test type-check shellcheck

test-clear-cache:
	$(IN_VENV)  pytest --cache-clear -vv --cov-branch --cov=fpr/ fpr/ tests/

coverage: test
	$(IN_VENV) coverage html
	$(IN_VENV) python -m webbrowser htmlcov/index.html

clean:
	rm -rf htmlcov/ fpr-debug.log fpr-graph.png fpr-graph.svg output.dot
	docker stop $(shell docker ps -f "name=dep-obs-" -f "status=running" --format "{{.ID}}") || true
	docker container prune -f

run-fetch-package-data-and-save:
	printf '{"name":"123done"}\n{"name":"abab"}\n{"name":"abatar"}' | $(FPR) fetch_package_data --dry-run fetch_npmsio_scores
	printf '{"name":"123done"}\n{"name":"abab"}\n{"name":"abatar"}' | $(FPR) fetch_package_data fetch_npmsio_scores -o output.jsonl
	printf '{"name":"123done"}\n{"name":"abab"}\n{"name":"abatar"}' | $(FPR) fetch_package_data --dry-run fetch_npm_registry_metadata
	printf '{"name":"123done"}\n{"name":"abab"}\n{"name":"abatar"}' | $(FPR) fetch_package_data fetch_npm_registry_metadata -o output.jsonl

run-repo-tasks-and-save:
	printf '{"repo_url": "https://github.com/mozilla/fxa", "org": "mozilla", "repo": "fxa", "ref": {"value": "v1.153.0", "kind": "tag"},"versions": {"ripgrep": "ripgrep 11.0.2 (rev 3de31f7527)"},"dependency_file": {"path": "package.json", "sha256": "5a371f12ccff8f0f8b6e5f4c9354b672859f10b4af64469ed379d1b35f1ea584"}}\n{"repo_url": "https://github.com/mozilla/fxa", "org": "mozilla", "repo": "fxa", "ref": {"value": "v1.153.0", "kind": "tag"},"versions":{"ripgrep":"ripgrep 11.0.2 (rev 3de31f7527)"}, "dependency_file": {"path": "package-lock.json", "sha256": "665f4d2481d902fc36faffaab35915133a53f78ea59308360e96fb4c31f8b879"}}' \
		| $(FPR) run_repo_tasks --docker-pull --docker-build --repo-task install --repo-task list_metadata --repo-task audit  --keep-volumes --dir './'  -o output.jsonl

run-crate-graph:
	$(FPR) -q crate_graph -i tests/fixtures/cargo_metadata_serialized.json | jq -r '.crate_graph_pdot' | dot -Tsvg > fpr-graph.svg
	$(IN_VENV) python -m webbrowser fpr-graph.svg

start-db:
	docker run --name dep-obs-postgres -p 5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_USER=postgres -e POSTGRES_DB=dependency_observatory -d postgres:12

stop-db:
	docker stop dep-obs-postgres

clean-db:
	docker rm -f dep-obs-postgres

db-shell:
	PGPASSWORD=postgres psql -U postgres -h localhost -p 5432 dependency_observatory

dump-db:
	mkdir -p "dep_obs_dump_$(shell date --utc +%F)/"
	PGPASSWORD=postgres pg_dump -j $(shell nproc --all) -U postgres -h localhost -p 5432 -Fd dependency_observatory -f "dep_obs_dump_$(shell date --utc +%F)/"

run-save-to-db:
	cat 00_repo_url.json | $(FPR) save_to_db --create-tables

run-crate-graph-and-save:
	$(FPR) crate_graph -i tests/fixtures/cargo_metadata_serialized.json -o crate_graph.jsonl --dot-filename default.dot
	$(FPR) crate_graph -i tests/fixtures/cargo_metadata_serialized.json -a crate_graph.jsonl -o /dev/null --node-key name --node-label name_authors --filter dpc --filter serde --dot-filename serde_authors_filtered.dot
	$(FPR) crate_graph -i tests/fixtures/cargo_metadata_serialized.json -a crate_graph.jsonl -o /dev/null --node-key name --node-label name_authors --style 'dpc:color:red' --style 'serde:shape:box' --dot-filename graph-with-style-args.dot
	$(FPR) crate_graph -i tests/fixtures/cargo_metadata_serialized.json -a crate_graph.jsonl -o /dev/null --node-key name_version --node-label name_version_repository -g 'repository' --dot-filename groupby-repo.dot
	$(FPR) crate_graph -i tests/fixtures/cargo_metadata_serialized.json -a crate_graph.jsonl -o /dev/null --node-key name_version --node-label name_authors -g 'author' --dot-filename groupby-author.dot
	$(FPR) crate_graph -i tests/fixtures/cargo_metadata_serialized.json -a crate_graph.jsonl -o /dev/null --node-key name_version --node-label name_readme --dot-filename readme-node-label.dot
	$(FPR) crate_graph -i tests/fixtures/cargo_metadata_serialized.json -a crate_graph.jsonl -o /dev/null --node-key name_version --node-label name_repository --dot-filename repo-node-label.dot
	$(FPR) crate_graph -i tests/fixtures/cargo_metadata_serialized.json -a crate_graph.jsonl -o /dev/null --node-key name_version --node-label name_package_source --dot-filename source-node-label.dot
	$(FPR) crate_graph -i tests/fixtures/cargo_metadata_serialized.json -a crate_graph.jsonl -o /dev/null --node-key name_version --node-label name_metadata --dot-filename metadata-node-label.dot
	./bin/write_dotfiles.sh < crate_graph.jsonl

show-dot:
	dot -O -Tsvg *.dot
	./bin/open_svgs.sh

clean-graph:
	rm -f *.dot *.svg crate_graph.jsonl

run-cargo-audit:
	$(FPR) cargo_audit -i tests/fixtures/mozilla_services_channelserver_branch.jsonl
	$(FPR) cargo_audit -i tests/fixtures/mozilla_services_channelserver_tag.jsonl
	$(FPR) cargo_audit -i tests/fixtures/mozilla_services_channelserver_commit.jsonl

run-cargo-audit-and-save:
	$(FPR) cargo_audit -i tests/fixtures/mozilla_services_channelserver_branch.jsonl -o output.jsonl

run-cargo-metadata:
	$(FPR) cargo_metadata -i tests/fixtures/mozilla_services_channelserver_branch.jsonl

run-cargo-metadata-and-save:
	$(FPR) cargo_metadata -i tests/fixtures/mozilla_services_channelserver_branch.jsonl -o output.jsonl

run-github-metadata-and-save:
	printf "{\"repo_url\": \"https://github.com/mozilla/extension-workshop.git\"}" | $(FPR) github_metadata -i - -o output.jsonl --github-query-type=REPO_DEP_MANIFESTS --github-repo-dep-manifests-page-size=1 --github-query-type=REPO_DEP_MANIFEST_DEPS --github-repo-dep-manifest-deps-page-size=50 --github-query-type=REPO_VULN_ALERTS --github-repo-vuln-alerts-page-size=1 --github-query-type=REPO_VULN_ALERT_VULNS --github-repo-vuln-alert-vulns-page-size=1 --github-query-type=REPO_LANGS --github-repo-langs-page-size=50

run-cargo-metadata-fxa-and-save:
	$(FPR) cargo_metadata -i tests/fixtures/mozilla_services_fxa_branch.jsonl -o output.jsonl

run-rust-changelog:
	$(FPR) rust_changelog -i tests/fixtures/channelserver_tags_metadata.jsonl

run-rust-changelog-and-save:
	$(FPR) rust_changelog -i tests/fixtures/channelserver_tags_metadata.jsonl -o output.jsonl

# NB: assuming package names don't include spaces
update-requirements:
	bash ./bin/update_requirements.sh

dump-test-fixture-pickle-files:
	$(IN_VENV) python -m pickle tests/fixtures/*.pickle

venv-shell:
	$(IN_VENV) bash

.PHONY: build-image dump-test-fixture-pickle-files coverage format type-check style-check test test-clear-cache clean install install-dev-tools run-crate-graph run-crate-graph-and-save run-cargo-audit run-cargo-audit-and-save run-cargo-metadata run-cargo-metadata-and-save run-github-metadata-and-save update-requirements show-dot unit-test
