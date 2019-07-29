## find-package-rugaru

Scripts for identifying suspicious open source packages and
dependencies that might be malware once in a blue moon like [the
legendary rugaru](https://en.wikipedia.org/wiki/Rougarou).

### Strategy

Our goal is to determine the behavior of known packages and find
predictors of suspicious packages. We break this down into three steps
for a repo or container image:

1. find dependency manifests and lockfiles (e.g. `package-lock.json`, `requirements.txt`, `Cargo.toml`, `go.mod`)
2. resolve dependent packages using different install options (e.g. `--prod`, `--ignore-scripts`)
3. fetch additional metadata about each dependency

env?, repo, commit, image, package manager, command

### Usage


### Repo layout

* `./bin/` scripts to run other scripts
* `./container_bin/` scripts that get mounted in `/tmp/bin/`

#### Files

* `./bin/base_image_config.json`
* `./bin/base_image_config.json.lock` hashes

These scripts generally assume the containers follow [dockerflow](https://github.com/mozilla-services/Dockerflow) i.e.

* app source is in `/app`
* `/app/version.json` exists and includes repo, version, and CI build info


### Design choices

* failures should be isolated
  * to each repo, dep. file, etc. + downstream jobs
  * errors should be caught (and wehere applicable retried w/ delay or rate limiting) and retried where applicable
* workload is IO heavy and (for now) small data so Beam, Spark, etc. and other Big Data tools not applicable
* however, we want to be able to save, restore, retry, and replay from checkpoints (i.e. not have to run a full task graph again and be able to test against fixtures)
* apply a flexible pipeline of analysers to specific org,repo,dep-file,dep paths

For this reason we're trying RxPy since it gives access to combinators with async support (without relying on a pure generator pipeline).
