## find-package-rugaru

Scripts for finding suspicious werewolf / rugaru / rougarou-like malware open source packages.

### Usage

#### Requirements




### How does this differ from other tools?

* language agnostic
* sandboxed

### Directions

1. clone this repo (while in development we won't publish)

```console
git clone https://github.com/mozilla-services/find-package-rugaru.git

```

2. Inspect a container:

```console

```

3. Optionally, we can containerize a repo first from a base image to inspect:


```console

```

####

* base docker images names for testing repos (Python, JS, etc.). These should be official or trusted (in the "I wrote this or trust the authors not ) docker images

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
