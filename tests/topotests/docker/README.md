# Topotests in Docker

## Quickstart

If you have Docker installed, you can run the topotests in Docker.
The easiest way to do this, is to use the make targets from this
repository.

Your current user needs to have access to the Docker daemon. Alternatively
you can run these commands as root.

```console
make topotests
```

This command will pull the most recent topotests image from dockerhub, compile FRR inside
of it, and run the topotests.

## Advanced Usage

Internally, the topotests make target uses a shell script to pull the image and spawn the docker
container.

There are several environment variables which can be used to modify the behavior
of the script, these can be listed by calling it with `-h`:

```console
./tests/topotests/docker/frr-topotests.sh -h
```

For example, a volume is used to cache build artifacts between multiple runs
of the image. If you need to force a complete recompile, you can set `TOPOTEST_CLEAN`:

```console
TOPOTEST_CLEAN=1 ./tests/topotests/docker/frr-topotests.sh
```

By default, `frr-topotests.sh` will build frr and run pytest. If you append
arguments and the first one starts with `/` or `./`, they will replace the call to
pytest. If the appended arguments do not match this patttern, they will be provided to
pytest as arguments.

So, to run a specific test with more verbose logging:

```console
./tests/topotests/docker/frr-topotests.sh -vv -s all-protocol-startup/test_all_protocol_startup.py
```

And to compile FRR but drop into a shell instead of running pytest:

```console
./tests/topotests/docker/frr-topotests.sh /bin/bash
```

## Development

The docker image just includes all the components to run the topotests, but not the topotests
themselves. So if you just want to write tests and don't want to make changes to the environment
provided by the docker image. You don't need to build your own docker image if you do not want to.

When developing new tests, there is one caveat though: The startup script of the container will
run a `git-clean` on its copy of the FRR tree to avoid any pollution of the container with build
artefacts from the host. This will also result in your newly written tests being unavailable in the
container unless at least added to the index with `git-add`.

If you do want to test changes to the docker image, you can locally build the image and run the tests
without pulling from the registry using the following commands:

```console
make topotests-build
TOPOTEST_PULL=0 make topotests
```
