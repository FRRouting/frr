# Topotests in Docker

This is folder contains auxiliary scripts to automate or help deploying
topology tests under Docker on a standardized Ubuntu environment.

Files description:

* _funcs.sh_: shared bash code
* _docker.sh_: builds docker image to run topotests
* _compile_frr.sh_: compile FRR sources (should be used by `topotests_run.sh`)
* _topotests_run.sh_: runs topotest image with the selected command

## Running Topotests in Docker

All you need to run topotests in Docker is:

* Have Docker installed (tested against docker-ce[1])
* Build the topotest images
* Have the FRR/Topotest sources cloned in your machine

Review and configure your sources folder in `topotests_run.sh`.

[1]: https://docs.docker.com/install/linux/docker-ce/ubuntu/
