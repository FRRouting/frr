# Ubuntu 20.04

This builds an ubuntu 20.04 container for dev / test

# Build

```
docker build -t frr-ubuntu20:latest --build-arg=UBUNTU_VERSION=20.04 -f docker/ubuntu-ci/Dockerfile .
```

# Running Full Topotest

```
docker run --init -it --privileged --name frr-ubuntu20 -v /lib/modules:/lib/modules frr-ubuntu20:latest bash -c 'cd ~/frr/tests/topotests ; sudo pytest -nauto --dist=loadfile'
```

# Extract results from the above run into `run-results` dir and analyze

```
tests/topotests/analyze.py -C frr-ubuntu20 -Ar run-results
```

# Running

```
docker run -d --init --privileged --name frr-ubuntu20 --mount type=bind,source=/lib/modules,target=/lib/modules frr-ubuntu20:latest
```

# make check

```
docker exec frr-ubuntu20 bash -c 'cd ~/frr ; make check'
```

# interactive bash

```
docker exec -it frr-ubuntu20 bash
```

# topotest -- when Host O/S is Ubuntu only

```
docker exec frr-ubuntu20 bash -c 'cd ~/frr/tests/topotests/ospf_topo1 ; sudo pytest test_ospf_topo1.py'
```

# stop & remove container

```
docker stop frr-ubuntu20 ; docker rm frr-ubuntu20
```

# remove image

```
docker rmi frr-ubuntu20:latest
```
