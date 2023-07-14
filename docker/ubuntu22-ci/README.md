# Ubuntu 22.04

This builds an ubuntu 22.04 container for dev / test

# Build

```
docker build -t frr-ubuntu22:latest -f docker/ubuntu-ci/Dockerfile .
```

# Running Full Topotest

```
docker run --init -it --privileged --name frr -v /lib/modules:/lib/modules frr-ubuntu22:latest bash -c 'cd ~/frr/tests/topotests ; sudo pytest -nauto --dist=loadfile'
```

# Extract results from the above run into `run-results` dir and analyze

```
tests/topotest/analyze.py -C frr -Ar run-results
```

# Running

```
docker run -d --init --privileged --name frr --mount type=bind,source=/lib/modules,target=/lib/modules frr-ubuntu22:latest
```

# make check

```
docker exec frr bash -c 'cd ~/frr ; make check'
```

# interactive bash

```
docker exec -it frr bash
```

# topotest -- when Host O/S is Ubuntu only

```
docker exec frr bash -c 'cd ~/frr/tests/topotests/ospf-topo1 ; sudo pytest test_ospf_topo1.py'
```

# stop & remove container

```
docker stop frr ; docker rm frr
```

# remove image

```
docker rmi frr-ubuntu22:latest
```
