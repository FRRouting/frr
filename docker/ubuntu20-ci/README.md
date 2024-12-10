# Ubuntu 20.04

This builds an ubuntu 20.04 container for dev / test

# Build

```
<<<<<<< HEAD
docker build -t frr-ubuntu20:latest  -f docker/ubuntu20-ci/Dockerfile .
=======
docker build -t frr-ubuntu20:latest --build-arg=UBUNTU_VERSION=20.04 -f docker/ubuntu-ci/Dockerfile .
```

# Running Full Topotest

```
docker run --init -it --privileged --name frr-ubuntu20 -v /lib/modules:/lib/modules frr-ubuntu20:latest bash -c 'cd ~/frr/tests/topotests ; sudo pytest -nauto --dist=loadfile'
```

# Extract results from the above run into `run-results` dir and analyze

```
tests/topotests/analyze.py -C frr-ubuntu20 -Ar run-results
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
```

# Running

```
<<<<<<< HEAD
docker run -d --privileged --name frr-ubuntu20 --mount type=bind,source=/lib/modules,target=/lib/modules frr-ubuntu20:latest
=======
docker run -d --init --privileged --name frr-ubuntu20 --mount type=bind,source=/lib/modules,target=/lib/modules frr-ubuntu20:latest
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
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
<<<<<<< HEAD
docker exec frr-ubuntu20 bash -c 'cd ~/frr/tests/topotests/ospf-topo1 ; sudo pytest test_ospf_topo1.py'
=======
docker exec frr-ubuntu20 bash -c 'cd ~/frr/tests/topotests/ospf_topo1 ; sudo pytest test_ospf_topo1.py'
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
```

# stop & remove container

```
<<<<<<< HEAD
docker stop frr-ubuntu20 ; docker rm frr-ubuntu18
=======
docker stop frr-ubuntu20 ; docker rm frr-ubuntu20
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
```

# remove image

```
docker rmi frr-ubuntu20:latest
```
