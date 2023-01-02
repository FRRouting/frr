# Ubuntu 18.04

This builds an ubuntu 18.04 container for dev / test

# Build

```
docker build -t frr-ubuntu18:latest  -f docker/ubuntu18-ci/Dockerfile .
```

# Running

```
docker run -d --privileged --name frr-ubuntu18 --mount type=bind,source=/lib/modules,target=/lib/modules frr-ubuntu18:latest
```

# make check

```
docker exec frr-ubuntu18 bash -c 'cd ~/frr ; make check'
```

# interactive bash
```
docker exec -it frr-ubuntu18 bash
```

# topotest -- when Host O/S is Ubuntu only

```
docker exec frr-ubuntu18 bash -c 'cd ~/frr/tests/topotests/ospf-topo1 ; sudo pytest test_ospf_topo1.py'
```

# stop & remove container

```
docker stop frr-ubuntu18 ; docker rm frr-ubuntu18
```

# remove image

```
docker rmi frr-ubuntu18:latest
```
