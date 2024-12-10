# Ubuntu 22.04

This builds an ubuntu 22.04 container for dev / test

# Build

```
docker build -t frr-ubuntu22:latest -f docker/ubuntu-ci/Dockerfile .
```

<<<<<<< HEAD
# Running Full Topotest

```
docker run --init -it --privileged --name frr -v /lib/modules:/lib/modules frr-ubuntu22:latest bash -c 'cd ~/frr/tests/topotests ; sudo pytest -nauto --dist=loadfile'
=======
# Run

```
docker run -d --init --privileged --name frr-ubuntu22 --mount type=bind,source=/lib/modules,target=/lib/modules frr-ubuntu22:latest
```

# Running full topotest (container stops at end)

```
docker run --init -it --privileged --name frr-ubuntu22 \
    -v /lib/modules:/lib/modules frr-ubuntu22:latest \
    bash -c 'cd /home/frr/frr/tests/topotests; sudo pytest -nauto --dist=loadfile'
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
```

# Extract results from the above run into `run-results` dir and analyze

```
<<<<<<< HEAD
tests/topotest/analyze.py -C frr -Ar run-results
```

# Running

```
docker run -d --init --privileged --name frr --mount type=bind,source=/lib/modules,target=/lib/modules frr-ubuntu22:latest
=======
tests/topotests/analyze.py -C frr-ubuntu22 -Ar run-results
```

# Extract coverage from a stopped container into host FRR source tree

```
docker export frr-ubuntu22 | tar --strip=3 --wildcards -vx '*.gc??'
lcov -b $(pwd) --capture --directory . --output-file=coverage.info
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
```

# make check

```
<<<<<<< HEAD
docker exec frr bash -c 'cd ~/frr ; make check'
=======
docker exec frr-ubuntu22 bash -c 'cd ~/frr ; make check'
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
```

# interactive bash

```
<<<<<<< HEAD
docker exec -it frr bash
```

# topotest -- when Host O/S is Ubuntu only

```
docker exec frr bash -c 'cd ~/frr/tests/topotests/ospf-topo1 ; sudo pytest test_ospf_topo1.py'
=======
docker exec -it frr-ubuntu22 bash
```

# Run a specific topotest

```
docker exec frr-ubuntu22 bash -c 'cd ~/frr/tests/topotests ; sudo pytest ospf_topo1/test_ospf_topo1.py'
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
```

# stop & remove container

```
<<<<<<< HEAD
docker stop frr ; docker rm frr
=======
docker stop frr-ubuntu22 ; docker rm frr-ubuntu22
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
```

# remove image

```
docker rmi frr-ubuntu22:latest
```
