# Debian 10 Docker

This is a binary docker container build of Debian 10 (buster) with FRR.

# Build

```
docker build -t frr-debian:latest .
```

# Running

```
docker run -itd --privileged --name frr frr-debian:latest
```

vtysh
```
docker exec -it frr vtysh
```
