# Debian9 Docker
This is a binary docker container build of debian9.

# Build
```
docker build --rm -t frr:6.0.2 .
```

# Running
```
docker run -itd --privileged --name frr frr:latest
```

vtysh
```
docker exec -it frr vtysh
```
