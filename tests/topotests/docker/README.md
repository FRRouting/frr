# Topotests in Docker

## Usage

If you have Docker installed, you can run the topotests in Docker.
The easiest way to do this, is to use the `frr-topotests.sh` script
from this repository:

```console
wget -O /usr/local/bin/frr-topotests \
    https://raw.githubusercontent.com/frrouting/topotests/master/docker/frr-topotests.sh
chmod +x /usr/local/bin/frr-topotests
```

Once this script is in place, simply run it while you are inside your FRR repository:

```
frr-topotests
```

It should build FRR inside of the container and run the topotests on it.
