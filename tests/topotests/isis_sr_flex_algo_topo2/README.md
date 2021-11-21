
## test

```
fdk-enter rt9.pid iperf3 -s
fdk-enter rt0.pid iperf3 -B 111.111.111.111 -c 222.222.222.222 -P20 -t 100000
fdk-enter rt0.pid watch -n0.1 ip -s link show
```
