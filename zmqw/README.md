# zmqw/libzmqw
Subscribe to hooks in agents to provide json based zmq output

# description
The zmq writer module subscripts to hooks provided in, currently the pimd module, to allow for notifications when igmp group join and leave events occur.  Messages are published into a zmq queue running on a port specified at startup time on the command line.

# command line
pimd --log=stdout --log-level=debug -M libfrrzmqw.so:"port=17171"

