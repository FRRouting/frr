<<<<<<< HEAD
#!/usr/bin/env python2
=======
#!/usr/bin/env python3
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
"Helper script to read api commands from a pipe and feed them to ExaBGP"

import sys

if len(sys.argv) != 2:
    sys.exit(1)
fifo = sys.argv[1]

while True:
    pipe = open(fifo, "r")
    with pipe:
        line = pipe.readline().strip()
        if line != "":
            sys.stdout.write("{}\n".format(line))
            sys.stdout.flush()
        pipe.close()

sys.exit(0)
