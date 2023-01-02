from lib.lutil import luCommand, luLast

rtrs = ["ce1", "ce2", "ce3", "r1", "r2", "r3", "r4"]
for rtr in rtrs:
    ret = luCommand(
        rtr,
        'vtysh -c "show bgp neigh"',
        "Notification received .([A-Za-z0-9/ ]*)",
        "none",
        "collect neighbor stats",
    )
    found = luLast()
    if ret != False and found != None:
        val = found.group(1)
        ret = luCommand(
            rtr,
            'vtysh -c "show bgp neigh"',
            "Notification received",
            "fail",
            "Notify RXed! {}".format(val),
        )
# done
