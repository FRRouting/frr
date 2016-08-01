#!/bin/expect

set f [open "copt.txt"]
set cmds [split [read $f] "\n"]
close $f

spawn vtysh

foreach command $cmds {
    expect "dell-s6000-16#"
    send "$command\r"
}

interact
