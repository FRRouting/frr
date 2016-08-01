#!/usr/bin/expect

# takes a list of command format strings
# and feeds them to the test grammar
# parser

set f [open [lindex $argv 0]]
set cmds [split [read $f] "\n"]
close $f

spawn vtysh

foreach command $cmds {
    expect {
        "dell-s6000-16#" {
            send "grammar parse $command\r"
        }
        "Grammar error" {
            send_user "$command"
            send "exit\r"
            exit
        }
    }
}

interact
