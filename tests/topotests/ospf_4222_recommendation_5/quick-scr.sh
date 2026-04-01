!/usr/bin/env bash
sudo pytest test_ospf_broadcast_2router_constraint.py  -v
sudo chown ravi:ravi pcaps
sudo chown ravi:ravi ./pcaps/*
./pcap_lsu_dir_to_csv.sh ./pcaps
python ./analyse_ospf_lsacks_sorted.py -i ./pcaps --pattern 'r1-*.csv' -o ./pcaps/r1_converged_packet_flow_broadcast.csv
#python ./analyse_ospf_lsacks.py -i pcaps/r1-eth0-ospf4.csv -o ./pcaps/r1-eth0-ospf4-timing.csv
#python ./analyse_ospf_lsacks.py -i pcaps/r2-eth0-ospf4.csv -o ./pcaps/r2-eth0-ospf4-timing.csv
