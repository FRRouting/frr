date > test_sockopt.log


gcc -o test_server test_server.c tcp_ao_config.c

gcc -o test_sockopt test_sockopt.c tcp_ao_config.c

if [ "$1" = "kill" ]; then
    echo "Killing process on port 12345" >> test_sockopt.log
    sudo kill -9 $(sudo lsof -t -i:12345)
fi