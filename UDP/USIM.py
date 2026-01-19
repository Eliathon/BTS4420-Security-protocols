"""
An extremely minimalistic USIM implementation.
"""
import socket
from common_def import *

hsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
usock.settimeout(SOCK_TIMEOUT)
usock.bind(USIM_ADDR)

MESSAGE = b"There was no specific message."


def sendto_home(msg: bytes) -> int:
    return hsock.sendto(msg, HOME_ADDR)


def recvfrom_home() -> bytes:
    try:
        data, addr = usock.recvfrom(DGRAM_BUFF)  
    except TimeoutError:
        data = bytes()
        
    # Normally, we should have checked 'addr'
    return data

    
if __name__ == "__main__":
    
    IMSI = b"IMSI_01"
    print("\nUSIM\n")
    print("Sending ID:",IMSI,flush=True)    
    sendto_home(IMSI)    
   
    data = recvfrom_home()
    if len(data)==0:
        print("No challenge received.")
    else:
        print("Received challenge:",data)
   
    print("Done.")
