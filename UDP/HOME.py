"""
An extremely minimalistic HOME implementation.
"""
import socket
from common_def import *

hsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
hsock.settimeout(SOCK_TIMEOUT)
hsock.bind(HOME_ADDR)
usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def sendto_usim(msg: bytes) -> int:
    return usock.sendto(msg, USIM_ADDR)


def recvfrom_usim() -> bytes:
    try:
        data, addr = hsock.recvfrom(DGRAM_BUFF)  
    except TimeoutError:
        data = bytes()
        
    # Normally, we should have checked 'addr'
    return data

    
if __name__ == "__main__":
    
    cnt = 0
    print("\nHOME\n")    
    while cnt<3:
        cnt += 1
        print("Waiting for ID ("+str(cnt)+").",flush=True)
   
        data = recvfrom_usim()
        if len(data)==0:
            print("No ID received.")
        else:
            print("Received ID: %s" % data)    
            challenge = b"(RAND,AUTH)"
            print("Sending challenge:",challenge)  
            sendto_usim(challenge)
            break
        
    if cnt>3 and len(data)==0:
        print("\nNo data received. Giving up.")
        
    print("Done.")
