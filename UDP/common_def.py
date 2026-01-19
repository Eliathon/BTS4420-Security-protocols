UDP_IP = "127.0.0.1"        # We *only* use internal datagram exchange (this is "localhost")
HOME_UDP_PORT = 5005        # The exact port's can be changed. But: only to ephemeral ones. 
USIM_UDP_PORT = 5006
SOCK_TIMEOUT  = 5           # Socket timeout in seconds. May be changed (if needed).
DGRAM_BUFF    = 1024        # The max.size of a single datagram. 

USIM_ADDR = (UDP_IP, USIM_UDP_PORT)
HOME_ADDR = (UDP_IP, HOME_UDP_PORT)