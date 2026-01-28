import os
import socket
from SUCI_util import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
import sys

# ENTITY_NAME_USER = "privacy-sensitive-name ÆØÅ"
ENTITY_NAME_USER = "halla balla"

cmd = cmd_arg([CMD_CONCEAL])

if cmd is None:
    err_print("\nNo valid command given.")
    sys.exit(1)

if cmd == CMD_CONCEAL:
    print("\nUser: Concealing a permanent identifier.")

    # UDP-sockets: én for sending til Home, én for å motta ACK
    hsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # sender
    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # lytter på USER_ADDR
    usock.settimeout(SOCK_TIMEOUT)
    usock.bind(USER_ADDR)

    # laster inn Home Public key.
    home_pub_key = load_public_key(PUB_PEM)

    # genererer ephemeral key-pair
    ephemeral_private_key, ephemeral_public_key = gen_ECDH_key_pair(ec.SECP256R1())

    # genererer shared key
    dhs = ephemeral_private_key.exchange(ec.ECDH(), home_pub_key)

    # genererer session key.
    session_key = key_derivation(dhs)

    # Legger til lengde indikator og padding
    # note: Bør sjekke at entity navn har lengdew <= 62
    utf8_home_ID = bytes(ENTITY_NAME_HOME, "utf-8")
    utf8_user_ID = bytes(ENTITY_NAME_USER, "utf-8")
    home_ID = add_padding(add_len_prefix(utf8_home_ID), 64)
    user_ID = add_padding(add_len_prefix(utf8_user_ID), 64)
    print("    Entity name home: '" + str(utf8_home_ID, "utf-8") + "'")
    print("    Entity name user: '" + str(utf8_user_ID, "utf-8") + "'")

    # serialization av ephemeral public key (med prefix for lengde)
    user_serialized_pub_key = add_len_prefix(serialize_pub_key(ephemeral_public_key))

    # bruker AEAD for å encrypte/beskytte  "SUCI" informasjonen.
    aesgcm = AESGCM(session_key)
    IV = os.urandom(16)
    aad = IV + home_ID + user_serialized_pub_key
    ct = aesgcm.encrypt(IV, user_ID, aad)

    SUCI_data = IV + home_ID + user_serialized_pub_key + ct

    # skriv til fil for å kunne sammenligne med tidligere løsning
    with open(SUCI_FILE_NAME, "wb") as suci_file:
        suci_file.write(SUCI_data)
    print("    SUCI_data written to file (debug). Len:", len(SUCI_data))

    # SEND SUCI OVER UDP TIL HOME
    print(f"    Sending SUCI_data ({len(SUCI_data)} bytes) to HOME at {HOME_ADDR}")
    hsock.sendto(SUCI_data, HOME_ADDR)

    ############## Vent på ACK fra Home (kan fjernes, men for testing) ################
    try:
        ack, addr = usock.recvfrom(DGRAM_BUFF)
        if ack == b"OK":
            print(f"    Received ACK from HOME at {addr}: {ack}")
        else:
            print(f"    Received unexpected response from {addr}: {ack}")
    except TimeoutError:
        print("    No ACK received from HOME (timeout).")

    print("User: Command completed.")
    sys.exit(0)

err_print("\nSomething went wrong:", cmd)
sys.exit(1)