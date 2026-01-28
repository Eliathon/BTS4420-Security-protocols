#Endret til å passe kravene til Sikkerhetsprotokller oblig 1C

from SUCI_util import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import socket # Tidligere importerte vi ikke socket, HOME leste SUCI direkte fra fil.
import sys

PRIVPW   = bytes("BTS4410 Høsten 2025","utf-8")

cmd = cmd_arg([CMD_KEYGEN,CMD_DECONCEAL])

if cmd is None:
    err_print("\nNo valid command given.")
    sys.exit(1)

if cmd==CMD_KEYGEN:
    print("\nHome: Generating long-term ECDH key-pair.")
    private_key, public_key = gen_ECDH_key_pair(ec.SECP256R1())
    
    print("    Key-pair generated.")
    
    len_priv_pem = len(store_private_key(private_key, PRIV_PEM, PRIVPW))
    print("    Private key stored in pem-file. Filesize:",len_priv_pem)
    
    len_pub_pem = len(store_public_key(public_key, PUB_PEM))
    print("    Public key stored in pem-file.  Filesize:", len_pub_pem)
    
    print("Home: Command completed.")
    sys.exit(0)

if cmd == CMD_DECONCEAL:
    print("\nHome: Deconceal command given.")
    print(f"    Binding UDP socket on {HOME_ADDR} with timeout {SOCK_TIMEOUT}s")

    # UDP socket for å motta SUCI fra User
    hsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    hsock.settimeout(SOCK_TIMEOUT)
    hsock.bind(HOME_ADDR)

    # En eggen socket for å sende svar (ACK) tilbake
    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        print("    Waiting for SUCI datagram ...", flush=True)
        raw_suci_data, user_addr = hsock.recvfrom(DGRAM_BUFF)
    except TimeoutError:
        print("    No SUCI received within timeout. Giving up.")
        sys.exit(1)

    print(f"    Received SUCI datagram from {user_addr}, Length: {len(raw_suci_data)}")

    # skriver til fil for debugging / bakoverkompatibilitet
    with open(SUCI_FILE_NAME, "wb") as f:
        f.write(raw_suci_data)
    print(f"    SUCI_data written to file '{SUCI_FILE_NAME}' (for debugging).")

    #last privat nøkkel, derive session key, decrypt, parse IDer
    priv_key = load_private_key(PRIV_PEM, PRIVPW)
    print("    Loaded own private key. Size:", priv_key.key_size)

    IV_LEN, HOME_LEN = 16, 64
    off = 0

    iv = raw_suci_data[off:off + IV_LEN]
    off += IV_LEN
    home_blk = raw_suci_data[off:off + HOME_LEN]
    off += HOME_LEN

    pub_len = int.from_bytes(raw_suci_data[off:off + 2], "big")
    off += 2
    user_pub_pem = raw_suci_data[off:off + pub_len]
    off += pub_len
    ct = raw_suci_data[off:]

    eph_pub = serialization.load_pem_public_key(user_pub_pem)
    dhs = priv_key.exchange(ec.ECDH(), eph_pub)
    session_key = key_derivation(dhs)

    aad = iv + home_blk + (pub_len.to_bytes(2, "big") + user_pub_pem)

    aesgcm = AESGCM(session_key)
    user_id_blk = aesgcm.decrypt(iv, ct, aad)

    name_len = int.from_bytes(user_id_blk[0:2], "big")
    user_name = user_id_blk[2:2 + name_len].decode("utf-8")

    home_len = int.from_bytes(home_blk[0:2], "big")
    home_name = home_blk[2:2 + home_len].decode("utf-8")

    print(f"    Verified Home-ID: '{home_name}'")
    print(f"    Recovered User-ID: '{user_name}'")

    # Sender enkel ACK tilbake til User (for testing)
    ack = b"OK"
    try:
        usock.sendto(ack, user_addr)
        print(f"    Sent ACK to {user_addr}: {ack}")
    except OSError as e:
        print("    Failed to send ACK:", e)

    print("Home: Command completed.")
    sys.exit(0)

err_print("\nSomething went wrong:", cmd)
sys.exit(1)