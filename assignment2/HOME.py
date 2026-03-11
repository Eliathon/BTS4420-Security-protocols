"""
HOME side of DEMO-AKA

Implements the HOME network side of the DAMO-AKA protocol.
HOME waits for a USIM to identify itself, challenges it using milenage-derives
credentials, verifies the response, and assigns a temporary identity (TMSI)

That is, we have also included:
    - the basic AESGCM encryption/decryption.
    - load the TS 35.208 conformance test sets
"""
import socket
import secrets
from enum import auto
from demo_aka_util import *
from demo_aka_cipher import AEAD_encrypt, AEAD_decrypt
from conformance_test_data import TestData, b2a
from milenage_aka import Milenage
from helpers import xor


# HOME listens for incoming messages on its onw port
# and sends outgoing messages to USIM
hsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
hsock.settimeout(SOCK_TIMEOUT)
hsock.bind(LOCAL_HOME_ADDR)
usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def sendto_usim(msg: bytes) -> int:
    # Sends a UDP datagram to USIM
    return usock.sendto(msg, REMOTE_USIM_ADDR)


def recvfrom_usim() -> bytes:
    # Receive UDP datagram from USIM.
    # Returns empty bytes on timeout
    try:
        data, addr = hsock.recvfrom(DGRAM_BUFF)
    except TimeoutError:
        data = bytes()
        
    # Normally, we should have checked 'addr'
    return data


# Message syntax validators
# Each checks length, then the PID+MID header bytes.
# Returns (True, "Syntax OK") or (False, <reason>).
def verify_SendIdentity_syntax(data: bytes):
    if len(data) ==  0: return (False,"No message received.")
    if len(data) != 20: return (False,"Wrong message length: "+str(len(data))+" (expected lenght: 20)")
    if data[0:4] != MSG_SEND_ID: return (False,"The message was not a SendIdentity message.")
    return (True,"Syntax OK")


def verify_Response_syntax(data: bytes):
    if len(data) ==  0: return (False,"No message received.")
    if len(data) != 12: return (False,"Wrong message length: "+str(len(data))+" (expected lenght: 12)")
    if data[0:4] != MSG_RESPONSE: return (False,"The message was not a Response message.")
    return (True,"Syntax OK")


def verify_AssignTMSI_ack_syntax(data: bytes):
    if len(data) ==  0: return (False,"No message received.")
    if len(data) != 40: return (False,"Wrong message length: "+str(len(data))+" (expected lenght: 40)")
    if data[0:4] != MSG_ASSIGN_TMSI_ACK: return (False,"The message was not an AssignTMSI-ack message.")
    return (True,"Syntax OK")


# We define State to contain the HOME states.
class State(Enum):
    INIT = auto()
    WAIT_FOR_ID = auto()
    SEND_CHALLENGE = auto()
    WAIT_FOR_RES = auto()
    SEND_ASSIGN_TMSI = auto()
    WAIT_FOR_TMSI_ACK = auto()
    ERROR = auto()
    DONE = auto()


def run_HOME_state_machine() -> bool:
    """The glorious HOME state machine."""
    was_success = False
    usim_data = None
    state = State.INIT

    # Session variables
    IMSI = RAND = SQN = AMF = None
    MACA = RES = CK = IK = AK = None
    TMSI = None

    while True:
        #>>> INIT >>>
        if state == State.INIT:
            new_run()
            at(state)
            print("HOME starts by waiting for SendIdentity.")
            usim_data = TestData("HOME")
            state = State.WAIT_FOR_ID

        #>>> WAIT_FOR_ID >>>
        if state == State.WAIT_FOR_ID:
            at(state)
            data = recvfrom_usim()

            # our EXIT strategy :-)
            if data==TERMINATE_MESSAGE:
                print("\nTERMINATE message received. Goodbye.")
                break

            check = verify_SendIdentity_syntax(data)
            if check[0]:
                imsi = data[-1] # test-set index
                if (imsi>=1 and (imsi<=20)):
                    # valid IMSI
                    K,OPc, RAND, SQN, AMF = usim_data.get_data(imsi)
                    IMSI = bytearray(16)
                    IMSI[-1] = imsi
                    print("Received 'SendIdentity':")
                    print("  IMSI:",b2a(IMSI))
                    print()
                    print("  Retrieved associated data:")
                    print("  K:   ",b2a(K))
                    print("  OPc: ",b2a(OPc))
                    print("  RAND:",b2a(RAND))
                    print("  SQN: ",b2a(SQN))
                    print("  AMF: ",b2a(AMF))

                    # HOME knows SQN, so compute() is used, not compute_w_masked_sqn()
                    milenage = Milenage(K,OPc)
                    milenage.compute(RAND,SQN,AMF)
                    MACA = milenage.f1() # MAC-A: network authentication code
                    RES = milenage.f2() # RES: response from USIM
                    CK = milenage.f3() # CK: cipher key
                    IK = milenage.f4() # IK: integrity key
                    AK = milenage.f5() # AK: anonymity key
                    print_computed_values(MACA,RES,CK,IK,AK)
                    state = State.SEND_CHALLENGE
                else:
                    print("IMSI index out of range [1..20]:", imsi)
                    state = State.ERROR
            else:
                print(check[1])
                state = State.ERROR

        #>>> SEND_CHALLENGE >>>
        elif state == State.SEND_CHALLENGE:
            at(state)
            MSQN = xor(SQN,AK)
            AUTN = MSQN+AMF+MACA
            msg = MSG_CHALLENGE + RAND + AUTN
            print_challenge_data("Sending 'Challenge'",RAND,AUTN,MSQN,AMF,MACA)
            sendto_usim(msg)
            state = State.WAIT_FOR_RES

        #>>> WAIT_FOR_RES >>>
        elif state == State.WAIT_FOR_RES:
            at(state)
            data = recvfrom_usim()
            check = verify_Response_syntax(data)
            if check[0]:
                print("Received 'Response':")
                uRES = data[4:]
                print("RES:",b2a(uRES))

                if uRES != RES:
                    print("Too bad -- the response was *invalid*!!")
                    state = State.ERROR
                else:
                    print("The response was valid :-)")
                    state = State.SEND_ASSIGN_TMSI
            else:
                print(check[1])
                state = State.ERROR

        #>>> ASSIGN_TMSI >>>
        # Generate TMSI, encrypt it and send to USIM with a fresh nonce
        elif state == State.SEND_ASSIGN_TMSI:
            at(state)
            nonce = secrets.token_bytes(16)
            TMSI = bytearray(4)
            TMSI[-1] = IMSI[-1]
            ciphertext = AEAD_encrypt(CK+IK,nonce,TMSI,IMSI)
            msg = MSG_ASSIGN_TMSI + nonce + ciphertext
            print_assign_tmsi_data("Sending 'AssignTMSI':",CK+IK,nonce,ciphertext,IMSI,TMSI)
            sendto_usim(msg)
            state = State.WAIT_FOR_TMSI_ACK

        #>>> WAIT_FOR_TMSI_ACK >>>
        # Receive USIM acknowledgement, decrypt and verify that TSMI matches the one sent
        elif state == State.WAIT_FOR_TMSI_ACK:
            at(state)
            data = recvfrom_usim()
            check = verify_AssignTMSI_ack_syntax(data)
            if check[0]:
                nonce = data[4:20]
                ciphertext = data[20:]
                uTMSI = AEAD_decrypt(IK+CK,nonce,ciphertext,IMSI)
                print_assign_tmsi_data("Received 'AssignTMSI-ack':",IK+CK,nonce,ciphertext,IMSI,uTMSI)

                if bytes(uTMSI) == bytes(TMSI):
                    state = State.DONE
                else:
                    print("\nHOME received an in valid TMSI in AssignTMSI-ack. All is lost!")
                    state = State.ERROR
            else:
                print(check[1])
                state = State.ERROR

                #>>> DONE >>>
        elif state == State.DONE:
            at(state)
            print("\nDEMO-AKA sequence successfully completed on HOME side!")
            state = State.INIT
            was_success = True

        #>>> ERROR >>>
        elif state == State.ERROR:
            at(state)
            print("There was an DEMO-AKA error. Exiting.")
            was_success = False
            break
        else:
            #>>> FATAL ERROR >>>
            print("There was a fatal error. Exiting.")
            was_success = False

    return was_success


if __name__ == "__main__":
    print("\nHOME starting.")

    result = run_HOME_state_machine()

    if result:
        print("\nHOME done.")
    else:
        print("\nHOME exiting --- something went wrong!")