"""
This is a very simple model of UMTS-AKA.

In our scheme, this program plays the part of the home network (H).
The user is played by interactive input from the user (U,you).
"""
from enum import Enum, auto
import string
import secrets

uid_space = string.ascii_uppercase

# We define State to contain the HOME states.
class State(Enum):
    INIT = auto()
    READY_FOR_ID = auto()
    SEND_CHALLENGE = auto()
    WAIT_FOR_RESPONSE = auto()
    SEND_GUTI = auto()
    AUTH_ERROR = auto()
    ERROR = auto()
    DONE = auto()


def at(s): print("\n@"+s.name)
def get_AUTN(RAND,K: int) -> int: return(RAND+K+1)
def res_ok(RES,RAND,K: int) -> bool: return(RES == RAND+K)
    

def Home():
    state = State.INIT
    
    while True:
        if  state == State.INIT:
            at(state)
            
            K = secrets.randbelow(100)
            aid = secrets.choice(uid_space) + secrets.choice(uid_space)
            print("A simpliedfied UMTS-AKA inspired challenge-response.")
            print("\tThe challenge: RAND,AUTN; Two integers.")
            print("\tThe challenge is valid if AUTN == K+RAND+1.")
            print("\tThe response RES is to be: RES == RAND+K\n")

            print("\tPre-shared secret K:",K)
            print("\tAssigned identifier:",aid)
                        
            state = State.READY_FOR_ID
            
        elif state == State.READY_FOR_ID:
            at(state)
            print("\tIdentity Presentation.The only valid answer is the assigned identifier.")
            uid = input("\tAssigned ID: ").upper()
            if uid==aid:  
                print("\tAccepted user identifier:",uid)
                state = state.SEND_CHALLENGE
            else:
                print("\nNo valid user identifer entered.")
                state = state.ERROR
            
        elif  state == State.SEND_CHALLENGE:
            at(state)
            
            RAND = secrets.randbelow(100)
            AUTN = get_AUTN(RAND,K)
            
            print("\tThe challenge (RAND,AUTN):",RAND,AUTN,"  Hint: RES is AUTN-1.")
            state = State.WAIT_FOR_RESPONSE
            
        elif  state == State.WAIT_FOR_RESPONSE:
            at(state)
            print("\tIf the (RAND,AUTN) pair was valid, answer the challenge with RES.")
            print("\tIf the pair was *invalid* answer with a '0'.")
            
            try:
                RES = int(input("\tRES: "))
            except ValueError:
                print("Invalid input.")
                RES = 0
                
            if RES == 0:
                print("\tThe challenge was not accepted.")
                state = state.ERROR
            else:
                if res_ok(RES,RAND,K):
                    print("\tThe response was accepted. :-)")
                    state = State.SEND_GUTI
                else:
                    print("\nThe response was NOT accepted.")
                    state = State.AUTH_ERROR
                                
        elif  state == State.SEND_GUTI:
            at(state)
            print("\tSending GUTI in encrypted form (what we should have done).")
            state = State.DONE
            
        elif  state == State.ERROR:
            at(state)
            print("Too bad. Giving up.")
            state = State.DONE
            
        elif state == State.AUTH_ERROR:
            at(state)
            print("AUTHENTICATION ERROR. Giving up :-(")
            state = State.DONE
            
        elif state == State.DONE:
            at(state)
            print("Done.")
            break
        
        else:
            print("\nExtremely bad. Should have been unreachable...")
            break

if __name__ == "__main__":
    Home()