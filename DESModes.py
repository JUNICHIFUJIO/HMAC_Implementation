# Section for allowing import of custom classes
import sys
import os

if sys.path[0] != os.path.dirname(os.path.realpath(sys.argv[0])):
    sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

######################################
#            IMPORTS
######################################
from enum import Enum

######################################
#            CLASS START
######################################
# An enumerator to handle the possible modes covered for this homework
# assignment.
class DESModes(Enum):
    ######################################
    #            CLASS FIELDS
    ######################################
    electronicCodebook = 1
    cipherBlockChain = 2
    counter = 3
    
    ######################################
    #            STATIC METHODS
    ######################################
    # Static method that parses a string passed in representing the encryption mode desired.
    # Returns a DESModes enumerator identifier.
    @staticmethod
    def GetEncryptionMode(mode_string):
        if mode_string.upper() == "CBC" or mode_string.lower() == "cipherblockchain" or mode_string.lower() == "cipher block chain":
            return DESModes.cipherBlockChain
        elif mode_string.upper() == "CTR" or mode_string.lower() == "counter":
            return DESModes.counter
        elif mode_string.upper() == "ECB" or mode_string.lower() == "electroniccodebook" or mode_string.lower() == "electronic codebook":
            return DESModes.electronicCodebook
        else:
            print(mode_string)
            raise ValueError("Inappropriate mode selected. Please choose between ECB, CBC, or CTR.")
        
######################################
#               MAIN
######################################
if __name__ == "__main__":
    print("Running Main for DESModes module.")
    print("DESModes' encryption codebook value:")
    print(DESModes.electronicCodebook)
    print(DESModes.electronicCodebook.value)
    print("DESModes' cipher block chain value:")
    print(DESModes.cipherBlockChain)
    print(DESModes.cipherBlockChain.value)
    print("DESModes' counter value:")
    print(DESModes.counter)
    print(DESModes.counter.value)
    print()
    print("Testing GetEncryptionMode")
    print("CBC returns...")
    print(DESModes.GetEncryptionMode("CBC"))
    print("ctr returns...")
    print(DESModes.GetEncryptionMode("ctr"))
    print("electronic codebook returns...")
    print(DESModes.GetEncryptionMode("electronic codebook"))
    try:
        print("IncorrectValue returns...")
        print(DESModes.GetEncryptionMode("IncorrectValue"))
    except ValueError:
        print("(A value error was raised)")
