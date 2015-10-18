# Section for allowing import of custom classes
import sys
import os

if sys.path[0] != os.path.dirname(os.path.realpath(sys.argv[0])):
    sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

######################################
#            IMPORT
######################################
from MyBitArray import MyBitArray

######################################
#            CLASS START
######################################
# Records the information relevant to a Feistel round for the Data Encryption
# Standard block cipher
class FeistelRoundInfo:
    ######################################
    #            CONSTRUCTOR
    ######################################
    def __init__(self, round_number):
        self.RoundNumber = round_number
        self.DataInput = MyBitArray()
        self.DataOutput = MyBitArray()
        self.KeyLeft = MyBitArray()
        self.KeyRight = MyBitArray()

    ######################################
    #            METHODS
    ######################################
    # Sets the halves of the key based off of the passed in key.
    # Key is expected to be a bit array.
    def SetKeyHalves(self, key):
        halfwayPoint = int(len(key) / 2)
                
        self.KeyLeft = MyBitArray()
        try:
            self.KeyLeft.FromBits(key.bits[:halfwayPoint])
        except AttributeError:
            self.KeyLeft.FromBits(key[:halfwayPoint])

        self.KeyRight = MyBitArray()
        try:
            self.KeyRight.FromBits(key.bits[halfwayPoint:])
        except AttributeError:
            self.KeyRight.FromBits(key[halwayPoint:])

    # Rotates key halves by n_rotations. is_encryption determines
    # whether they are rotated left (encryption) or right (decryption).
    def RotateKeyHalves(self, n_rotations, is_encryption):
        if is_encryption == True:
            self.KeyLeft = self.KeyLeft.RotateLeft(n_rotations)
            self.KeyRight = self.KeyRight.RotateLeft(n_rotations)
        else:
            self.KeyLeft = self.KeyLeft.RotateRight(n_rotations)
            self.KeyRight = self.KeyRight.RotateRight(n_rotations)

######################################
#               MAIN
######################################
if __name__ == "__main__":
    print("Running Main for FeistelRoundInfo module.")
    roundInfo = FeistelRoundInfo(1)
    roundInfo.DataInput = MyBitArray()
    roundInfo.DataInput.FromBytes(bytes([128, 90, 6]))
    roundInfo.SetKeyHalves(roundInfo.DataInput)
    print(roundInfo.DataInput)
    print(roundInfo.KeyLeft)
    print(roundInfo.KeyRight)
    print("Testing RotateKeyHalves")
    roundInfo.RotateKeyHalves(2, True)
    print("Rotating encryption twice")
    print(roundInfo.KeyLeft)
    print(roundInfo.KeyRight)
    roundInfo.RotateKeyHalves(len(roundInfo.KeyLeft) - 1, False)
    print("Rotating decryption len(keyhalf) - 1 times")
    print(roundInfo.KeyLeft)
    print(roundInfo.KeyRight)
