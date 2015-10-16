# Section for allowing import of custom classes
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

# imports
from MyBitArray import MyBitArray

# Records the information relevant to a Feistel round for the Data Encryption
# Standard block cipher
class FeistelRoundInfo:
    ######################################
    #            CONSTRUCTOR
    ######################################
    def __init__(self, round_number):
        self.RoundNumber = round_number
        self.DataInput = 0
        self.DataOutput = 0
        self.KeyLeft = 0
        self.KeyRight = 0

    ######################################
    #            METHODS
    ######################################
    def SetKeyHalves(self, key):
        halfwayPoint = int(len(key) / 2)
                
        self.keyLeft = MyBitArray()
        self.keyLeft.FromBits(key.bits[:halfwayPoint])

        self.keyRight = MyBitArray()
        self.keyRight.FromBits(key.bits[halfwayPoint:])

    def RotateKeyHalves(self, n_rotations, is_encryption):
        if is_encryption == True:
            self.KeyLeft.RotateLeft(n_rotations)
            self.KeyRight.RotateLeft(n_rotations)
        else:
            self.KeyLeft.RotateRight(n_rotations)
            self.KeyRight.RotateRight(n_rotations)

    

# Main
if __name__ == "__main__":
    print("Running Main for FeistelRoundInfo module.")
    roundInfo = FeistelRoundInfo(1)
    roundInfo.dataInput = MyBitArray()
    roundInfo.dataInput.FromBytes(bytes([128, 90, 6]))
    roundInfo.SetKeyHalves(roundInfo.dataInput)
    print(roundInfo.dataInput)
    print(roundInfo.keyLeft)
    print(roundInfo.keyRight)
