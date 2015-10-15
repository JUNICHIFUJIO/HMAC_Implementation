# Author: Thomas Brown
# S# 0821288
# 
# Description
#	Creates a handler for simulating a Data Encryption Standard block cipher.
#	Handles the following:
#		1) Generation of a password
#			use: ./des genkey password outputFile
#		2) Encryption of an input file given a file holding a password key
#			use: ./des encrypt inputFile keyFile outputFile mode
#		3) Decryption of an input file given a file holding a password key
#			use: ./des decrypt inputFile keyFile outputFile mode

from enum import Enum	# import enumerators to specify possible modes
from bitstring import BitArray
from sys import getsizeof
import copy # for copying and deepcopying custom classes
from os import path
from sys import argv # for getting the arguments to the program
from hashlib import sha256
from hashlib import hexdigest
import random

# Main
if __name__ == "__main__":
        usageString = "Usage: (genkey, password, outputFile); (encrypt, inputFile, keyFile, outputFile, mode); (decrypt, inputFile, keyFile, outputFile, mode);
        if len(sys.argv) < 4 || len(sys.argv) > 6:
                raise RuntimeError(usageString)
        
        if sys.argv[1] == "genkey":
                if len(sys.argv) != 4:
                        raise RuntimeError("Usage: genkey password outputFile")
                else:
                        des = DES()
                        password = sys.argv[2]
                        outputFileName = sys.argv[3]
                        des.GenKey(password, outputFileName)
        else if sys.argv[1] == "encrypt":
                if len(sys.argv) != 6:
                        raise RuntimeError("Usage: encrypt inputFile keyFile outputFile mode")
                else:
                        des = DES()
                        inputFileName = sys.argv[2]
                        keyFileName = sys.argv[3]
                        outputFileName = sys.argv[4]
                        modeString = sys.argv[5]
                        des.Encrypt(inputFileName, keyFileName, outputFileName, modeString)
        else if sys.argv[1] == "decrypt":
                if len(sys.argv) != 6:
                        raise RuntimeError("Usage: decrypt inputFile keyFile outputFile mode")
                else:
                        des = DES()
                        inputFileName = sys.argv[2]
                        keyFileName = sys.argv[3]
                        outputFileName = sys.argv[4]
                        modeString = sys.argv[5]
                        des.Decrypt(inputFileName, keyFileName, outputFileName, modeString)        

# Enumerator to handle the modes
class DESModes(enum.Enum):
	encryptionCodebook = 1
	cipherBlockChain = 2
	counter = 3
	
# Records the information relevant to a Feistel round for the Data Encryption Standard
class FeistelRoundInfo:
        # Constructor
        def __init__(self, round_number):
                self.roundNumber = round_number

        # Methods
        def SetKeyHalves(self, key):
                # ERROR TESTING
                # should be a 56 bit key. if not throw an error
                halfwayPoint = key.__len__ / 2
                
                self.keyLeft = MyBitArray()
                keyLeft.FromBits(key.bits[:halfwayPoint])

                self.keyRight = MyBitArray()
                keyRight.FromBits(key.bits[halfwayPoint:])
        
        # Fields
        dataInput = 0
        dataOutput = 0
        keyLeft = 0
        keyRight = 0
        roundNumber = 0

# Takes a series of bytes, and converts them to a conjoined list of bits
class MyBitArray:
        # Constructor
        
        # Methods
        def FromBytes(self, bytes_):
                self.bits = [0] * bytes_.__len__ * 8
                self.__len__ = self.bits.__len__
                
                bitIndex = 0
                for byte in bytes_:
                        for i in reversed(range(8)):
                                if(byte & (1 << i) != 0):
                                        bits[bitIndex] = 1
                                else:
                                        bits[bitIndex] = 0
                                ++bitIndex

        def FromBits(self, bits):
                self.bits = bits.copy()
                self.__len__ = len(self.bits)

        def ToBytes(self):
                result = bytearray()
                byteIndex = 0
                bitIndex = 0
                while (byteIndex * 8) < len(self):
                        bitIndex = 0
                        theBits = self.bits[index : index + 8]
                        result.append(0)
                        for i in range(8):
                                result[byteIndex] = result[byteIndex] & (theBits[bitIndex] << (len(theBits) - 1 - index))
                                bitIndex = i
                        byteIndex += 1

                return bytes(result)

        def extend(self, bit_array):
                try:
                        self.bits.extend(bit_array.bits)
                except AttributeError:
                        self.bits.extend(bit_array)
                return self

        # Returns a fresh MyBitArray that contains this bit array's bits rotated
        # to the left by n_rotations
        def RotateLeft(n_rotations = 1)
                try:
                        if n_rotations >= len(self.bits):
                                n_rotations %= len(self.bits)
                        shiftedBits = MyBitArray()
                        shiftedBits.extend(bits[n_rotations:])
                        shiftedBits.extend(bits[:n_rotations])
                        return shiftedBits
                except ZeroDivisionError, IndexError:
                        return MyBitArray()
                # check its length, get the MSB, << it, and then append it and return

        # Returns a fresh MyBitArray that contains this bit array's bits rotated
        # to the right by n_rotations
        def RotateRight(n_rotations = 1)
                try:
                        if n_rotations >= len(self.bits):
                                n_rotations %= len(self.bits)
                        # check its length, get the LSB, >> it, and then if LSB was 1, XOR it with a 1 <<'d the length
                        shiftedBits = MyBitArray()
                        shiftedBits.extend(bits[bits.__len__-n_rotations:])
                        shiftedBits.extend(bits[:bits.__len__-n_rotations])
                        return shiftedBits
                except ZeroDivisionError, IndexError:
                        return MyBitArray()

        ##################################################################
        # Handler methods
        def __getitem__(self, key):
                return bits[key]

        def __copy__(self):
                copy = type(self)()
                copy.FromBits(copy.copy(self.bits))
                return copy

        def __deepcopy__(self, memo):
                deepcopy = type(self)()
                deepcopy.FromBits(copy.deepcopy(self.bits, memo))
                return deepcopy
        
        def __reversed__(self):
                result = MyBitArray()
                result.FromBits(self.bits)
                for i in range(len(self)):
                        tempBit = result[i]
                        result[i] = result[len(self) - 1 - i]
                        result[len(self) - 1 - i] = tempBit
                        
                return result
                                   
        def __xor__(self, other):
                reverseResult = []
                shorterArr = self
                longerArr = other
                if len(other) < len(self)
                        shorterArr = other
                        longerArr = self
                reverseSelfBits = reversed(self.bits)
                reverseOtherBits = reversed(other.bits)

                # get the bits you have to compare for
                reverseResult.expand((reverseSelfBits[i] & reverseOtherBits[i]) for i in range(len(shorterArr)))
                # get the remaining bits
                reverseResult.expand(longerArr[i] for i in range(len(shorterArr):))

                # get the reverse of the reverse result
                result = MyBitArray()
                result.FromBits(reversed(reverseResult))

                return result
                                   
        ####################################################################
        # Iterator
        def __iter__(self):
                return MyBitArrayIterator(self.bits)

        # Fields
        bits = []

        # Sub classes
        class MyBitArrayIterator:
                def __init__(self, bits):
                        self.index = 0
                        self.bits = bits

                def __iter__(self):
                        return self

                def __next__(self):
                        try:
                                result = self.bits[self.index]
                        except IndexError:
                                raise StopIteration
                        self.index += 1
                        return result

class DES:		# define the DES class
        # variables
        # boxes # ERROR TESTING # verify these values are correct!
        initialPermutationBox = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
        finalPermutationBox = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
        expansionBox = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
        permutationBox = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
        pc1BoxLeft = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36]
        pc1BoxRight = [63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
        pc2Box = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

        rotationSchedule = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

        sBox1 = [
                # 0yyyy0
                [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                # 0yyyy1
                [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                # 1yyyy0
                [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                # 1yyyy1
                [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
                ]
        sBox2 = [
                [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
                ]
        sBox3 = [
                [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
                ]
        sBox4 = [
                [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
                ]
        sBox5 = [
                [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
                ]
        sBox6 = [
                [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
                ]
        sBox7 = [
                [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
                ]
        sBox8 = [
                [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
                ]

        expectedBlockLength = 64

        def GetScriptDirectory(self):
                return os.path.dirname(os.path.realpath(sys.argv[0]))

        def GetFileName(path):
                fileNameWithExtension = GetFileNameWithExtension(path)
                fileName = fileNameWithExtension.split(".")[0]

                return fileName

        def GetFileNameWithExtension(path):
                directories = path.split("\\")
                fileNameWithExtension = directories[len(directories) - 1]

                return fileNameWithExtension

        def GetFileExtension(file_name):
                fileExtension = file_name.split(".")[0]

                return fileExtension

        # Assumes the extension is included in the file name, but that the directory path is not
        def WriteByteDataFile(data_file_name, data):
                directoryPath = GetScriptDirectory() + '\'
                dataFileName = GetFileNameWithExtension(data_file_name)
                file = open(directoryPath + dataFileName, "wb")
                file.write(data)
                file.close()

        def ReadByteDataFile(data_file_name):
                directoryPath = GetScriptDirectory() + "\"
                dataFileName = GetFileNameWithExtension(data_file_name)
                file = open(directoryPath + dataFileName, "rb")
                result = file.read()
                file.close()

                return result

	def GenKey(self, password, output_file_name):
                # get the first 8 bytes (64 bits) of the hash and save it as the key
                keyHash = hashlib.sha256(password.__str__()).digest()[:8]
                # save it to the desired output file
                # ERROR TESTING
                # Need to save file to the directory of the top level script
                outputFileName = GetScriptDirectory() + output_file_name + ".txt"
                outputFileHandler = open(outputFileName, "wb")
                outputFileHandler.write(keyHash)
                outputFileHandler.close()

        def GetEncryptionMode(mode_string):
                if mode.upper() == "CBC" || mode.lower() == "cipherblockchain":
                        return DESModes.cipherBlockChain
                else if mode.upper() == "CTR" || mode.lower() == "counter":
                        return DESModes.counter
                else:
                        # default to electronic codebook (EBC)
                        return DESModes.encryptionCodebook
                
        # Assumes that the files are in the current working directory of the .exe
        # and that the passed in file names are JUST the names with the extensions,
        # not the actual full path
	def Encrypt(self, input_file_name, key_file_name, output_file_name, mode_string):
                # get the input bits from the input file name
                dataInput = MyBitArray()
                dataInput.FromBytes(RetrieveByteData(input_file_name))

                # retrieve the key from the key file
		key = MyBitArray()
		key.FromBytes(RetrieveByteData(key_file_name))

		# open the output file for writing
		outputFileName = GetScriptDirectory() + output_file_name + ".txt"
                outputFile = open(outputFileName, "wb")

                # get the mode from the passed in string
                encryptionMode = GetEncryptionMode(mode_string)
                if encryptionMode == DESModes.cipherBlockChain:
                        EncryptionCBC(dataInput, key, outputFile)
                else if encryptionMode == DESModes.counter:
                        EncryptionCTR(dataInput, key, outputFile)
                else:
                        # run the process
                        EncryptionECB(dataInput, key, outputFile)

                # close the output file
                outputFile.close()

        def GetECBBlock(input_bit_array, index = 0):
                block = MyBitArray()
                        
                # determine if the bit array has enough bits left to form a full block
                paddingAmount = 0
                if index + expectedBlockLength > len(input_bit_array):
                        # need to pad a certain amount
                        paddingAmount = index + expectedBlockLength - len(input_bit_array)

                # transfer over bits to fill block
                block.FromBits(input_bit_array.bits[index:index + expectedBlockLength])

                if paddingAmount > 0:
                        paddingBitArray = MyBitArray()
                        paddingBytes = bytes(paddingAmount)
                        paddingBytes.extend(bytes(paddingAmount.__str__().encode('utf-8')) for i in range(paddingAmount))
                        paddingBitArray.FromBytes(bytes(paddingAmount))
                        block.bits.extend(paddingBitArray.bits)

                return block

        def ProcessPermutation(bit_array, permutation_box):
                # make resulting bit array                                   
                result = MyBitArray()
                result.FromBits(bit_array.bits)

                # process the permutation
                for i in range(len(permutation_box)):
                        result.bits[i] = bit_array.bits[permutation_box[i]]
                                   
                return result

        def ProcessSBox(input_bit_array, s_box):
                result = MyBitArray()

                # calculate row # of table
                row = input_bit_array[0]
                row = row << 1
                row = row ^ input_bit_array[len(input_bit_array) - 1]
                # calculate column # of table
                column = input_bit_array[1:len(input_bit_array) - 1]

                resultBytes = bytes([s_box[row][column]])
                result.FromBytes(resultBytes)

                return result

        def FeistelFunction(data_input_right_half, subkey):
                # E box (Expansion)
                expandedData = ProcessPermutation(data_input_right_half, expansionBox)
                
                # XOR Mr with round's subkey
                sBoxInput = MyBitArray()
                sBoxInput.FromBits(expandedData ^ subkey)

                # Process through S-boxes
                joinedSBoxOutput = MyBitArray()
                joinedSBoxOutput.FromBits([])
                sBoxes = [sBox1, sBox2, sBox3, sBox4, sBox5, sBox6, sBox7, sBox8]
                sBoxInputLength = 6
                for i in range(len(sBoxes)):
                        index = i * sBoxInputLength
                        sBoxOutput = ProcessSBox(data_input_right_half[index : index + sBoxInputLength])
                        joinedSBoxOutput.bits.extend(sBoxOutput.bits)
                        # ERROR TESTING write an extend method (takes bit array)
                
                # Permute result
                result = ProcessPermutation(joinedSBoxOutput, permutationBox)

                return result
        
        def ProcessFeistelRound(data_input, key_left, key_right, round_number, is_encryption):
                # requires a 64 bit input. if not 64 bits, throw an error # ERROR TESTING NEED TO IMPLEMENT
                try:
                        if len(data_input) != 64 || len(key_left) != 28 || len(key_right) != 28:
                                raise ValueError("FeistelRoundEncryption received data or keys of an inappropriate length.")

                # create result FeistelRoundInfo
                roundResult = FeistelRoundInfo()
                roundResult.roundNumber = round_number
                roundResult.dataInput = data_input
                roundResult.dataOutput = MyBitArray()
                roundResult.keyLeft = MyBitArray()
                roundResult.keyRight = MyBitArray() # ERROR TESTING .bits not initialized, but SHOULD be handled

                # split the data into two halves, call them Ml and Mr
                Ml = MyBitArray()
                Mr = MyBitArray()
                SplitBitArray(roundResult.dataInput, [Ml, Mr])

                # generate the subkey for the round
                if is_encryption == True:
                        subkey = DESSubKeyGenerator(key_left, key_right, rotationSchedule[round_number], is_encryption)
                else:
                        subkey = DESSubKeyGenerator(key_left, key_right, rotationSchedule[round_number], False)
                SplitBitArray(subkey, [roundResult.keyLeft, roundResult.keyRight]) # ERROR TESTING set left and right keys as subkeys halves

                # Process Feistel Function
                newMr = FeistelFunction(Mr, subkey)

                # XOR with Ml
                newMr = mangledMr ^ Ml

                # Concatenate XOR result with original Mr
                roundResult.dataOutput = MyBitArray() # ERROR TESTING should be concatenation of Mr with newMr
                roundResult.dataOutput.FromBits(Mr)
                roundResult.dataOutput.extend(newMr)
                
                # returns the output of the round
                return roundResult
        
        def EncryptECB(input_bit_array, key_bit_array, output_file_handler, is_encryption, write_to_output_file = True):
                # run the PC1 permutation on the key to select 56 bits of the 64 bits of the key
                permutedKey = ProcessPermutation(key_bit_array, initialPermutationBox)
                
                # split the key
                roundInfo.keyLeft = MyBitArray()
                roundInfo.keyLeft.bits = []
                roundInfo.keyRight = MyBitArray()
                roundInfo.keyRight.bits = []
                SplitBitArray(permutedKey, [keyLeft.bits, keyRight.bits])

                # run the rounds
                index = 0
                while index < len(input_bit_array):
                        GetECBBlock(input_bit_array, index)
                        index += expectedBlockLength

                        # run the initial permutation on the data
                        permutedInputBitArray = ProcessPermutation(input_bit_array, self.initialPermutationBox)

                        # split the key
                        subkeyHalfSize = 28
                        keyLeft = MyBitArray()
                        keyLeft.FromBits(ProcessPermutation(key, pc1BoxLeft)[:subkeyHalfSize])
                        keyRight = MyBitArray()
                        keyRight.FromBits(ProcessPermutation(key, pc1BoxRight)[:subkeyHalfSize])
                        
                        roundInfo = FeistelRoundInfo()
                        roundInfo.keyLeft = keyLeft
                        roundInfo.keyRight = keyRight
                        roundInfo.dataInput = permutedInputBitArray
                        # run a feistel round 16 times
                        for i in range(0, 16):
                                if(i > 0):
                                        roundInfo.inputData = roundInfo.outputData
                                roundInfo.roundNumber = i
                                roundInfo.outputData = ProcessFeistelRound(roundInfo.dataInput, roundInfo.keyLeft, roundInfo.keyRight, roundInfo.roundNumber, roundInfo)
                                # ERROR TESTING key has to be mutable -> use a list of bits

                        # run the final permutation of the data
                        roundInfo.outputData = ProcessPermutation(roundInfo.outputData, self.finalPermutationBox)
                        
                        # append to a ciphertext file
                        if write_to_output_file == True:
                                output_file_handler.write(roundInfo.outputData)
                        lastCipherBlock = roundInfo.outputData

                return lastCipherBlock

        def CreateInitializationVector(self):
                bitLength = 0
                initializationVector = bytearray()

                while bitLength < expectedBlockLength:
                        appendage = random.randint(0, 255)
                        initializationVector.append(appendage)
                        bitLength += appendage.bit_length()
                        if bitLength >= expectedBlockLength:
                                initializationVector
                                break

                resultBitArray = MyBitArray()
                resultBitArray.FromBytes(initializationVector)
                # truncate result to expectedBlockSize bits
                resultBitArray.bits = resultBitArray.bits[:expectedBlockSize]

                return resultBitArray

        # Takes in an array of bytes and increments the last byte by 1 as if conjoined
        # Returns a byte array of the incrementated initialization vector
        # If all bytes are at the maximum value, all bytes are set to 0
        def IncrementInitializationVector(self, bit_array_of_IV):
                # ERROR TESTING will just make bytes of 1s and 0s. Convert to an integer and transform into a byte
                byte_array = bytes(bit_array_of_IV.bits)
                newIVBytes = bytearray(byte_array)
                for i in reversed(range(len(result)):
                        try:
                                newIVBytes[i] += 1
                        except ValueError:
                                newIVBytes[i] = 0
                                continue
                        break

                result = MyBitArray()
                result.FromBytes(newIVBytes)

                return result

        def WriteIVKeyFile(IV_bit_array, key_bit_array, output_file_handler):
                # Save the initialization vector and key
                IVAndKeyBytes = bytearray(IV_bit_array.ToBytes())
                IVAndKeyBytes.extend(key_bit_array.ToBytes())
                # Write the IV + key byte stream to a file
                IVAndKeyFileName = GetScriptDirectory() + "\\" + GetFileName(output_file_handler.name) + "_IVKey.txt"
                WriteByteDataFile(IVAndKeyFileName, data)

                return IVAndKeyFileName

        def ReadIVKeyFile(ciphertext_file_handler):
                # Find the IVKeyFile
                IVAndKeyFileName = GetScriptDirectory() + "\\" + GetFileName(ciphertext_file_handler.name) + "_IVKey.txt"
                return ReadByteDataFile(IVAndKeyFileName, data)
                
        def RunCBCMode(input_bit_array, key_bit_array, output_file_handler, is_encryption):
                if is_encryption == True:
                        IV = CreateInitializationVector()
                        lastCBCResult = IV
                else:
                        # retrieve the IV and key from the IV and key file
                        ciphertextInput = GetECBBlock(input_bit_array)
                        lastCBCResult = ciphertextInput

                        # retrieve the IV from the IV and key file (key is already derived in general Decrypt section)
                        IV = ExtractIVFor(output_file_handler)

                if is_encryption:
                        index = 0 # start at beginning of plaintext
                        readTextForwards = True
                else:
                        index = len(input_bit_array) - 1 # start at end of ciphertext
                        readTextForwards = False
                while index < len(input_bit_array):
                        textInput = GetECBBlock(input_bit_array, index, readTextForwards)
                        ECBInput = textInput ^ lastCBCResult
                        
                        lastCBCResult = EncryptECB(ECBInput, key_bit_array, output_file_handler)
                        # ERROR TESTING might refer to an out of scope object now?
                        index += expectedBlockLength

                IVAndKeyFileName = WriteIVKeyFile(IV, key_bit_array, output_file_handler)
                
                return IVAndKeyFileName

        def DecryptCBC(ciphertext_bit_array, IV_bit_array, key_bit_array, output_file_handler):
                index = len(ciphertext_bit_array) - 1 # start at the end of the ciphertext bit array
                lastCBCResult = IV_bit_array
                readTextForwards = False
                
                while index > 0:
                        textInput = GetECBBlock(ciphertext_bit_array, index, readTextForwards)
                        lastCBCResult = textInput
                        ECBInput = textInput

                        # get result of using DES
                        isEncryption = False
                        writeToOutputFile = False
                        DESResult = EncryptECB(ECBInput, key_bit_array, output_file_handler, isEncryption, writeToOutputFile)

                        # XOR last cbc result or IV with result of DES
                        roundResult = 

                        # update loop variables
                        lastCBCResult = textInput
                        index -= expectedBlockSize

                        # detect if there are padding bytes present (only first iteration)
                
                        # write the round result
                        WriteByteDataFile(output_file_name.name.find(
                        
        def EncryptCTR(input_bit_array, key_bit_array, output_file_handler):
                # create an initialization vector (IV)
                IV = CreateInitializationVector()
                incrementedIV = IV
                
                while index < len(input_bit_array):
                        ECBOutput = EncryptECB(incrementedIV, key_bit_array, output_file_handler, write_to_output_file=False)
                        cipherTextAppendage = ECBOutput ^ GetECBBlock(input_bit_array, index)
                        output_file_handler.write(cipherTextAppendage.ToBytes())

                        incrementedIV = IncrementInitializationVector(incrementedIV)
                        index += expectedBlockSize

                IVAndKeyFileName = WriteIVKeyFile(IV, key_bit_array, output_file_handler)

                return IVAndKeyFileName

        def GetFinalKey(key_bit_array):
                # pretend it has gone through 16 feistel function iterations
                n_total_rotations = 0
                for n_rotations in self.rotationSchedule:
                        n_total_rotations += n_rotations
                finalKey = key_bit_array.RotateLeft(n_total_rotations)
                
                return finalKey        

	def Decrypt(input_file, key_file, output_file_name, mode):
                # get the input bits from the input file name
                dataInput = MyBitArray()
                dataInput.FromBytes(RetrieveByteData(input_file_name))

                # retrieve the key from the key file
		key = MyBitArray()
		key.FromBytes(RetrieveByteData(key_file_name))

                # process the key to make it equal to the final iteration through DES' key
                key = GetFinalKey(key)

		# open the output file for writing
		outputFileName = GetScriptDirectory() + output_file_name + ".txt"
                outputFile = open(outputFileName, "wb")

                # get the mode from the passed in string
                encryptionMode = GetEncryptionMode(mode_string)
                is_encryption = False
                if encryptionMode == DESModes.cipherBlockChain:
                        RunCBCMode(dataInput, key, outputFile, is_encryption)
                else if encryptionMode == DESModes.counter:
                        RunCTRMode(dataInput, key, outputFile, is_encryption)
                else:
                        # run the process
                        RunECBMode(dataInput, key, outputFile, is_encryption)

                # close the output file
                outputFile.close()

        # Splits bits between a list of input list of bit arrays. Consecutive bits stay consecutive.
        # If unable to split evenly, the remainder of bits goes to the end of the last result array.
        def SplitBitArray(input_bit_array, list_of_result_arrays):
                # Guard condition
                if(list_of_result_arrays == None || len(list_of_result_arrays) < 1):
                        return

                # transfer the bits over
                arrIndex = 0
                nInArr = len(input_bit_array) / len(list_of_result_arrays)
                for arr in list_of_result_arrays:
                        if arr.bits == None:
                                arr.bits = []
                        arr.expand(input_bit_array[arrIndex * nInArr : (arrIndex + 1) * nInArr]
                        arrIndex += 1

                # transfer the remaining bits to the last array
                if (arrIndex * nInArr) < len(input_bit_array):
                        list_of_result_arrays[len(list_of_result_arrays) - 1].expand(input_bit_array[arrIndex * nInArr:])

        def DESSubKeyGenerator(key_left, key_right, n_rotations, is_encryption):
                # both inputs should be 28 bits long. if not, throw an exception # ERROR TESTING need to implement
                # ERROR TESTING
                try:
                        if len(key_left) != 28 || len(key_right) != 28:
                                raise ValueError
                
                # rotate the key halves
                if is_encryption == True:
                        rotatedKeyLeft = key_left.RotateLeft(n_rotations)
                        rotatedKeyRight = key_right.RotateLeft(n_rotations)
                else:
                        rotatedKeyLeft = key_left.RotateRight(n_rotations)
                        rotatedKeyRight = key_right.RotateRight(n_rotations)

                # pass through PC2
                roundKey = MyBitArray()
                roundKey.FromBits(rotatedKeyLeft.bits)
                roundKey.extend(rotatedKeyRight.bits)
                return ProcessPermutation(roundKey, pc2Box)
