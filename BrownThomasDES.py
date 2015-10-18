# Author: Thomas Brown
# S# 0821288
# 10/18/15
# Homework Assignment 1: Data Encryption Standard with Modes of Operation
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

# Section for allowing import of custom classes
import sys
import os

if sys.path[0] != os.path.dirname(os.path.realpath(sys.argv[0])):
    sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

######################################
#               IMPORTS
######################################
import copy                     # For copying and deepcopying custom classes
from hashlib import sha256      # For key generation hashing algorithm
from random import randint      # For initialization vector creation.
                                # I decided on using random for IVs because they are
                                # publicly accessible anyways, unlike the password
                                # or the key.

######################################
#            CUSTOM IMPORTS
######################################
from DESModes import DESModes   # Defines the modes available for use with my
                                # program.
from FeistelRoundInfo import FeistelRoundInfo
                                # Stores and manipulates data typically associated
                                # with a DES Feistel round.
from MyBitArray import MyBitArray
                                # Custom class for managing bits. Didn't find
                                # anything native to Python that could do so.
from DESStartupInfo import DESStartupInfo
                                # Stores and manipulates data typically needed
                                # for the execution of my custom DES class.
from BinaryFileHandler import * # Custom module handling the writing and reading
                                # of data from binary files, as well as the easy
                                # retrieval of file names, directories, and extensions.
from IVFileHandler import *     # Custom module handling the writing and reading
                                # of data from files storing initialization vectors
                                # associated with an output file.

######################################
#            CLASS START
######################################
# Defines a class to encapsulate all logic involving DES and the modes of
# operation required for Homework assignment #1 for CSS 527.
class DES:
    ######################################
    #            CLASS FIELDS
    ######################################
    initialPermutationBox = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
        ]
    finalPermutationBox = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
        ]
    expansionBox = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
        ]
    permutationBox = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
        ]
    pc1BoxLeft = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36
        ]
    pc1BoxRight = [
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
        ]
    pc2Box = [
        14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32
        ]
    # Defines # of shifts required each Feistel round.
    rotationSchedule = [
        1, 1, 2, 2,
        2, 2, 2, 2,
        1, 2, 2, 2,
        2, 2, 2, 1
        ]

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
    # Class fields representing generic constants
    expectedBlockLength = 64
    bitsPerByte = 8
    sBoxInputLength = 6
    nRounds = 16

    ######################################
    #               METHODS
    ######################################
    # Splits bits evenly between a passed in list of bit arrays. The bit arrays
    # must already be instantiated bit arrays. Consecutive bits stay consecutive.
    # If unable to split evenly, the remainder of bits goes to the end of the
    # last result array.
    def SplitBitArray(self, input_bit_array, list_of_result_arrays):
        # Guard condition
        if(list_of_result_arrays == None or len(list_of_result_arrays) < 1):
            return

        # transfer the bits over
        arrIndex = 0
        nInArr = int(len(input_bit_array) / len(list_of_result_arrays))
        for bit_array in list_of_result_arrays:
            bit_array.extend(input_bit_array[arrIndex * nInArr : (arrIndex + 1) * nInArr])
            arrIndex += 1

        # transfer the remaining bits to the last array
        if (arrIndex * nInArr) < len(input_bit_array):
            list_of_result_arrays[len(list_of_result_arrays) - 1].expand(input_bit_array[arrIndex * nInArr:])
    
    ######################################
    #           KEY GENERATION
    ######################################
    # Generate an encryption key, given a password. Utilizes the native sha256
    # hashing algorithm. Writes the file to the same directory holding the
    # top level executable script.
    # Returns the name of the file holding the password hash.
    def GenKey(self, password, output_file_name):
        # Repeatedly hashes the password passed in for extra security.
        keyHash = sha256(password.__str__().encode("utf-8")).hexdigest()
        for i in range(36171):
            keyHash = sha256(keyHash.encode("utf-8")).hexdigest()
        # Get the first 8 bytes (64 bits) of the hash and save it as the key.
        keyHash = sha256(keyHash.encode("utf-8")).digest()[:int(self.expectedBlockLength / self.bitsPerByte)]

        # Write to binary file in the same directory as the top level script
        return WriteByteDataFile("EncryptionKey", keyHash)

    ######################################
    #       PADDING HANDLER METHODS
    ######################################
    # Gets the padding byte for the passed in block of data.
    # Returns the byte in a bytes array if it's a pad byte, or -1 if it's not
    # a padded block.
    def GetPaddingByte(self, block_bytes):
        # Get the last byte to compare to other bytes
        padByte = block_bytes[len(block_bytes) - 1]
        startIndex = len(block_bytes) - int(padByte)

        # Verify all appropriate bytes are pad bytes
        for x in block_bytes[startIndex:]:
            if x != padByte:
                return -1

        return padByte

    # Returns a fresh bit array that holds all unpadded bits. The padding is
    # assumed to be PKCS #5.
    def RemovePadding(self, padded_block_bit_array):
        blockBytes = padded_block_bit_array.ToBytes()

        # Search for existence of padding
        padByte = self.GetPaddingByte(blockBytes)
        if padByte != -1:
            endIndex = len(blockBytes) - int(padByte)
            unpaddedBytes = bytes(blockBytes[:endIndex])
            unpaddedBits = MyBitArray()
            unpaddedBits.FromBytes(unpaddedBytes)
            return unpaddedBits
        else:
            originalBitArray = MyBitArray()
            originalBitArray.extend(padded_block_bit_array)
            return originalBitArray

    ######################################
    #       PERMUTATION/SBOX HANDLERS
    ######################################
    # Process a given permutation on the passed bit array.
    # Assumes the permutation box is set up to indicate the index of the input
    # bit array to draw from for the result's bit.
    # If is_reversed argument is true, reverses the process of permutation on
    # a given result bit array.
    # Returns the resulting permutation in a bit array format.
    def ProcessPermutation(self, bit_array, permutation_box, is_reversed = False):
        # Make resulting bit array                                   
        result = MyBitArray()

        # Process the permutation
        if is_reversed == False:
            for x in permutation_box:
                result.append(bit_array[x - 1])
        else:
            # Reverse the permutation
            result.bits = [0] * len(bit_array)
            for i in range(len(permutation_box)):
                result[permutation_box[i] - 1] = bit_array[i]
            
        return result

    # Process a given DES S-Box on the passed bit array.
    # Returns the 4 bit output of the S-Box processing in a bit array format.
    def ProcessSBox(self, input_bit_array, s_box):
        if len(input_bit_array) != self.sBoxInputLength:
            raise ValueError("Passed bit array was not the correct length.")
        result = MyBitArray()

        # Calculate row # of table
        row = input_bit_array[0]
        row = row << 1
        row = row ^ input_bit_array[len(input_bit_array) - 1]
        # Calculate column # of table
        columnBits = input_bit_array[1:len(input_bit_array) - 1]
        column = columnBits[0]
        for i in range(1, len(columnBits)):
            column = column << 1
            column ^= columnBits[i]

        # Convert result into bit array format
        resultBytes = bytes([s_box[row][column]])
        result.FromBytes(resultBytes)

        return result

    ######################################
    #   INITIALIZATION VECTOR HANDLERS
    ######################################
    # Creates an initialization vector for use with some block cipher modes
    # of operation. Not cryptographically secure, as it utilizes random.
    # However, IV is publicly accessible, so it doesn't need to be
    # cryptographically secure.
    # Returns a bit array representing the initialization vector.
    def CreateInitializationVector(self):
        bitLength = 0
        initializationVector = bytearray()

        while bitLength < self.expectedBlockLength:
            appendage = randint(0, 255)
            initializationVector.append(appendage)
            bitLength += appendage.bit_length()
            if bitLength >= self.expectedBlockLength:
                break

        resultBitArray = MyBitArray()
        resultBitArray.FromBytes(initializationVector)
        # Truncate result to expectedBlockLength # of bits
        resultBitArray.bits = resultBitArray.bits[:self.expectedBlockLength]

        return resultBitArray

    # Takes in an array of bytes and increments the last byte(s) by 1 as if
    # conjoined.
    # Returns a byte array of the incrementated initialization vector.
    # If all bytes are at the maximum value, all bytes are set to 0.
    def IncrementInitializationVector(self, IV_bit_array):
        byteArray = bytearray(IV_bit_array.ToBytes())
        for i in reversed(range(len(byteArray))):
            try:
                byteArray[i] += 1
            except ValueError:
                byteArray[i] = 0
                continue
            break

        result = MyBitArray()
        result.FromBytes(byteArray)

        return result
    
    ######################################
    #           FEISTEL HANDLERS
    ######################################
    # Runs a Feistel function (the mangler function for DES) on the right half
    # of the input data message using the given subkey.
    # Returns the result of the Feistel/mangler function, which should be the
    # Mr at the end of the Feistel round.
    def FeistelFunction(self, data_input_right_half, subkey):
        # E box (Expansion)
        expandedData = self.ProcessPermutation(data_input_right_half, self.expansionBox)
                
        # XOR Mr with round's subkey
        sBoxInput = expandedData ^ subkey

        # Process through S-boxes
        joinedSBoxOutput = MyBitArray()
        sBoxes = [self.sBox1, self.sBox2, self.sBox3, self.sBox4, self.sBox5, self.sBox6, self.sBox7, self.sBox8]
        for i in range(len(sBoxes)):
            index = i * self.sBoxInputLength
            sBoxOutput = self.ProcessSBox(sBoxInput[index : index + self.sBoxInputLength], sBoxes[i])
            joinedSBoxOutput.extend(sBoxOutput)
                
        # Permute result
        result = self.ProcessPermutation(joinedSBoxOutput, self.permutationBox)

        return result

    # Rotates the halves of the key in the given feistel round info object
    # in-place. Assumes the feistel_round_info parameter represents a FeistelRoundInfo
    # object and that the appropriate field is available/mutable.
    def RotateKeyHalves(self, feistel_round_info, is_encryption):
        feistel_round_info.RotateKeyHalves(self.rotationSchedule[feistel_round_info.RoundNumber], is_encryption)

    # Generates subkey and shifts recorded key halves in-place depending upon
    # whether encryption or decryption is requested.
    # Returns the generated subkey for the round.
    def ProcessKeySchedule(self, feistel_round_info, is_encryption):
        if len(feistel_round_info.KeyLeft) != 28 or len(feistel_round_info.KeyRight) != 28:
            raise ValueError("Inappropriate key encountered when processing key schedule.")

        if is_encryption == True:
            self.RotateKeyHalves(feistel_round_info, is_encryption)

        # Get the subkey    
        preSubkey = MyBitArray()
        preSubkey.extend(feistel_round_info.KeyLeft)
        preSubkey.extend(feistel_round_info.KeyRight)
        subkey = self.ProcessPermutation(preSubkey, self.pc2Box)

        if is_encryption == False:
            self.RotateKeyHalves(feistel_round_info, is_encryption)

        return subkey
    
    # Runs a Feistel round (one of 16 in DES) using the given input data, the
    # pre-round key halves, the round number, and whether or not DES is being
    # run as an encryption or decryption.
    # Returns a FeistelRoundInfo object defining the attributes of the round processed.
    def ProcessFeistelRound(self, input_block_bit_array, key_left_bit_array, key_right_bit_array, round_number, is_encryption):
        # Requires a 64 bit input
        if len(input_block_bit_array) != 64 or len(key_left_bit_array) != 28 or len(key_right_bit_array) != 28:
            raise ValueError("ProcessFeistelRound received data or keys of an inappropriate length.")

        # Create result FeistelRoundInfo
        roundResult = FeistelRoundInfo(0)
        roundResult.RoundNumber = round_number
        roundResult.DataInput = input_block_bit_array
        roundResult.DataOutput = MyBitArray()
        roundResult.KeyLeft = MyBitArray()
        roundResult.KeyLeft.extend(key_left_bit_array)
        roundResult.KeyRight = MyBitArray()
        roundResult.KeyRight.extend(key_right_bit_array)

        # Split the data into two halves, call them Ml and Mr
        Ml = MyBitArray()
        Mr = MyBitArray()
        self.SplitBitArray(roundResult.DataInput, [Ml, Mr])

        # Generate the subkey for the round
        subkey = self.ProcessKeySchedule(roundResult, is_encryption)
        
        # Process Feistel Function
        mangledMr = self.FeistelFunction(Mr, subkey)
        
        # XOR with Ml
        newMr = mangledMr ^ Ml

        # Concatenate XOR result with original Mr
        roundResult.DataOutput.extend(Mr)
        roundResult.DataOutput.extend(newMr)
        
        return roundResult

    # Runs a reversed Feistel round (one of 16 in DES decryption) that reconstructs
    # the appropriate input message for the parallel encryption round.
    # Returns a FeistelRoundInfo object defining the attributes of the round processed.
    def ProcessReverseFeistelRound(self, input_block_bit_array, key_left_bit_array, key_right_bit_array, round_number):
        isEncryption = False

        # Create result FeistelRoundInfo
        roundResult = FeistelRoundInfo(0)
        roundResult.RoundNumber = round_number
        roundResult.DataInput = input_block_bit_array
        roundResult.DataOutput = MyBitArray()
        roundResult.KeyLeft = MyBitArray()
        roundResult.KeyLeft.extend(key_left_bit_array)
        roundResult.KeyRight = MyBitArray()
        roundResult.KeyRight.extend(key_right_bit_array)

        # Assign names to the halves of the data input for easy conceptualization
        # of reorganization
        originalMr = MyBitArray() # refers to original encryption Mr for the round
        newMr = MyBitArray()      # refers to the mangled original encryption Mr
                                  # XOR'd with the original encryption Ml
        self.SplitBitArray(roundResult.DataInput, [originalMr, newMr])

        # Generate the subkey for the round
        subkey = self.ProcessKeySchedule(roundResult, isEncryption)

        # Process Feistel Function
        mangledMr = self.FeistelFunction(originalMr, subkey)

        # Create the original Ml
        originalMl = newMr ^ mangledMr

        # Reconstruct the input of the parallel encryption round
        roundResult.DataOutput = MyBitArray()
        roundResult.DataOutput.FromBits(originalMl.bits)
        roundResult.DataOutput.extend(originalMr)

        return roundResult

    ######################################
    #       TOP LEVEL DES METHODS
    ######################################
    # Get a block of input data ready from the input bit array
    # Pads with PKCS #5 if there are less bits than the expected block size
    # Returns the expected input data block, properly padded if necessary,
    # as a bit array.
    def GetDESBlock(self, input_bit_array, index = 0):
        block = MyBitArray()
                        
        # Determine if the bit array has enough bits left to form a full block
        paddingAmount = 0
        if index + self.expectedBlockLength > len(input_bit_array):
            paddingAmount = int((index + self.expectedBlockLength - len(input_bit_array))/ self.bitsPerByte)

        # Transfer over bits to fill block
        block.FromBits(input_bit_array.bits[index:index + self.expectedBlockLength])

        # Pad if necessary
        if paddingAmount > 0:
            paddingBitArray = MyBitArray()
            paddingBytes = bytearray()
            paddingBytes.extend(paddingAmount for i in range(paddingAmount))
            paddingBitArray.FromBytes(bytes(paddingAmount))
            block.bits.extend(paddingBitArray.bits)

        return block
    
    # Encrypts the input file using plain DES block cipher encryption.
    # Returns the last output block made by DES.
    def RunDESEncryption(self, input_bit_array, key_bit_array, output_file_handler, write_to_output_file = True):
        isEncryption = True
        roundInfo = FeistelRoundInfo(0)
        # Run the PC1 permutation on the key to select 56 bits of the 64 bits of the key
        roundInfo.KeyLeft = self.ProcessPermutation(key_bit_array, self.pc1BoxLeft)
        roundInfo.KeyRight = self.ProcessPermutation(key_bit_array, self.pc1BoxRight)

        # Run the Feistel rounds
        inputIndex = 0
        while inputIndex < len(input_bit_array):
            # Get the DES input of the appropriate length
            roundInfo.DataInput = self.GetDESBlock(input_bit_array, inputIndex)
            inputIndex += self.expectedBlockLength

            # Run the initial permutation on the data
            permutedInputBitArray = self.ProcessPermutation(roundInfo.DataInput, self.initialPermutationBox)
            roundInfo.DataInput = permutedInputBitArray

            # Run 16 Feistel rounds
            for i in range(self.nRounds):                      
                if i > 0:
                    roundInfo.DataInput = roundInfo.DataOutput
                roundInfo.RoundNumber = i
                roundInfo = self.ProcessFeistelRound(roundInfo.DataInput, roundInfo.KeyLeft, roundInfo.KeyRight, roundInfo.RoundNumber, isEncryption)

            # Run the final permutation of the data
            roundInfo.DataOutput = self.ProcessPermutation(roundInfo.DataOutput, self.finalPermutationBox)

            # Append to output file if appropriate
            if write_to_output_file == True:
                output_file_handler.write(roundInfo.DataOutput.ToBytes())
            lastOutputBlock = roundInfo.DataOutput

        return lastOutputBlock

    # Decrypts the input file using plain DES block cipher decryption.
    # Returns the last output block made by DES.
    def RunDESDecryption(self, input_bit_array, key_bit_array, output_file_handler, write_to_output_file = True, last_input_block = False):
        roundInfo = FeistelRoundInfo(0)
        roundInfo.KeyLeft = MyBitArray()
        roundInfo.KeyRight = MyBitArray()
        self.SplitBitArray(key_bit_array, [roundInfo.KeyLeft, roundInfo.KeyRight])

        # Run the Feistel rounds
        inputIndex = 0
        while inputIndex < len(input_bit_array):
            # Get the DES input of the appropriate length
            roundInfo.DataInput = self.GetDESBlock(input_bit_array, inputIndex)
            inputIndex += self.expectedBlockLength

            # Run the reverse of the final permutation on the data
            permutedInputBitArray = self.ProcessPermutation(roundInfo.DataInput, self.finalPermutationBox, True)
            roundInfo.DataInput = permutedInputBitArray

            # Run 16 Feistel rounds
            for i in range(self.nRounds):
                # Set feistel round info correctly
                if i > 0:
                    roundInfo.DataInput = roundInfo.DataOutput
                roundInfo.RoundNumber = self.nRounds - i - 1

                roundInfo = self.ProcessReverseFeistelRound(roundInfo.DataInput, roundInfo.KeyLeft, roundInfo.KeyRight, roundInfo.RoundNumber)

            # Run the reverse of the initial permutation of the data
            roundInfo.DataOutput = self.ProcessPermutation(roundInfo.DataOutput, self.initialPermutationBox, True)

            # If decrypting and this is the last block of data to decrypt,
            # search for and remove padding bytes at the end of the message.
            if last_input_block == True or (len(input_bit_array) > self.expectedBlockLength and inputIndex >= len(input_bit_array)):
                roundInfo.DataOutput = self.RemovePadding(roundInfo.DataOutput)

            # Append to output file if appropriate
            if write_to_output_file == True:
                output_file_handler.write(roundInfo.DataOutput.ToBytes())
            lastOutputBlock = roundInfo.DataOutput

        return lastOutputBlock

    # Runs DES in either encryption or decryption mode.
    # Returns the results of running DES, which is currently the last output
    # block done by the encryption/decryption algorithm.
    def RunDES(self, input_bit_array, key_bit_array, output_file_handler, is_encryption, write_to_output_file = True, last_input_block = False):
        if is_encryption == True:
            return self.RunDESEncryption(input_bit_array, key_bit_array, output_file_handler, write_to_output_file)
        else:
            return self.RunDESDecryption(input_bit_array, key_bit_array, output_file_handler, write_to_output_file, last_input_block)
    
    ######################################
    #       DECRYPTION KEY METHODS
    ######################################
    # Runs through the DES encryption algorithm's key schedule to get the final key
    # for DES decryption.
    # Returns a FeistelRoundInfo object containing the final key halves and the
    # elapsed # of rounds.
    def GetDESDecryptionKey(self, encryption_key):
        temp = FeistelRoundInfo(0)
        temp.KeyLeft = self.ProcessPermutation(encryption_key, self.pc1BoxLeft)
        temp.KeyRight = self.ProcessPermutation(encryption_key, self.pc1BoxRight)

        # Run it through 16 Feistel rounds
        for i in range(self.nRounds):
            temp.RoundNumber = i
            self.RotateKeyHalves(temp, True)

        return temp

    # Sets the passed in startup info's key to be the proper DES decryption key.
    # Assumes startup_info is an instance of the DESStartupInfo class, and that
    # the appropriate field is available/mutable.
    def SetKeyToDecryptionKey(self, startup_info):
        temp = self.GetDESDecryptionKey(startup_info.KeyBitArray)
        startup_info.KeyBitArray = MyBitArray()
        startup_info.KeyBitArray.extend(temp.KeyLeft)        
        startup_info.KeyBitArray.extend(temp.KeyRight)

    ######################################
    #   ENCRYPTION/DECRYPTION + MODES
    ######################################
    # Runs an encryption or decryption of the startup info's input file data
    # in ECB (Electronic CodeBook) mode.
    def RunECBMode(self, startup_info):
        self.RunDES(startup_info.InputBitArray, startup_info.KeyBitArray, startup_info.OutputFileHandler, startup_info.IsEncryption)

    # Runs an encryption or decryption of the startup info's input file data in
    # CBC mode. (Cipher Block Chaining)
    def RunCBCMode(self, startup_info):
        if startup_info.IsEncryption == True:
            IV = self.CreateInitializationVector()
        else:
            IV = ExtractIV(ReadIVFile(open(startup_info.InputFilePath, "rb")))
        mask = IV

        index = 0
        while index < len(startup_info.InputBitArray):
            DESInput = self.GetDESBlock(startup_info.InputBitArray, index)
            index += self.expectedBlockLength
            
            if startup_info.IsEncryption == True:
                DESInput = DESInput ^ mask

            # Determine if you need to watch out for padding bytes
            if index >= len(startup_info.InputBitArray):
                isLastInputBlock = True
            else:
                isLastInputBlock = False

            # Run the DES block cipher
            DESOutput = self.RunDES(DESInput, startup_info.KeyBitArray, startup_info.OutputFileHandler, startup_info.IsEncryption, False, isLastInputBlock)

            # Update bit mask and cipher/plain text
            if startup_info.IsEncryption == True:
                text = DESOutput
                mask = text
            else:
                text = DESOutput ^ mask
                mask = DESInput
            startup_info.OutputFileHandler.write(text.ToBytes())

        # Write the encryption IV to a file
        if startup_info.IsEncryption == True:
            WriteIVFile(IV, startup_info.OutputFileHandler)

    # Runs an encryption or decryption of the startup info's input file data in
    # CTR mode. (CounTeR)
    def RunCTRMode(self, startup_info):
        if startup_info.IsEncryption == True:
            IV = self.CreateInitializationVector()
        else:
            IV = ExtractIV(ReadIVFile(open(startup_info.InputFilePath, "rb")))
        DESInput = IV
        index = 0
        while index < len(startup_info.InputBitArray):
            if index > 0:
                DESInput = self.IncrementInitializationVector(IV)

            isLastInputBlock = False
            
            DESOutput = self.RunDES(DESInput, startup_info.KeyBitArray, startup_info.OutputFileHandler, True, False, isLastInputBlock)

            text = self.GetDESBlock(startup_info.InputBitArray, index) ^ DESOutput

            index += self.expectedBlockLength

            # Determine if you need to watch out for padding bytes
            if index >= len(startup_info.InputBitArray):
                isLastInputBlock = True
            else:
                isLastInputBlock = False
                
            if isLastInputBlock == True and startup_info.IsEncryption == False:
                text = self.RemovePadding(text)

            startup_info.OutputFileHandler.write(text.ToBytes())

        # Write the encryption IV to a file
        if startup_info.IsEncryption == True:
            WriteIVFile(IV, startup_info.OutputFileHandler)

    # Encrypts a file in the startup_info's mode of operation.
    # Assumes that the files are in the current working directory of the top
    # level script.
    def Encrypt(self, startup_info):
        if startup_info.ModeOfOperation == DESModes.cipherBlockChain:
            self.RunCBCMode(startup_info)
        elif startup_info.ModeOfOperation == DESModes.counter:
            self.RunCTRMode(startup_info)
        elif startup_info.ModeOfOperation == DESModes.electronicCodebook:
            self.RunECBMode(startup_info)
        else:
            raise ValueError("Invalid mode specified.")

        # Close all files that remain open in the start up info
        startup_info.close()

    # Decrypts a file in the startup_info's mode of operation.
    # Adds some logic to, and then runs, the Encrypt method.
    # Assumes that the files are in the current working directory of the top
    # level script.
    def Decrypt(self, startup_info):
        if startup_info.ModeOfOperation == DESModes.counter:
            self.Encrypt(startup_info)
            return
        
        if startup_info.IsEncryption != False:
            raise ValueError("Decrypt method inappropriately called.")

        # Alter the key to the proper DES decryption key
        self.SetKeyToDecryptionKey(startup_info)

        # Run the Encrypt logic with the decryption key
        self.Encrypt(startup_info)
        

######################################
#               MAIN
######################################
if __name__ == "__main__":
    usageString = "Usage: Password Generation(genkey, password, outputFile); Encryption(encrypt, inputFile, keyFile, outputFile, mode); Decryption(decrypt, inputFile, keyFile, outputFile, mode)";
    print()
    print("Running Main for BrownThomasDES module.")
    
    if len(sys.argv) < 4 or len(sys.argv) > 6:
        raise RuntimeError(usageString)
        
    if sys.argv[1].lower() == "genkey":
        if len(sys.argv) != 4:
            raise RuntimeError("Usage: genkey password outputFile")
        else:
            des = DES()
            password = sys.argv[2]
            outputFileName = sys.argv[3]
            # Ensures .txt extension exists on file name
            if len(outputFileName.split(".")) < 2:
                outputFileName += ".txt"
            print("Encryption key stored in " + des.GenKey(password, outputFileName))
    elif sys.argv[1].lower() == "encrypt":
        if len(sys.argv) != 6:
            raise RuntimeError("Usage: encrypt inputFile keyFile outputFile mode")
        else:
            des = DES()
            inputFileName = sys.argv[2]
            keyFileName = sys.argv[3]
            outputFileName = sys.argv[4]
            # Ensures .txt extension exists on file names
            if len(inputFileName.split(".")) < 2:
                inputFileName += ".txt"
            if len(keyFileName.split(".")) < 2:
                keyFileName += ".txt"
            if len(outputFileName.split(".")) < 2:
                outputFileName += ".txt"
            modeString = sys.argv[5]
            startupInfo = DESStartupInfo.RetrieveDESStartupInfo(inputFileName, keyFileName, outputFileName, modeString, True)
            des.Encrypt(startupInfo)
    elif sys.argv[1].lower() == "decrypt":
        if len(sys.argv) != 6:
            raise RuntimeError("Usage: decrypt inputFile keyFile outputFile mode")
        else:
            des = DES()
            inputFileName = sys.argv[2]
            keyFileName = sys.argv[3]
            outputFileName = sys.argv[4]
            # Ensures .txt extension exists on file names
            if len(inputFileName.split(".")) < 2:
                inputFileName += ".txt"
            if len(keyFileName.split(".")) < 2:
                keyFileName += ".txt"
            if len(outputFileName.split(".")) < 2:
                outputFileName += ".txt"
            modeString = sys.argv[5]
            startupInfo = DESStartupInfo.RetrieveDESStartupInfo(inputFileName, keyFileName, outputFileName, modeString, False)
            des.Decrypt(startupInfo)
