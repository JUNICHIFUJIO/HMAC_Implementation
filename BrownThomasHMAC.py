# Author: Thomas Brown
# S# 0821288
# 11/15/15
#
# Generates a hashed message authetication code using customized SHA256 algorithm.

import sys
import os

if sys.path[0] != os.path.dirname(os.path.realpath(sys.argv[0])):
    sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

######################################
#               IMPORTS              #
######################################
from MyHexHandler import *      # Used to handle the hex to byte conversions and vice versa
from MySHA256 import MySHA256
from BinaryFileHandler import * # Custom module handling the writing and reading
                                # of data from binary files, as well as the easy
                                # retrieval of file names, directories, and extensions.
from MyBitArray import MyBitArray
                                # Custom class for managing bits. Didn't find
                                # anything native to Python that could do so.

class BrownThomasHMAC:
    '''Generates a hashed message authentication code using customized SHA256
       algorithm.'''
    ######################################
    #            CLASS VARIABLES         #
    ######################################
    ipadSegment = "0b00110110"
    opadSegment = "0b01011100"
    nPadSegments = 8
    expectedBlockLength = 512
    expectedHashOutputLength = 256
    
    ######################################
    #           KEY GENERATION           #
    ######################################
    def GenKey(self, password):
        '''Generate an encryption key, given a password. Utilizes my custom SHA256
           hashing algorithm. Writes the file to the same directory holding the
           top level executable script.

           Returns the name of the file holding the password hash.'''
        # Repeatedly hashes the password passed in for extra security.
        mySHA = MySHA256()
        keyHash = mySHA.hash(password)
        for i in range(15):
            keyHash = mySHA.hash(MySHA256.hexdigest(keyHash))
        # Get the first 8 bytes (64 bits) of the hash and save it as the key.
        keyHash = mySHA.hash(MySHA256.hexdigest(keyHash))[:8]

        # Write to binary file in the same directory as the top level script
        return WriteByteDataFile("EncryptionKey", keyHash)

    ######################################
    #           DATA RETRIEVAL           #
    ######################################
    def ReadMessage(self, message_file_name):
        '''Retrieve a message from the given file for use in the HMAC.'''
        return ReadByteDataFile(message_file_name)

    def ReadKey(self, key_file_name):
        '''Reads a key from the given file for use in the HMAC.'''
        return ReadByteDataFile(key_file_name)

    ######################################
    #           PAD MANIPULATION         #
    ######################################
    def padKey(self, key_bytes):
        '''Pads the used key with zeroes on the right until it meets the expected
           hash input length. Doesn't return the padded key, just changes it
           in-place.'''
        paddedKey = MyBitArray()
        paddedKey.FromBytes(key_bytes)
        if len(paddedKey) < BrownThomasHMAC.expectedBlockLength:
            padding = [0] * (len(paddedKey) - BrownThomasHMAC.expectedBlockLength)
            padding.extend(paddedKey.bits)
            paddedKey.FromBits(padding)
        elif len(paddedKey) > BrownThomasHMAC.expectedBlockLength:
            paddedKey.bits = paddedKey.bits[:BrownThomasHMAC.expectedBlockLength]

        return paddedKey

    def ipadToBits(self):
        '''Converts ipad segment to ipad, which is then converted to bit array.

           Returns ipad as a bit array.'''
        ipadBitArray = MyBitArray()
        ipadBytes = bytes([int(BrownThomasHMAC.ipadSegment, 2)] * BrownThomasHMAC.nPadSegments)
        ipadBitArray.FromBytes(ipadBytes)

        return ipadBitArray
        
    def opadToBits(self):
        '''Converts opad segment to opad, which is then converted to bit array.

           Returns opad as a bit array.'''
        opadBitArray = MyBitArray()
        opadBytes = bytes([int(BrownThomasHMAC.opadSegment, 2)] * BrownThomasHMAC.nPadSegments)
        opadBitArray.FromBytes(opadBytes)

        return opadBitArray

    def fusePadWithKey(self, pad_bit_array, padded_key_bit_array):
        '''Fuses a key with the given ipad or opad. XORs the key with the leftmost
           bits of the given pad. The pad will not be the same size as the key.
           The key will be a smaller size.

           Returns the padded key as a bit array.'''
        padFirstPart = MyBitArray()
        padFirstPart.FromBits(pad_bit_array.bits[:len(padded_key_bit_array)])
        resultFirstPart = padFirstPart ^ padded_key_bit_array
        result = MyBitArray()
        result.FromBits(padFirstPart.bits)
        result.extend(pad_bit_array[len(padFirstPart):])

        return result        

    ######################################
    #           HMAC FUNCTIONS           #
    ######################################
    def HMAC(self, key_bytes, message_bytes):
        '''Provides the bytes of the hashed message authentication code. To
           convert to hexadecimal, the bytes need to be passed through
           MySHA256.hexdigest(result).

           Returns the bytes of the hashed message authentication code.'''
        # Convert the ipad and the opad to bitarrays
        ipadBitArray = self.ipadToBits()
        opadBitArray = self.opadToBits()
        # Pad the key
        paddedKey = self.padKey(key_bytes)
        # Fuse the key with the ipad and opad
        fusedIpad = self.fusePadWithKey(ipadBitArray, paddedKey)
        fusedOpad = self.fusePadWithKey(opadBitArray, paddedKey)

        # Prepend the message with the fused ipad
        inputMessage = bytearray(fusedIpad.ToBytes())
        inputMessage.extend(message_bytes)
        # Hash the ipad to begin hashing the message
        mySHA = MySHA256()
        ipadHashPart = mySHA.hash(BytesToWords(inputMessage))
        ipadHashPartBits = MyBitArray()
        ipadHashPartBits.FromBytes(ipadHashPart)

        # Take the result hash bytes and prepend the fused opad
        finalHashInput = MyBitArray()
        finalHashInput.FromBytes(fusedOpad.ToBytes())
        finalHashInput.extend(ipadHashPartBits)

        # Hash the resulting concatenation
        result = mySHA.hash(BytesToWords(finalHashInput.ToBytes()))

        return result

    def WriteHMACToFile(self, key_file_name, message_file_name, output_file_name):
        '''Writes the HMAC using the key from the given key file and the message
           from the message file to the given output file.'''
        # Read in key and set it
        keyBytes = self.ReadKey(key_file_name)
        # Read in the message bytes
        messageBytes = self.ReadMessage(message_file_name)
        # Open the output file
        outputFileHandler = OpenWriteByteDataFile(output_file_name)
        # Calculate the HMAC
        hmacBytes = self.HMAC(keyBytes, messageBytes)
        # Convert HMAC to hexadecimal string
        hmacHexString = BytesToWords(hmacBytes)
        # Write to output file
        outputFileHandler.write(bytes(hmacHexString.encode("utf-8")))
        # Close the output file
        outputFileHandler.close()

if __name__ == "__main__":
    # Print introduction
    print("Running main for BrownThomasHMAC.")
    print("Module resides in " + os.path.dirname(os.path.realpath(sys.argv[0])))
    print()

    # Generate password
    # password = "Guest"
    # hmac.GenKey(password)

    # Gather system variables
    keyFileName = sys.argv[1]
    messageFileName = sys.argv[2]
    outputFileName = sys.argv[3]

    # Generate the HMAC
    hmac = BrownThomasHMAC()
    print("Generating HMAC to output file " + str(outputFileName) + ".")
    hmac.WriteHMACToFile(keyFileName, messageFileName, outputFileName)

'''
# Main testing mainframe
if __name__ == "__main__":
    print("Running main for BrownThomasHMAC.")
    print("Module resides in " + os.path.dirname(os.path.realpath(sys.argv[0])))
    print()

    hmac = BrownThomasHMAC()
    password = "Guest"
    print("Testing KeyGen method with password " + str(password) + ".")
    hmac.GenKey(password)
    print()

    messageFileName = "Message.txt"
    keyFileName = "EncryptionKey.txt"
    outputFileName = "TestOutput.txt"
    print("Testing HMAC capabilities. Using message from " + str(messageFileName) + " and key from " + str(keyFileName) + ".")
    print("Writing HMAC to output file " + str(outputFileName) + ".")
    hmac.WriteHMACToFile(keyFileName, messageFileName, outputFileName)
'''
