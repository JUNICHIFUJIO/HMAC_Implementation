# Section for allowing import of custom classes
import sys
import os

if sys.path[0] != os.path.dirname(os.path.realpath(sys.argv[0])):
    sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

######################################
#               IMPORTS
######################################
from BinaryFileHandler import *
from MyBitArray import MyBitArray

######################################
#           METHODS START
######################################
# Opens a binary file with a name based off of the name associated with
# output_file_handler's name, writes the binary data to it, and then closes
# the file.
def WriteIVFile(IV_bit_array, output_file_handler):
    # Save the initialization vector
    IVBytes = bytearray(IV_bit_array.ToBytes())
    # Write the IV byte stream to a file
    IVFileName = os.path.join(GetScriptDirectory(), GetFileName(output_file_handler.name)) + "_IV.txt"
    WriteByteDataFile(IVFileName, IVBytes)

    return IVFileName

# Searches for a binary file with a name based off of the name associated with
# ciphertext_file_handler's name, reads the binary data from it, and then closes
# the file.
def ReadIVFile(ciphertext_file_handler):
    # Find the IVFile
    IVFileName = os.path.join(GetScriptDirectory(), GetFileName(ciphertext_file_handler.name)) + "_IV.txt"
    
    return ReadByteDataFile(IVFileName)

# Extracts the IV from a stream of bytes
def ExtractIV(IV_bytes):
    IVBitArray = MyBitArray()
    IVBitArray.FromBytes(IV_bytes)

    return IVBitArray

######################################
#               MAIN
######################################
if __name__ == "__main__":
    print("Running Main for IVFileHandler module.")
    print("Testing WriteIVFile() with a bit array based off of bytes(180, 99, 23). The output file is TestOutput.txt")
    testIVBytes = bytes([180, 99, 23])
    print("Test IV Bytes is...")
    print(testIVBytes)
    testIVBits = MyBitArray()
    testIVBits.FromBytes(testIVBytes)
    outputFile = open(os.path.join(GetScriptDirectory(), "TestOutput.txt"), "rb")
    print("The resulting file is titled...")
    print(WriteIVFile(testIVBits, outputFile))

    print("Testing ReadIVFile() for 'TestOutput.txt'.")
    readIVBytes = ReadIVFile(outputFile)
    print(readIVBytes)
    outputFile.close()

    print("Testing ExtractIV() for the read-in IV from the ReadIVFile() test.")
    print(ExtractIV(readIVBytes))
