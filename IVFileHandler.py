# Section for allowing import of custom classes
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

# imports
from BinaryFileHandler import *
from MyBitArray import MyBitArray

def WriteIVFile(IV_bit_array, output_file_handler):
    # Save the initialization vector
    IVBytes = bytearray(IV_bit_array.ToBytes())
    # Write the IV byte stream to a file
    IVFileName = GetScriptDirectory() + "\\" + GetFileName(output_file_handler.name) + "_IV.txt"
    WriteByteDataFile(IVFileName, IVBytes)

    return IVAndKeyFileName

def ReadIVFile(ciphertext_file_handler):
    # Find the IVFile
    IVFileName = GetScriptDirectory() + "\\" + GetFileName(ciphertext_file_handler) + "_IV.txt"
    return ReadByteDataFile(IVFileName)

def ExtractIV(IV_bytes):
    IVBitArray = MyBitArray()
    IVBitArray.FromBytes(IV_bytes)

    return IVBitArray
