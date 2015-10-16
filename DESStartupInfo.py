# Section for allowing import of custom classes
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

# imports
from DESModes import DESModes
from MyBitArray import MyBitArray
from BinaryFileHandler import *

class DESStartupInfo:
    
    def __init__(self):
        InputFilePath = 0
        InputBitArray = 0
        KeyBitArray = 0
        OutputFileHandler = 0
        ModeOfOperation = 0
        IsEncryption = 0
        
    # Static method that retrieves data as appropriate from the given files
    @staticmethod
    def RetrieveDESStartupInfo(input_file_name, key_file_name, output_file_name, mode_string, is_encryption):
        startupInfo = DESStartupInfo()

        # Store the input file name for potential later use
        startupInfo.InputFilePath = GetScriptDirectory() + "\\" + GetFileNameWithExtension(input_file_name)

        # get the input bits from the input file name
        startupInfo.InputBitArray = MyBitArray()
        startupInfo.InputBitArray.FromBytes(ReadByteDataFile(input_file_name))

        # retrieve the key bit array from the key file
        startupInfo.KeyBitArray = MyBitArray()
        startupInfo.KeyBitArray.FromBytes(ReadByteDataFile(key_file_name))

        # open an output file handler
        outputFileName = GetScriptDirectory() + output_file_name
        # append file extension if necessary
        if len(outputFileName.split(".")) < 2:
            outputFileName += ".txt"
        startupInfo.OutputFileHandler = open(outputFileName, "wb")
        
        # record the mode of operation
        startupInfo.ModeOfOperation = DESModes.GetEncryptionMode(mode_string)

        return startupInfo

    def close(self):
        try:
            self.InputBitArray.close()
        except AttributeError
        try:
            self.KeyBitArray.close()
        except AttributeError
        try:
            self.OutputFileHandler.close()
        except AttributeError
        try:
            self.ModeOfOperation.close()
        except AttributeError
