# Section for allowing import of custom classes
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

######################################
#            IMPORTS
######################################
from DESModes import DESModes
from MyBitArray import MyBitArray
from BinaryFileHandler import *

######################################
#            CLASS START
######################################
# Organizes and handles information necessary for the running of my custom
# DES implementation.
class DESStartupInfo:
    ######################################
    #            CONSTRUCTOR
    ######################################
    def __init__(self):
        InputFilePath = 0
        InputBitArray = 0
        KeyBitArray = 0
        OutputFileHandler = 0
        ModeOfOperation = 0
        IsEncryption = 0

    ######################################
    #            STATIC METHODS
    ######################################
    # Static method that retrieves data as appropriate from the given files
    @staticmethod
    def RetrieveDESStartupInfo(input_file_name, key_file_name, output_file_name, mode_string, is_encryption):
        startupInfo = DESStartupInfo()

        # Store the input file name for potential later use
        startupInfo.InputFilePath = GetScriptDirectory() + "\\" + GetFileNameWithExtension(input_file_name)

        # Get the input bits from the input file name
        startupInfo.InputBitArray = MyBitArray()
        startupInfo.InputBitArray.FromBytes(ReadByteDataFile(input_file_name))

        # Retrieve the key bit array from the key file
        startupInfo.KeyBitArray = MyBitArray()
        startupInfo.KeyBitArray.FromBytes(ReadByteDataFile(key_file_name))

        # Open an output file handler
        outputFileName = GetScriptDirectory() + output_file_name
        # Append file extension if necessary
        if len(outputFileName.split(".")) < 2:
            outputFileName += ".txt"
        startupInfo.OutputFileHandler = open(outputFileName, "wb")
        
        # Record the mode of operation
        startupInfo.ModeOfOperation = DESModes.GetEncryptionMode(mode_string)

        # Record whether an encryption is taking place or not
        if is_encryption != True and is_encryption != False:
            if is_encryption.lower() == "true":
                startupInfo.IsEncryption = True
            elif is_encryption.lower() == "false":
                startupInfo.IsEncryption = False
            else:
                raise ValueError("Inappropriate is_encryption value passed.")
        else:
            startupInfo.IsEncryption = is_encryption
        return startupInfo

    ######################################
    #            METHODS
    ######################################
    def close(self):
        try:
            self.OutputFileHandler.close()
        except AttributeError:
            print("Output file handler failed to close.")

######################################
#               MAIN
######################################
if __name__ == "__main__":
    print("Running Main for DESStartupInfo module.")
    startup_info = DESStartupInfo.RetrieveDESStartupInfo("TestInput.txt", "TestPassword.txt", "TestOutput", "Cipher block chain", "TrUe")
    print("For the file stored at...")
    print(startup_info.InputFilePath)
    print("The input bit array looks like...")
    print(startup_info.InputBitArray)
    print("The key bit array looks like...")
    print(startup_info.KeyBitArray)
    print("The output file handler's name is...")
    print(startup_info.OutputFileHandler.name)
    print("The mode of operation is...")
    print(startup_info.ModeOfOperation)
    print("And the recorded state is encryption...?")
    print(startup_info.IsEncryption)
