# Section for allowing import of custom classes
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

# imports

# Easier to read way to access the top level executable's script path
# Useful for locating modules/files
def GetScriptDirectory():
    return os.path.dirname(os.path.realpath(sys.argv[0]))

# Get the file's name without the extension or directory path
def GetFileName(path):
    fileNameWithExtension = GetFileNameWithExtension(path)
    fileName = fileNameWithExtension.split(".")[0]

    return fileName

# Get the file's name with the extension but without the directory path
def GetFileNameWithExtension(path):
    directories = path.split("\\")
    fileNameWithExtension = directories[len(directories) - 1]

    return fileNameWithExtension

# Get the file's extension as a string
def GetFileExtension(file_name):
    fileExtension = file_name.split(".")[0]

    return fileExtension

# Writes a binary file with the given file name, complete with extension
# Returns the name of the file written
def WriteByteDataFile(data_file_name, data):
    directoryPath = GetScriptDirectory() + "\\"
    dataFileName = GetFileNameWithExtension(data_file_name)

    # append .txt if there's no file extension given
    if len(dataFileName.split(".")) < 2:
        # if there's no extension for the file name...
        dataFileName += ".txt"

    # open and write to the file
    file = open(directoryPath + dataFileName, "wb")
    file.write(data)
    file.close()

    return dataFileName

# Read a binary file with the given file name and return an array of bytes
# Returns the array of bytes held in the file
def ReadByteDataFile(data_file_name):
    directoryPath = GetScriptDirectory() + "\\"
    dataFileName = GetFileNameWithExtension(data_file_name)

    # append .txt if there's no file extension given
    if len(dataFileName.split(".")) < 2:
        # if there's no extension for the file name...
        dataFileName += ".txt"
        
    file = open(directoryPath + dataFileName, "rb")
    result = file.read()
    file.close()

    return result
