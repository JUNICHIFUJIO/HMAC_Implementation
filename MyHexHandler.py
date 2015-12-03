# Author: Thomas Brown
# S# 0821288
# 11/15/15
#
# Converts between custom hexadecimal strings (ones without the '0x' prefix) and
# byte arrays.
import sys
import os

if sys.path[0] != os.path.dirname(os.path.realpath(sys.argv[0])):
    sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

######################################
#               IMPORTS              #
######################################
from MyBitArray import MyBitArray


######################################
#               METHODS              #
######################################
def WordsToBytes(words):
    ''' Transforms a series of two-hex words into an array of bytes.
        Primarily used for custom hex strings that don't begin with the
        '0x' prefix.

        Returns the result as a bytearray.
    '''
    result = bytearray()
    for i in range(int(len(words) / 2)):
        try:
            word = "0x" + words[2*i] + words[2*i+1]
        except IndexError:
            word = "0x" + words[2 * i]

        byte = int(word, 16)

        result.append(byte)

    if len(words) % 2 != 0:
        word = "0x0" + words[len(words) - 1]
        byte = int(word, 16)
        result.append(byte)

    return result

def BytesToWords(bytearr):
    '''Transforms an array of bytes into a string of hexadecimal words without
       the '0x' prefix.

       Returns a string of hexadecimal words without the '0x' prefix.'''
    result = ""

    for byte in bytearr:
        wordPair = hex(byte)[2:]
        if len(wordPair) < 2:
            wordPair = "0" + wordPair

        result += wordPair

    return result

######################################
#           MAIN TESTING             #
######################################
if __name__ == "__main__":
    print("Running main for MyHexHandler.")
    print("File found in...")
    print(os.path.dirname(os.path.realpath(sys.argv[0])))
    print()
    
    print("************************")
    validString = '1938fa'
    print("Testing MyHexHandler using string " + validString)
    print("Testing WordsToBytes function:")
    byteArray = WordsToBytes(validString)
    print(byteArray)
    print()

    print("(Individual bytes:")
    for i in range(len(byteArray)):
        print("\t" + str(i) + ")\t" + str(byteArray[i]))
    print("\t\t  )")
    print()
    
    print("Testing BytesToWords function:")
    words = BytesToWords(byteArray)
    print(words)
    print()

    print("************************")
    irregularString = validString[:len(validString)-1]
    print("Testing functions with irregularly sized hex string " + irregularString)
    byteArray = WordsToBytes(irregularString)
    print(byteArray)
    print()
    print("Testing BytesToWords with irregularly sized hex string " + irregularString)
    words = BytesToWords(byteArray)
    print(words)
    print()

    print("************************")
    invalidString = "mcj1o"
    print("Testing MyHexHandler using string " + invalidString)
    try:
        byteArray = WordsToBytes(invalidString)
        print(byteArray)
    except ValueError:
        print("ValueError encountered, as expected.")
    print()
    
