# Author: Thomas Brown
# S# 0821288
# 11/15/15
#
# Generates a hash using the SHA256 algorithm and a given message.
# (Not very fast or efficient, sorry.

import sys
import os

if sys.path[0] != os.path.dirname(os.path.realpath(sys.argv[0])):
    sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

######################################
#               IMPORTS              #
######################################
from MyBitArray import MyBitArray
from MyHexHandler import *
import hashlib                  # For comparing results in the test mainframe

class MySHA256:
    '''Generates a hash using the SHA256 algorithm and a given message.'''
    ######################################
    #           CLASS VARIABLES          #
    ######################################
    aInit = "6a09e667"
    bInit = "bb67ae85"
    cInit = "3c6ef372"
    dInit = "a54ff53a"
    eInit = "510e527f"
    fInit = "9b05688c"
    gInit = "1f83d9ab"
    hInit = "5be0cd19"
    nRounds = 64
    nWordBits = 32
    blockLength = 512
    outputLength = 256

    
    def resetHashInits(self):
        self.a = MySHA256.aInit
        self.b = MySHA256.bInit
        self.c = MySHA256.cInit
        self.d = MySHA256.dInit
        self.e = MySHA256.eInit
        self.f = MySHA256.fInit
        self.g = MySHA256.gInit
        self.h = MySHA256.hInit
        
    ######################################
    #        MESSAGE MANIPULATION        #
    ######################################
    def messageLengthToBytes(message_bytes):
        '''Returns several (8 by default) bytes signifying the length of the passed
           in message in number of bits.'''
        # Guard conditions
        if MySHA256.outputLength <= 0:
            raise ValueError("MySHA256 output length should be set to 256, but is set to a negative or zero value.")

        expectedByteLength = 8
        
        # Calculate the original message length and convert its bit length into
        # byte format
        divisor = 1
        originalMessageLengthBytes = bytearray()
        while divisor <= (len(message_bytes) * 8):
            originalMessageLengthBytes.insert(0, int(len(message_bytes) * 8 % (divisor * MySHA256.outputLength) / divisor))
            divisor = divisor * MySHA256.outputLength

        # Expand the byte array to have 0s in the front as necessary
        if len(originalMessageLengthBytes) < expectedByteLength:
            for i in range(expectedByteLength - len(originalMessageLengthBytes)):
                originalMessageLengthBytes.insert(0, 0)

        return originalMessageLengthBytes

    def padMessage(message_bytes):
        ''' Pads a given byte array of a message with a 1 followed by 0s and finally the length
            of the original message in the last 8 bytes of the last message block.
            '''
        lastMessageBitIndex = 448

        # Guard conditions        
        if MySHA256.blockLength < 0:
            raise ValueError("MySHA256 block length should be set to 512, but is set to a negative number.")

        originalMessageLengthBytes = MySHA256.messageLengthToBytes(message_bytes)
        if len(originalMessageLengthBytes) > (MySHA256.blockLength - lastMessageBitIndex):
            raise ValueError("MySHA256 cannot process a message of this length.")

        # Get length of block in bytes
        lastBlockLength = (len(message_bytes) % (int(MySHA256.blockLength/8)))
        nZeroes = lastMessageBitIndex - 1 - (lastBlockLength * 8)

        if nZeroes < 0:
            # Add a whole block of padding if necessary, to fit with the padding scheme
            nZeroes = MySHA256.blockLength + nZeroes - 1
        
        # Add padding
        messageBitArray = MyBitArray()
        messageBitArray.FromBytes(message_bytes)
        messageBitArray.extend([1])
        messageBitArray.extend([0] * nZeroes)

        # Append length of the original message
        result = bytearray(messageBitArray.ToBytes())
        result.extend(originalMessageLengthBytes)

        return bytes(result)

    ######################################
    #       MATHEMATICAL OPERATIONS      #
    ######################################
    def sigma0(word_bytes):
        '''Static method.
           Calculates the sigma0 value of the given word, assuming that the word
           is an array of bytes.

           Returns a bytes array of the result.'''
        wordBits = MyBitArray()
        wordBits.FromBytes(word_bytes)

        return (wordBits.RotateRight(7) ^ wordBits.RotateRight(18) ^ wordBits.SHR(3)).ToBytes()

    def sigma1(word_bytes):
        '''Static method.
           Calculates the sigma1 value of the given word, assuming that the word
           is an array of bytes.

           Returns a byte array of the result.'''
        wordBits = MyBitArray()
        wordBits.FromBytes(word_bytes)

        return (wordBits.RotateRight(17) ^ wordBits.RotateRight(19) ^ wordBits.SHR(10)).ToBytes()

    def AddModulo(a, b):
        '''Static method.
           Adds together a series of bytes representing a large number while ignoring
           any changes that extend beyond the length of the passed in byte arrays.

           Returns a bytearray of the result.'''
        # Guard conditions
        if len(a) != len(b):
            raise ValueError("MySHA256 encountered an error when performing modular arithmetic.")

        result = bytearray()
        carryover = 0
        for i in reversed(range(len(a))):
            try:
                byteresult = a[i] + b[i]
            except TypeError:
                return (a + b + carryover) % MySHA256.outputLength

            result.insert(0, (byteresult + carryover) % MySHA256.outputLength)
            if (byteresult + carryover) / MySHA256.outputLength >= 1:
                carryover = 1
            else:
                carryover = 0

        return result

    def Wi(self, i):
        '''Calculates the word with the given index. Assumes all words before
           the desired word are calculated already. Invalid for any 'i' index
           less than 16 or the expected # of rounds for the algorithm.

           Returns a byte array that represents the word.'''
        if i < 16 or i > MySHA256.nRounds:
            raise ValueError("MySHA256 encountered an internal error when processing the words.")

        x = MySHA256.AddModulo(WordsToBytes(self.words[i-7]), MySHA256.sigma1(WordsToBytes(self.words[i-2])))
        y = MySHA256.AddModulo(MySHA256.sigma0(WordsToBytes(self.words[i-15])), x)
        result = MySHA256.AddModulo(WordsToBytes(self.words[i - 16]), y)

        return result
    
    def __initializeWords(self, message_block_bytes):
        '''Calculates and assigns all words.'''
        # Guard conditions
        if len(message_block_bytes) != int(MySHA256.blockLength / 8):
            raise ValueError("MySHA256 encountered an internal message blocking error.")

        # Get first 16 from message bytes
        for i in range(16):
            self.words[i] = BytesToWords(message_block_bytes[i * 4 : (i + 1) * 4])

        # Get remaining 48 from Wi formula
        for i in range(16, 64):
            self.words[i] = BytesToWords(self.Wi(i))

    def __clearWords(self):
        '''Resets all stored words.'''
        for i in range(len(self.words)):
            self.words[i] = ""

    def Ch(self):
        '''Calculates the Ch (choose?) equation.

           Returns a bytes array of the result.'''
        eBytes = WordsToBytes(self.e)
        fBytes = WordsToBytes(self.f)
        gBytes = WordsToBytes(self.g)

        if len(eBytes) != len(fBytes) or len(fBytes) != len(gBytes):
            raise ValueError("SHA256 Ch method failed. Invalid variable states.")

        result = bytearray()
        for i in range(len(eBytes)):
            result.append((eBytes[i] & fBytes[i]) ^ ((~eBytes[i]) & gBytes[i]))

        return bytes(result)

    def Maj(self):
        '''Calculates the Maj (Majority?) equation.

           Returns a byte array of the result.'''
        aBytes = WordsToBytes(self.a)
        bBytes = WordsToBytes(self.b)
        cBytes = WordsToBytes(self.c)

        if len(aBytes) != len(bBytes) or len(bBytes) != len(cBytes):
            raise ValueError("SHA256 Maj method failed. Invalid variable states.")

        result = bytearray()
        for i in range(len(aBytes)):
            part1 = aBytes[i] & bBytes[i]
            part2 = aBytes[i] & cBytes[i]
            part3 = bBytes[i] & cBytes[i]
            conj1 = part1 ^ part2
            conj2 = conj1 ^ part3
            result.append(conj2)

        return result

    def Epsilon0(word_bytes):
        '''Static method.
           Calculates the Epsilon0 equation.

           Returns a byte array of the result.'''
        bitArray = MyBitArray()
        bitArray.FromBytes(word_bytes)

        result = bitArray.RotateRight(2) ^ bitArray.RotateRight(13) ^ bitArray.RotateRight(22)

        return result.ToBytes()

    def Epsilon1(word_bytes):
        '''Static method.
           Calculates the Epsilon1 equation.

           Returns a byte array of the result.'''
        bitArray = MyBitArray()
        bitArray.FromBytes(word_bytes)

        result = bitArray.RotateRight(6) ^ bitArray.RotateRight(11) ^ bitArray.RotateRight(25)

        return result.ToBytes()

    def T1(self, i):
        '''Calculates the T1 equation.

           Returns a byte array of the result.'''
        x = MySHA256.AddModulo(WordsToBytes(self.K[i]), WordsToBytes(self.words[i]))
        y = MySHA256.AddModulo(self.Ch(), x)
        z = MySHA256.AddModulo(MySHA256.Epsilon1(WordsToBytes(self.e)), y)
        result = MySHA256.AddModulo(WordsToBytes(self.h), z)

        return result

    def T2(self, i):
        '''Calculates the T2 equation.

           Returns a byte array of the result.'''
        return MySHA256.AddModulo(MySHA256.Epsilon0(WordsToBytes(self.a)), self.Maj())

######################################
#           HASHING METHODS          #
######################################

    def __hashMessageBlock(self, message_block_bytes):
        '''Hashes the message block using my custom SHA256 class.
           Sets the class object's a through h fields to the proper values
           while cycling through the rounds necessary. Does not return anything.'''
        self.__initializeWords(message_block_bytes)
        for i in range(MySHA256.nRounds):
            # Update a through h
            T1 = self.T1(i)
            T2 = self.T2(i)

            self.h = self.g
            self.g = self.f
            self.f = self.e
            self.e = BytesToWords(MySHA256.AddModulo(WordsToBytes(self.d), T1))        
            self.d = self.c
            self.c = self.b
            self.b = self.a
            self.a = BytesToWords(MySHA256.AddModulo(T1, T2))        

    def __hashMessage(self, processed_message_bytes):
        '''The meat of the HMAC hashing algorithm. Takes a whole message.

           Returns the final hash in bytes.'''
        nBlockBytes = int(MySHA256.blockLength / 8)
        hashBytes = bytearray()

        # Initialize hash values
        h0 = MySHA256.aInit
        h1 = MySHA256.bInit
        h2 = MySHA256.cInit
        h3 = MySHA256.dInit
        h4 = MySHA256.eInit
        h5 = MySHA256.fInit
        h6 = MySHA256.gInit
        h7 = MySHA256.hInit
        
        byteIndex = 0
        # Repeatedly process the message blocks
        while byteIndex < len(processed_message_bytes):            
            # Hash the block
            messageBlockBytes = bytearray(processed_message_bytes[byteIndex : byteIndex + nBlockBytes])
            self.__hashMessageBlock(messageBlockBytes)

            # Update the a through h
            h0 = BytesToWords(MySHA256.AddModulo(WordsToBytes(self.a), WordsToBytes(h0)))
            h1 = BytesToWords(MySHA256.AddModulo(WordsToBytes(self.b), WordsToBytes(h1)))
            h2 = BytesToWords(MySHA256.AddModulo(WordsToBytes(self.c), WordsToBytes(h2)))
            h3 = BytesToWords(MySHA256.AddModulo(WordsToBytes(self.d), WordsToBytes(h3)))
            h4 = BytesToWords(MySHA256.AddModulo(WordsToBytes(self.e), WordsToBytes(h4)))
            h5 = BytesToWords(MySHA256.AddModulo(WordsToBytes(self.f), WordsToBytes(h5)))
            h6 = BytesToWords(MySHA256.AddModulo(WordsToBytes(self.g), WordsToBytes(h6)))
            h7 = BytesToWords(MySHA256.AddModulo(WordsToBytes(self.h), WordsToBytes(h7)))

            # Update a through h
            self.a = h0
            self.b = h1
            self.c = h2
            self.d = h3
            self.e = h4
            self.f = h5
            self.g = h6
            self.h = h7

            # Increment the block byte index
            byteIndex += nBlockBytes

        # Calculate the final hash
        finalHashParts = [self.a, self.b, self.c, self.d, self.e, self.f, self.g, self.h]
        for hashPart in finalHashParts:
            hashPartBytes = WordsToBytes(hashPart)
            for byte in hashPartBytes:
                hashBytes.append(byte)

        # Reset a through h
        self.resetHashInits()
        
        return hashBytes

    def hash(self, message):
        '''Runs the hashing algorithm given the message.

           Returns the final hash in bytes.'''
        # reset variables
        self.resetHashInits()
        self.words = [""] * MySHA256.nRounds

        # Convert the message into an array of bytes for easy parsing
        messageBytes = message.encode('utf-8')
        processedMessageBytes = MySHA256.padMessage(message.encode('utf-8'))
        
        processedMessageBits = MyBitArray()
        processedMessageBits.FromBytes(processedMessageBytes)

        # Hash the message
        result = self.__hashMessage(processedMessageBytes)

        # reset variables again
        self.resetHashInits()
        self.words = [""] * MySHA256.nRounds

        return result

    def hexdigest(hash_bytes):
        '''Converts the hash bytes to a string of hexadecimal characters without
           the '0x' prefix.'''
        return BytesToWords(hash_bytes)

    def __init__(self):
        '''Constructor that initializes object-specific fields.'''
        self.resetHashInits()
        self.words = [""] * MySHA256.nRounds

        # The keys used to break up patterns in the message block
        self.K = [
            "428a2f98", "71374491", "b5c0fbcf", "e9b5dba5", "3956c25b", "59f111f1", "923f82a4", "ab1c5ed5",
            "d807aa98", "12835b01", "243185be", "550c7dc3", "72be5d74", "80deb1fe", "9bdc06a7", "c19bf174",
            "e49b69c1", "efbe4786", "0fc19dc6", "240ca1cc", "2de92c6f", "4a7484aa", "5cb0a9dc", "76f988da",
            "983e5152", "a831c66d", "b00327c8", "bf597fc7", "c6e00bf3", "d5a79147", "06ca6351", "14292967",
            "27b70a85", "2e1b2138", "4d2c6dfc", "53380d13", "650a7354", "766a0abb", "81c2c92e", "92722c85",
            "a2bfe8a1", "a81a664b", "c24b8b70", "c76c51a3", "d192e819", "d6990624", "f40e3585", "106aa070",
            "19a4c116", "1e376c08", "2748774c", "34b0bcb5", "391c0cb3", "4ed8aa4a", "5b9cca4f", "682e6ff3",
            "748f82ee", "78a5636f", "84c87814", "8cc70208", "90befffa", "a4506ceb", "bef9a3f7", "c67178f2"]


######################################
#            MAIN TESTING            #
######################################
if __name__ == "__main__":
    print("Running main for MySHA256 module.")
    print("Module found in...")
    print(os.path.dirname(os.path.realpath(sys.argv[0])))
    print()

    message = "This is a test message."
    messageBytes = bytes(message.encode("utf-8"))
    
    print("Testing messageLengthToBytes static method with message '" + message + "'")
    messageLengthBytes = MySHA256.messageLengthToBytes(messageBytes)
    print(messageLengthBytes)
    print("\t(len = " + str(len(messageLengthBytes)) + ")")
    print("\tvalue = " + str(int(messageLengthBytes[len(messageLengthBytes) - 1])) + " bits.")
    print("Real length of the message: " + str(messageBytes) + " = " + str(len(bytes(message.encode("utf-8")))) + " bytes (" + str(len(messageBytes) * 8) + " bits)")
    print()

    print("Testing padMessage static method with message '" + message + "'")
    paddedMessage = MySHA256.padMessage(messageBytes)
    print("\tpadded message = " + str(paddedMessage))
    print("\tlen = " + str(len(paddedMessage)) + " (should be multiple of " + str(int(MySHA256.blockLength / 8)) + ")")
    print()
    print("Testing padMessage static method with an empty message.")
    emptyPaddedMessage = MySHA256.padMessage(bytes())
    print("\tpadded message = " + str(emptyPaddedMessage))
    print("\tlen = " + str(len(emptyPaddedMessage)) + " (should be multiple of " + str(int(MySHA256.blockLength / 8)) + ")")
    print()

    print("Testing AddModulo static method with message '" + message + "' and empty message.")
    print(MySHA256.AddModulo(paddedMessage, emptyPaddedMessage))
    print("\t(original message remains " + str(messageBytes) + ")")
    print()
    print("Testing AddModulo static method using message '" + message + "' twice.")
    print(MySHA256.AddModulo(paddedMessage, paddedMessage))
    print("\tThe original ints were...")
    messageInts = []
    messageInts.extend(int(x) for x in paddedMessage)
    print(str(messageInts))
    print("\tThe double ints are (before modulo)...")
    messageIntsDoubled = []
    messageIntsDoubled.extend(int(x*2) for x in paddedMessage)
    print(str(messageIntsDoubled))
    intenseCarryover1 = bytes([255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255])
    intenseCarryover2 = bytes([24, 89, 11, 0, 1, 2, 1, 1, 1, 1, 99])
    print("\tTesting intense carryover with " + str(intenseCarryover1) + " and " + str(intenseCarryover2))
    print("\tOriginal ints are :")
    intenseCarryover1Ints = []
    intenseCarryover1Ints.extend(int(x) for x in intenseCarryover1)
    print("\t" + str(intenseCarryover1Ints))
    intenseCarryover2Ints = []
    intenseCarryover2Ints.extend(int(x) for x in intenseCarryover2)
    print("\t" + str(intenseCarryover2Ints))
    print(MySHA256.AddModulo(intenseCarryover1, intenseCarryover2))
    intenseCarryoverInts = []
    intenseCarryoverInts.extend(int(x) for x in MySHA256.AddModulo(intenseCarryover1, intenseCarryover2))
    print(intenseCarryoverInts)

    #testMessage = ""
    #testMessage = "abc"
    testMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    print("Testing actual MySHA256 algorithm with message '" + testMessage + "'")
    mysha = MySHA256()
    print(str(BytesToWords(mysha.hash(testMessage))))
    print("Real SHA256 produces...")
    print(hashlib.sha256(testMessage.encode("utf-8")).hexdigest())
