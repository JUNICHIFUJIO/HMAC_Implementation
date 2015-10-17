# Section for allowing import of custom classes
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

######################################
#            CLASS START
######################################
# Takes a series of bytes or bits and converts them to a manageable list of bits
class MyBitArray:
    ######################################
    #            CONSTRUCTOR
    ######################################
    def __init__(self):
        self.bits = []

    ######################################
    #            METHODS
    ######################################

    # Converts an iterable of bytes to bits and stores them.
    def FromBytes(self, bytes_):
        self.bits = [0] * (len(bytes_) * 8) # ERROR TESTING should make an array of 0s
                
        bitIndex = 0
        for byte in bytes_:
            for i in reversed(range(8)):
                if(byte & (1 << i) != 0):
                    self.bits[bitIndex] = 1
                else:
                    self.bits[bitIndex] = 0
                bitIndex += 1

    # Stores the iterable of bits inside.
    def FromBits(self, bits):
        self.bits = bits.copy()

    # Converts stored bits to bytes array.
    # Returns fresh MyBitArray holding bytes.
    def ToBytes(self):
        result = bytearray()
        byteIndex = 0
        bitIndex = 0
        while (byteIndex * 8) < len(self):
            theBits = self.bits[bitIndex : bitIndex + 8]
            result.append(0)
            for i in range(8):
                result[byteIndex] = result[byteIndex] | (theBits[i] << (len(theBits) - 1 - i))
                bitIndex += 1
            byteIndex += 1

        return bytes(result)

    # Appends a single bit to the bit array.
    # Raises ValueError if bit isn't a 1 or 0.
    def append(self, bit):
        if int(bit) == 1 or int(bit) == 0:
            self.bits.append(bit)
        else:
            raise ValueError("Passed in bit was not a 1 or 0")

    # Appends all bits in the passed in bit array to this bit array.
    def extend(self, bit_array):
        try:
            self.bits.extend(bit_array.bits)
        except AttributeError:
            self.bits.extend(bit_array)

    # Returns a fresh MyBitArray that contains this bit array's bits rotated
    # to the left by n_rotations.
    def RotateLeft(self, n_rotations = 1):
        try:
            n_rotations %= len(self.bits)
            shiftedBits = MyBitArray()
            shiftedBits.extend(self.bits[n_rotations:])
            shiftedBits.extend(self.bits[:n_rotations])
            return shiftedBits
        except (ZeroDivisionError, IndexError) as error:
            return MyBitArray()

    # Returns a fresh MyBitArray that contains this bit array's bits rotated
    # to the right by n_rotations.
    def RotateRight(self, n_rotations = 1):
        try:
            n_rotations %= len(self.bits)
            shiftedBits = MyBitArray()
            shiftedBits.extend(self.bits[len(self.bits)-n_rotations:])
            shiftedBits.extend(self.bits[:len(self.bits)-n_rotations])
            return shiftedBits
        except (ZeroDivisionError, IndexError) as error:
            return MyBitArray()

    ######################################
    #           BUILT-IN METHODS
    ######################################
    def __len__(self):
        return len(self.bits)
        
    def __getitem__(self, key):
        return self.bits[key]

    def __setitem__(self, index, value):
        self.bits[index] = value

    def __copy__(self):
        copy = type(self)()
        copy.FromBits(copy.copy(self.bits))
        return copy

    def __deepcopy__(self, memo):
        deepcopy = type(self)()
        deepcopy.FromBits(copy.deepcopy(self.bits, memo))
        return deepcopy

    def __reversed__(self):
        return self.MyReverseBitArrayIterator(self.bits)
                                   
    def __xor__(self, other):
        result = MyBitArray()
        shorterArr = self
        longerArr = other
        if len(other) < len(self):
            shorterArr = other
            longerArr = self

        shorterIndex = len(shorterArr) - 1
        longerIndex = len(longerArr) - 1

        while True:
            if shorterIndex >= 0 and longerIndex >= 0:
                XORBit = shorterArr[shorterIndex] ^ longerArr[longerIndex]
                shorterIndex -= 1
                longerIndex -= 1
            elif longerIndex >= 0:
                XORBit = longerArr[longerIndex]
                longerIndex -= 1
            else:
                break

            result.bits.insert(0, XORBit)

        return result

    def __str__(self):
        string = "["
        if len(self) > 0:
            string += self.bits[0].__str__()
            index = 1
            while index < len(self):
                string += ", "
                if index % 8 == 0:
                    string += "| "
                string += self.bits[index].__str__()
                index += 1
        string += "]"

        return string

    ######################################
    #            ITERATOR
    ######################################
    def __iter__(self):
        return self.MyBitArrayIterator(self.bits)

    ######################################
    #            SUB CLASSES
    ######################################
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

    class MyReverseBitArrayIterator:
        def __init__(self, bits):
            self.index = len(bits) - 1
            self.bits = bits

        def __iter__(self):
            return self

        def __next__(self):
            try:
                result = self.bits[self.index]
            except IndexError:
                raise StopIteration
            self.index -= 1
            return result

######################################
#               MAIN
######################################
if __name__ == "__main__":
    print("Running Main for MyBitArray!")
    BitArray = MyBitArray()
    BitArray.FromBytes(bytes([120, 18, 94]))
    print(BitArray)
    print(BitArray.ToBytes())
    BitArray.FromBytes(BitArray.ToBytes())
    print(BitArray.ToBytes())
    print("Testing RotateLeft method:")
    print(BitArray.RotateLeft())
    print("Testing RotateLeft method with 3 rotations:")
    print(BitArray.RotateLeft(3))
    print("Testing original Bit array")
    print(BitArray)
    print()
    print("Testing __len__()")
    print(len(BitArray))
    print("Testing __reversed__()")
    print(reversed(BitArray))
    print("Testing __xor__()")
    OtherBitArray = MyBitArray()
    OtherBitArray.FromBytes(bytes([8, 0, 0]))
    print((BitArray ^ OtherBitArray))
    BitArray.append(1)
    print(BitArray)
    try:
        BitArray.append(8)
        print(BitArray)
    except ValueError:
        print("Value Error correctly raised for append method")
