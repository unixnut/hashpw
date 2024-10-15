from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

from ...errors import Yescrypt64StringReaderException, Yescrypt64StringWriterException


# *** CLASSES ***
class B64StringReader:
    atoi64_partial = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        64, 64, 64, 64, 64, 64, 64,
        12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
        64, 64, 64, 64, 64, 64,
        38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
        51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
        ]

    encodedValue: bytes
    currentIndex: int


    @classmethod
    def atoi64(context, val: int) -> int:
        """
        Convert a byte (C-style char) to a decoded byte
        """

        if val >= ord('.') and val <= ord('z'):
            return context.atoi64_partial[val - ord('.')]
        else:
            return 64


    def __init__(self, encodedString: str):
        self.encodedValue = encodedString.encode('ascii')
        self.currentIndex = 0


    def readUint32Min(self, min: int) -> int:
        """
        Read a variable-length integer out of the encodedString.

        Does floor-conversion based on the expected minimum value.
        """

        rval: int
        start: int = 0
        end: int = 47
        chars: int = 1
        bits: int = 0

        c: int

        try:
            c = self.atoi64(self.encodedValue[self.currentIndex])
            self.currentIndex += 1
        except IndexError:
            raise Yescrypt64StringReaderException("Invalid 'have' byte or missing optional parameter (%s)" % self.encodedValue.decode('ascii'))
        if c > 63:
            raise Yescrypt64StringReaderException("Invalid encoding at index: " + self.currentIndex)

        rval = min
        while c > end:
            rval += (end + 1 - start) << bits
            start = end + 1
            end = start + (62 - end) / 2
            chars += 1
            bits += 6

        rval += (c - start) << bits

        for i in range(1, chars):
            c = self.atoi64(self.encodedValue[self.currentIndex])
            self.currentIndex += 1
            if c > 63:
                raise Yescrypt64StringReaderException("Invalid encoding at index: " + self.currentIndex)
            bits -= 6
            rval += c << bits

        return rval


    def readUint32Bits(self, valBits: int) -> int:
        """
        Read a fixed-length integer out of the encodedString.
        """

        rval: int = 0

        for bits in range(0, valBits, 6):
            c = self.atoi64(self.encodedValue[self.currentIndex])
            self.currentIndex += 1
            if c > 63:
                raise Yescrypt64StringReaderException("Invalid encoding at index: " + self.currentIndex)
            rval |= c << bits

        return rval


    def readBytes(self, length: int) -> bytes:
        """
        Read a byte string out of the encodedString.
        """

        rval: List[int] = []

        bitsAvailable = (len(self.encodedValue) - self.currentIndex) * 6
        bitsRequested = length * 8

        if bitsAvailable > bitsRequested:
            bits = bitsRequested
        else:
            bits = bitsAvailable

        while bits > 23:
            val = self.readUint32Bits(24)
            for i in range(0, 3):
                rval.append(val & 0xff)
                val >>= 8
            bits -= 24

        hasPadding: bool = False
        if bits > 0:
            hasPadding = True
            val = self.readUint32Bits(bits)
            for i in range(0, bits // 6):
                rval.append(val & 0xff)
                val >>= 8

        return bytes(rval)


    def hasMore(self) -> bool:
        return self.currentIndex < len(self.encodedValue)



class B64StringWriter:
    itoa64 = [ '.', '/', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
        'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
        'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
        'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
        'u', 'v', 'w', 'x', 'y', 'z' ]

    encodedValue: str


    def __init__(self):
        self.encodedValue = ""


    def writeUint32Min(self, val: int, valMin: int): # -> B64StringWriter
        """
        Append a variable-length encoded int to the encodedString.  The encoded
        value is floor-converted, i.e. first reduced by a floor given by @p valMin
        """

        start: int = 0
        end: int = 47
        chars: int = 1
        bits: int = 0

        if val < valMin:
            raise Yescrypt64StringWriterException("src (%d) must not be less than valMin (%d)" % (val, valMin))

        val -= valMin

        # Determine output char count and internal bit count
        while True:
            count = (end + 1 - start) << bits
            if val < count:
                break
            if start >= 63:
                raise Yescrypt64StringWriterException("Um... I crapped my pants")
            start = end + 1
            end = start + (62 - end) / 2
            val -= count
            chars += 1
            bits += 6

        # Output chars
        self.encodedValue += self.itoa64[start + (val >> bits)]
        for i in range(1, chars):
            bits -= 6
            self.encodedValue += self.itoa64[(val >> bits) & 0x3f]

        return self


    def writeUint32Bits(self, val: int, valBits: int): # -> B64StringWriter
        """
        Append an encoded fixed-length integer to the encodedString.
        """

        for bits in range(0, valBits, 6):
            self.encodedValue += self.itoa64[val & 0x3f]
            val >>= 6

        return self


    def writeBytes(self, b: bytes): # -> B64StringWriter
        i = 0
        while i < len(b):
            value = 0
            bits = 0

            while True:
                value |= b[i] << bits
                i += 1
                bits += 8
                if not (bits < 24 and i < len(b)):
                    break

            self.writeUint32Bits(value, bits)

        return self


    def appendString(self, s: str): # -> B64StringWriter
        self.encodedValue += s

        return self


    def getStr(self) -> str:
        return self.encodedValue


    def __str__(self) -> str:
        return self.getStr()
