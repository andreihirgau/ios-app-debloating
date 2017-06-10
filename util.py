import struct

ADDR = 0
SIZE = 1
DIFF = 2
PREV_FUNC = 3

ULEB_DATA = 0
ULEB_OFF = 1

PAGE_SIZE = 4096

def big_swap_u32(i):
	return struct.unpack("<I", struct.pack(">I", i))[0]
def big_swap_u8(i):
	return struct.unpack("<B", struct.pack(">B", i))[0]
def big_swap_16(i):
	return struct.unpack("<h", struct.pack(">h", i))[0]
def big_swap_u64(i):
	return struct.unpack("<Q", struct.pack(">Q", i))[0]
	
def little_swap_u32(i):
	return struct.unpack("<I", struct.pack(">I", i))[0]
def little_swap_u8(i):
	return struct.unpack("<B", struct.pack(">B", i))[0]
def little_swap_16(i):
	return struct.unpack("<h", struct.pack(">h", i))[0]
def little_swap_u64(i):
	return struct.unpack("<Q", struct.pack(">Q", i))[0]

def decode_uleb128(ba, start):
	more = True
	i = start
	decoded = 0
	shift = 0

	while True:
		byte = ba[i]
		i += 1
		decoded = decoded | ((byte & 0x7f) << shift)
		shift += 7
		if byte < 0x80:
			more = False
		if not more:
			break

	return (decoded, i)

def encode_uleb128(value, start):
	enc = bytearray()

	while True:
		byte = value & 0x7f
		
		value >>= 7
		if value != 0:
			byte |= 0x80

		enc += bytes(byte)

		if value == 0:
			break

	return enc
