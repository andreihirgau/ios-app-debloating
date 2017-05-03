from capstone import *
from keystone import *
import sys

CODE = b"NOP"

def parse_and_replace(fn, new_fn):
    file = open(fn, 'rb')
    ofile = open(new_fn, 'wb')

    bin1 = file.read(0xE0F)
    ofile.write(bin1)

    i = 0

    while i < 0xb2:
        ba = bytearray(test_nop())
        ofile.write(ba)
        i += 1

    file.seek(0xb2, 1)
    bin2 = file.read()
    ofile.write(bin2)

    file.close()
    ofile.close()

def test_nop():
    try:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        encoding, count = ks.asm(CODE)
        return encoding
        #print("%s = %s (number of statements: %u)" %(CODE, encoding, count))
    except KsError as e:
        print("ERROR: %s" %e)

def main():
    file = open(sys.argv[1])
    file.seek(0xe10)

    binary = file.read(0xb2)
    mi = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in mi.disasm(binary, 0):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

if __name__ == "__main__":
    test_nop()
    parse_and_replace(sys.argv[1], sys.argv[2])
    main()
