from macholib.ptypes import *
from util import *

NLIST64_SIZE = 16
NLIST32_SIZE = 12

class la_ptr(Structure):
	_fields_ = (
		('ptr', p_ulonglong),
	)

class nlist_32(Structure):
	_fields_ = (
		('n_un', p_uint),
		('n_type', p_ubyte),
		('n_sect', p_ubyte),
		('n_desc', p_short),
		('n_value', p_ulong)
	)

class nlist_64(Structure):
	_fields_ = (
		('n_un', p_uint),
		('n_type', p_ubyte),
		('n_sect', p_ubyte),
		('n_desc', p_short),
		('n_value', p_ulonglong)
	)

def swap_nlist64_mem(nlist):
	ret = nlist_64()
	ret.n_un = big_swap_u32(nlist.n_un)
	ret.n_type = big_swap_u8(nlist.n_type)
	ret.n_sect = big_swap_u8(nlist.n_sect)
	ret.n_desc = big_swap_16(nlist.n_desc)
	ret.n_value = big_swap_u64(nlist.n_value)
	return ret

def swap_nlist64_file(nlist):
	ret = nlist_64()
	ret.n_un = little_swap_u32(nlist.n_un)
	ret.n_type = little_swap_u8(nlist.n_type)
	ret.n_sect = little_swap_u8(nlist.n_sect)
	ret.n_desc = little_swap_16(nlist.n_desc)
	ret.n_value = little_swap_u64(nlist.n_value)
	return ret

def swap_nlist32_mem(nlist):
	ret = nlist_32()
	ret.n_un = big_swap_u32(nlist.n_un)
	ret.n_type = big_swap_u8(nlist.n_type)
	ret.n_sect = big_swap_u8(nlist.n_sect)
	ret.n_desc = big_swap_16(nlist.n_desc)
	ret.n_value = big_swap_u32(nlist.n_value)
	return ret

def swap_nlist32_file(nlist):
	ret = nlist_32()
	ret.n_un = little_swap_u32(nlist.n_un)
	ret.n_type = little_swap_u8(nlist.n_type)
	ret.n_sect = little_swap_u8(nlist.n_sect)
	ret.n_desc = little_swap_16(nlist.n_desc)
	ret.n_value = little_swap_u32(nlist.n_value)
	return ret
