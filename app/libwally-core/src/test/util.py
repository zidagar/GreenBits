from ctypes import *
from binascii import hexlify, unhexlify
from os.path import isfile
import platform
import sys

# Allow to run from any sub dir
SO_EXT = 'dylib' if platform.system() == 'Darwin' else 'so'
for depth in [0, 1, 2]:
    root_dir = '../' * depth
    if isfile(root_dir + 'src/.libs/libwallycore.' + SO_EXT):
        break

libwally = CDLL(root_dir + 'src/.libs/libwallycore.' + SO_EXT)

wally_free_string = libwally.wally_free_string
wally_free_string.restype, wally_free_string.argtypes = None, [c_char_p]

WALLY_OK, WALLY_ERROR, WALLY_EINVAL, WALLY_ENOMEM = 0, -1, -2, -3

class ext_key(Structure):
    _fields_ = [("chain_code", c_ubyte * 32),
                ("parent160", c_ubyte * 20),
                ("depth", c_ubyte),
                ("pad1", c_ubyte * 10),
                ("priv_key", c_ubyte * 33),
                ("child_num", c_uint),
                ("hash160", c_ubyte * 20),
                ("version", c_uint),
                ("pad2", c_ubyte * 3),
                ("pub_key", c_ubyte * 33)]

# Sentinel classes for returning output parameters
class c_char_p_p_class(object):
    pass
c_char_p_p = c_char_p_p_class()
class c_ulong_p_class(object):
    pass
c_ulong_p = c_ulong_p_class()

# ctypes is missing this for some reason
c_uint_p = POINTER(c_uint)

for f in (
    ('wordlist_init', c_void_p, [c_char_p]),
    ('wordlist_lookup_word', c_ulong, [c_void_p, c_char_p]),
    ('wordlist_lookup_index', c_char_p, [c_void_p, c_ulong]),
    ('wordlist_free', None, [c_void_p]),
    ('mnemonic_from_bytes', c_char_p, [c_void_p, c_void_p, c_ulong]),
    ('mnemonic_to_bytes', c_int, [c_void_p, c_char_p, c_void_p, c_ulong, c_ulong_p]),
    ('base58_from_bytes', c_int, [c_void_p, c_ulong, c_uint, c_char_p_p]),
    ('base58_get_length', c_int, [c_char_p, c_ulong_p]),
    ('base58_to_bytes', c_int, [c_char_p, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('bip32_key_from_seed', c_int, [c_void_p, c_ulong, c_uint, POINTER(ext_key)]),
    ('bip32_key_serialize', c_int, [POINTER(ext_key), c_uint, c_void_p, c_ulong]),
    ('bip32_key_unserialize', c_int, [c_void_p, c_uint, POINTER(ext_key)]),
    ('bip32_key_from_parent', c_int, [c_void_p, c_uint, c_uint, POINTER(ext_key)]),
    ('bip32_key_from_parent_path', c_int, [c_void_p, c_uint_p, c_ulong, c_uint, POINTER(ext_key)]),
    ('bip38_raw_from_private_key', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_void_p, c_ulong]),
    ('bip38_from_private_key', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_char_p_p]),
    ('bip38_to_private_key', c_int, [c_char_p, c_void_p, c_ulong, c_uint, c_void_p, c_ulong]),
    ('bip38_raw_to_private_key', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_void_p, c_ulong]),
    ('bip39_get_languages', c_int, [c_char_p_p]),
    ('bip39_get_wordlist', c_int, [c_char_p, POINTER(c_void_p)]),
    ('bip39_get_word', c_int, [c_void_p, c_ulong, c_char_p_p]),
    ('bip39_mnemonic_from_bytes', c_int, [c_void_p, c_void_p, c_ulong, c_char_p_p]),
    ('bip39_mnemonic_to_bytes', c_int, [c_void_p, c_char_p, c_void_p, c_ulong, c_ulong_p]),
    ('bip39_mnemonic_validate', c_int, [c_void_p, c_char_p]),
    ('bip39_mnemonic_to_seed', c_int, [c_char_p, c_char_p, c_void_p, c_ulong, c_ulong_p]),
    ('wally_sha256', c_int, [c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_sha256d', c_int, [c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_sha512', c_int, [c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_hex_from_bytes', c_int, [c_void_p, c_ulong, c_char_p_p]),
    ('wally_hex_to_bytes', c_int, [c_char_p, c_void_p, c_ulong, c_ulong_p]),
    ('wally_hmac_sha256', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_void_p]),
    ('wally_hmac_sha512', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_void_p]),
    ('wally_aes', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_void_p, c_ulong]),
    ('wally_aes_cbc', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_pbkdf2_hmac_sha256', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_ulong, c_void_p, c_ulong]),
    ('wally_pbkdf2_hmac_sha512', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_ulong, c_void_p, c_ulong]),
    ('wally_scrypt', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_uint, c_uint, c_void_p, c_ulong]),
    ('wally_secp_randomize', c_int, [c_void_p, c_ulong]),
    ):

    def bind_fn(name, res, args):
        try:
            fn = getattr(libwally, name)
            fn.restype, fn.argtypes = res, args
            return fn
        except AttributeError:
            # Internal function and 'configure --enable-export-all' not used
            return None

    def string_fn_wrapper(fn, *args):
        # Return output string parameters directly without leaking
        p = c_char_p()
        new_args = [a for a in args] + [byref(p)]
        ret = fn(*new_args)
        ret_str = None if p.value is None else p.value.decode('utf-8')
        wally_free_string(p)
        return [ret_str, (ret, ret_str)][fn.restype is not None]

    def int_fn_wrapper(fn, *args):
        p = c_ulong()
        new_args = [a for a in args] + [byref(p)]
        ret = fn(*new_args)
        return [p.value, (ret, p.value)][fn.restype is not None]

    name, restype, argtypes = f
    is_str_fn = type(argtypes[-1]) is c_char_p_p_class
    is_int_fn = type(argtypes[-1]) is c_ulong_p_class
    if is_str_fn:
        argtypes[-1] = POINTER(c_char_p)
    elif is_int_fn:
        argtypes[-1] = POINTER(c_ulong)
    fn = bind_fn(name, restype, argtypes)
    def mkstr(f): return lambda *args: string_fn_wrapper(f, *args)
    def mkint(f): return lambda *args: int_fn_wrapper(f, *args)
    if is_str_fn:
        fn = mkstr(fn)
    elif is_int_fn:
        fn = mkint(fn)
    globals()[name] = fn


def load_words(lang):
    with open(root_dir + 'src/data/wordlists/%s.txt' % lang, 'r') as f:
        words_list = [l.strip() for l in f.readlines()]
        return words_list, ' '.join(words_list)

is_python3 = int(sys.version[0]) >= 3
utf8 = lambda s: s
if is_python3:
    utf8 = lambda s: s.encode('utf-8')

def h(s):
    return hexlify(s)

def make_cbuffer(hex_in):
    hex_len = len(hex_in) // 2
    return unhexlify(hex_in), hex_len
