"""Authored PE fixture for static parsers only; never execute on the host."""
import struct
from pathlib import Path


def build(destination: Path):
    image = bytearray(1024)
    image[:2] = b'MZ'
    struct.pack_into('<I', image, 0x3c, 0x80)
    image[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', image, 0x84, 0x8664, 1, 0, 0, 0, 0xf0, 0x22)
    optional = 0x98
    struct.pack_into('<HBB', image, optional, 0x20b, 14, 0)
    struct.pack_into('<III', image, optional+4, 0x200, 0, 0)
    struct.pack_into('<IIQII', image, optional+16, 0x1000, 0x1000, 0x140000000, 0x1000, 0x200)
    struct.pack_into('<HHHHHH', image, optional+40, 6, 0, 0, 0, 6, 0)
    struct.pack_into('<IIIHH', image, optional+56, 0x2000, 0x200, 0, 3, 0x160)
    struct.pack_into('<QQQQII', image, optional+72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    # Store an innocuous marker on the stack, restore stack and return zero.
    code = b'\x48\x83\xec\x28\x48\xb8BENIGN\0\0\x48\x89\x44\x24\x20\x31\xc0\x48\x83\xc4\x28\xc3'
    section = optional+0xf0
    struct.pack_into('<8sIIIIIIHHI', image, section, b'.text\0\0\0', 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    image[0x200:0x200+len(code)] = code
    marker = b'Sandbox Lab benign static parser fixture\0'
    image[0x280:0x280+len(marker)] = marker
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(image)
    return destination
