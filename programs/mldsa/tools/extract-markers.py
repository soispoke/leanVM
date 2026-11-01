import struct
import sys
from pathlib import Path

b = Path(sys.argv[1]).read_bytes()
offset = struct.unpack_from('<Q', b, 40)[0]
size, count, names_index = struct.unpack_from('<HHH', b, 58)
headers = [struct.unpack_from('<IIQQQQIIQQ', b, offset + i * size) for i in range(count)]
names_header = headers[names_index]
names = b[names_header[4]:names_header[4] + names_header[5]]
for h in headers:
    if names[h[0]:].split(b'\0')[0] == b'.text':
        for i in range(0, h[5], 4):
            word = struct.unpack_from('<I', b, h[4] + i)[0]
            if word & 0xfffff == 0x13 and 100 <= word >> 20 <= 109:
                print(f'{h[3] + i:x} {word >> 20}')
