#!/usr/bin/env python3

import sys
from pathlib import Path

header_file = Path('include/shellcode-template.h').read_text()
shellcode = Path(sys.argv[1]).read_bytes()

shellcode_formatted = ''

for byte in shellcode:
    shellcode_formatted += r'\x{:02x}'.format(byte)

header_file = header_file.replace('<SHELLCODE>', shellcode_formatted)
header_file = header_file.replace('<SHELLCODE-SIZE>', str(len(shellcode)))

Path('include/shellcode.h').write_text(header_file)
