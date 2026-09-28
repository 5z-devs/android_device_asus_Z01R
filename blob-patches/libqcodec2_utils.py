#
# SPDX-FileCopyrightText: The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#

import re

from extract_utils.fixups_blob import (
    BlobFixupCtx,
    File,
)
from extract_utils.tools import (
    llvm_objdump_path,
)
from extract_utils.utils import (
    run_cmd,
)


def blob_fixup(
    ctx: BlobFixupCtx,
    file: File,
    file_path: str,
    *args,
    **kwargs,
):
    patches = {
        # qc2::QC2Buffer::Graphic::GetAlignedHeight(unsigned int, unsigned int)
        '_ZN3qc29QC2Buffer7Graphic16GetAlignedHeightEjj': (
            # addw r1, r0, #0x1ff
            # movw r2, #0x1ff
            '00 F2 FF 11 40 F2 FF 12',
            # addw r1, r0, #0x1f
            # movw r2, #0x1f
            '00 F2 1F 01 40 F2 1F 02',
        ),
        # qc2::QC2Buffer::Graphic::GetAlignedWidth(unsigned int, unsigned int)
        '_ZN3qc29QC2Buffer7Graphic15GetAlignedWidthEjj': (
            # addw r1, r0, #0x1ff
            # movw r2, #0x1ff
            '00 F2 FF 11 40 F2 FF 12',
            # addw r1, r0, #0x7f
            # movw r2, #0x7f
            '00 F2 7F 01 40 F2 7F 02',
        ),
    }

    segments = [
        (int(vaddr, 16), int(off, 16), int(filesz, 16))
        for off, vaddr, filesz in re.findall(
            r'LOAD off\s+(0x[0-9a-f]+) vaddr (0x[0-9a-f]+).*\n'
            r'\s+filesz (0x[0-9a-f]+)',
            run_cmd([llvm_objdump_path, '-p', file_path]),
        )
    ]

    symbols = {
        name: (int(addr, 16) & ~1, int(size, 16))
        for addr, size, name in re.findall(
            r'^([0-9a-f]+) .*\t([0-9a-f]+)\s+(\S+)$',
            run_cmd([llvm_objdump_path, '-T', file_path]),
            re.MULTILINE,
        )
        if name in patches
    }

    with open(file_path, 'rb+') as f:
        for symbol, (search, replace) in patches.items():
            search = bytes.fromhex(search)
            replace = bytes.fromhex(replace)

            addr, size = symbols[symbol]
            offset = next(
                addr - vaddr + off
                for vaddr, off, filesz in segments
                if vaddr <= addr < vaddr + filesz
            )

            f.seek(offset)
            data = f.read(size)

            f.seek(offset)
            f.write(data.replace(search, replace))
