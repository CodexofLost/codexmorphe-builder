import struct
from typing import Any, Dict, List, Optional, Tuple


class ClassfileAst:
    """
    Pure Python JVM Classfile AST and constant pool parser.
    Supports ClassFile format (major 45 through 65, Java 1.1 to 21+),
    including invokedynamic / BootstrapMethods attributes and bytecode Code inspection.
    """
    def __init__(self, data: bytes):
        self.cp: Dict[int, Tuple[str, Any]] = {}
        self.methods: Dict[Tuple[str, str], bytes] = {}
        self.bootstrap_methods: List[List[Any]] = []
        self.super_class: str = ""
        self.this_class: str = ""
        self._parse(data)

    def _parse(self, data: bytes):
        if len(data) < 10:
            return
        magic, minor, major, cp_count = struct.unpack_from('>IHHH', data, 0)
        if magic != 0xCAFEBABE:
            return
        pos = 10
        i = 1
        while i < cp_count:
            if pos >= len(data):
                break
            tag = data[pos]
            pos += 1
            if tag == 1:  # Utf8
                if pos + 2 > len(data):
                    break
                length, = struct.unpack_from('>H', data, pos)
                pos += 2
                self.cp[i] = ('Utf8', data[pos:pos+length].decode('utf-8', errors='ignore'))
                pos += length
            elif tag in (3, 4):  # Integer, Float
                if pos + 4 > len(data):
                    break
                val, = struct.unpack_from('>I', data, pos)
                pos += 4
                self.cp[i] = ('Int' if tag == 3 else 'Float', val)
            elif tag in (5, 6):  # Long, Double
                if pos + 8 > len(data):
                    break
                val, = struct.unpack_from('>Q', data, pos)
                pos += 8
                self.cp[i] = ('Long' if tag == 5 else 'Double', val)
                i += 1  # 8-byte entries take 2 constant pool slots
            elif tag == 7:  # Class
                if pos + 2 > len(data):
                    break
                idx, = struct.unpack_from('>H', data, pos)
                pos += 2
                self.cp[i] = ('Class', idx)
            elif tag == 8:  # String
                if pos + 2 > len(data):
                    break
                idx, = struct.unpack_from('>H', data, pos)
                pos += 2
                self.cp[i] = ('String', idx)
            elif tag in (9, 10, 11):  # Fieldref, Methodref, InterfaceMethodref
                if pos + 4 > len(data):
                    break
                ref = struct.unpack_from('>HH', data, pos)
                pos += 4
                self.cp[i] = ('Ref2', ref)
            elif tag == 12:  # NameAndType
                if pos + 4 > len(data):
                    break
                nat = struct.unpack_from('>HH', data, pos)
                pos += 4
                self.cp[i] = ('NameAndType', nat)
            elif tag in (15, 16):  # MethodHandle, MethodType
                pos += 3 if tag == 15 else 2
            elif tag in (17, 18):  # Dynamic, InvokeDynamic
                if pos + 4 > len(data):
                    break
                bsm, nat_idx = struct.unpack_from('>HH', data, pos)
                pos += 4
                self.cp[i] = ('InvokeDynamic', (bsm, nat_idx))
            elif tag in (19, 20):  # Module, Package
                pos += 2
            i += 1

        if pos + 8 > len(data):
            return
        access, this_c, super_c, if_cnt = struct.unpack_from('>HHHH', data, pos)
        pos += 8 + if_cnt * 2

        this_entry = self.cp.get(this_c)
        if this_entry and this_entry[0] == 'Class':
            self.this_class = self.cp.get(this_entry[1], ('', ''))[1]
        super_entry = self.cp.get(super_c)
        if super_entry and super_entry[0] == 'Class':
            self.super_class = self.cp.get(super_entry[1], ('', ''))[1]

        if pos + 2 > len(data):
            return
        f_cnt, = struct.unpack_from('>H', data, pos)
        pos += 2
        for _ in range(f_cnt):
            if pos + 8 > len(data):
                return
            _, _, _, a_cnt = struct.unpack_from('>HHHH', data, pos)
            pos += 8
            for _ in range(a_cnt):
                if pos + 6 > len(data):
                    return
                _, a_len = struct.unpack_from('>HI', data, pos)
                pos += 6 + a_len

        if pos + 2 > len(data):
            return
        m_cnt, = struct.unpack_from('>H', data, pos)
        pos += 2
        for _ in range(m_cnt):
            if pos + 8 > len(data):
                return
            _, m_name_idx, m_desc_idx, a_cnt = struct.unpack_from('>HHHH', data, pos)
            pos += 8
            m_name = self.cp.get(m_name_idx, ('', ''))[1]
            m_desc = self.cp.get(m_desc_idx, ('', ''))[1]
            code = b''
            for _ in range(a_cnt):
                if pos + 6 > len(data):
                    return
                a_name_idx, a_len = struct.unpack_from('>HI', data, pos)
                pos += 6
                a_name = self.cp.get(a_name_idx, ('', ''))[1]
                if a_name == 'Code' and pos + 8 <= len(data):
                    _, _, c_len = struct.unpack_from('>HHI', data, pos)
                    code = data[pos+8:pos+8+c_len]
                pos += a_len
            self.methods[(m_name, m_desc)] = code

        if pos + 2 > len(data):
            return
        a_cnt, = struct.unpack_from('>H', data, pos)
        pos += 2
        for _ in range(a_cnt):
            if pos + 6 > len(data):
                return
            a_name_idx, a_len = struct.unpack_from('>HI', data, pos)
            pos += 6
            a_name = self.cp.get(a_name_idx, ('', ''))[1]
            if a_name == 'BootstrapMethods' and pos + 2 <= len(data):
                num_bsm, = struct.unpack_from('>H', data, pos)
                bpos = pos + 2
                for _ in range(num_bsm):
                    if bpos + 4 > len(data):
                        break
                    m_ref, arg_cnt = struct.unpack_from('>HH', data, bpos)
                    bpos += 4
                    args = []
                    for _ in range(arg_cnt):
                        if bpos + 2 > len(data):
                            break
                        arg_idx, = struct.unpack_from('>H', data, bpos)
                        bpos += 2
                        entry = self.cp.get(arg_idx)
                        resolved = self.cp.get(entry[1])[1] if entry and entry[0] in ('String', 'Class') else (entry[1] if entry else None)
                        args.append(resolved)
                    self.bootstrap_methods.append(args)
            pos += a_len

    def get_constant_string(self, idx: int) -> Optional[str]:
        entry = self.cp.get(idx)
        if entry:
            if entry[0] in ('String', 'Class'):
                utf = self.cp.get(entry[1])
                return utf[1] if utf and utf[0] == 'Utf8' else None
            elif entry[0] == 'Utf8':
                return entry[1]
        return None
