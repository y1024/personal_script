from types import SimpleNamespace
import idaapi
from idaapi import *

"""
Refer: https://github.com/swiftlang/swift/blob/main/stdlib/public/core/StringObject.swift

  ┌─────────────────────╥─────┬─────┬─────┬─────┐
  │ Form                ║ b63 │ b62 │ b61 │ b60 │
  ╞═════════════════════╬═════╪═════╪═════╪═════╡
  │ Immortal, Small     ║  1  │ASCII│  1  │  0  │
  ├─────────────────────╫─────┼─────┼─────┼─────┤
  │ Immortal, Large     ║  1  │  0  │  0  │  0  │
  ├─────────────────────╫─────┼─────┼─────┼─────┤
  │ Immortal, Bridged   ║  1  │  1  │  0  │  0  │
  ╞═════════════════════╬═════╪═════╪═════╪═════╡
  │ Native              ║  0  │  0  │  0  │  0  │
  ├─────────────────────╫─────┼─────┼─────┼─────┤
  │ Shared              ║  x  │  0  │  0  │  0  │
  ├─────────────────────╫─────┼─────┼─────┼─────┤
  │ Shared, Bridged     ║  0  │  1  │  0  │  0  │
  ╞═════════════════════╬═════╪═════╪═════╪═════╡
  │ Foreign             ║  x  │  0  │  0  │  1  │
  ├─────────────────────╫─────┼─────┼─────┼─────┤
  │ Foreign, Bridged    ║  0  │  1  │  0  │  1  │
  └─────────────────────╨─────┴─────┴─────┴─────┘

  b63: isImmortal: Should the Swift runtime skip ARC
    - Small strings are just values, always immortal
    - Large strings can sometimes be immortal, e.g. literals
  b62: (large) isBridged / (small) isASCII
    - For large strings, this means lazily-bridged NSString: perform ObjC ARC
    - Small strings repurpose this as a dedicated bit to remember ASCII-ness
  b61: isSmall: Dedicated bit to denote small strings
  b60: isForeign: aka isSlow, cannot provide access to contiguous UTF-8
"""

'''
pattern_mov_nr_nr:      short: 0xa/0xe
    part1:  mov mop_n,          mop_r
    part2:  mov mop_n,          mop_r
pattern_mov_nr_avr:     long :0x8
    part1:  mov mop_n,          mop_r
    part2:  mov mop_a(mop_v),   mop_r
pattern_stx_nrn_nrn:    short: 0xa/0xe
    part1:  stx mop_n,          m_add(mop_r, mop_n)
    part2:  stx mop_n,          m_add(mop_r, mop_n)
pattern_stx_nrn_avrn:   long: 0x8
    part1:  stx mop_n,          m_add(mop_r, mop_n)
    part2:  stx mop_a(mop_v)    m_add(mop_r, mop_n)
'''
def is_part1_match(part1, part2):
    is_match = False
    if part2.opcode == m_mov:
        if part1.d.t == mop_r: 
            r1 = part1.d.r
            r2 = part2.d.r
            if r1 + 8 == r2: # reg相邻
                is_match = True
    elif part2.opcode == m_stx:
        if part1.d.t == mop_d and part1.d.d.opcode == m_add and part1.d.d.r.t == mop_n:
            d1 = part1.d.d
            d2 = part2.d.d
            if d1.l.r == d2.l.r and d1.r.nnn.value + 8 == d2.r.nnn.value: # lvar相邻
                is_match = True
    return is_match

def decode_swift_str_mblock(blk):
    maybe_part1_lst = list()
    str_lst = list()
    insn = blk.head
    while insn is not None:
        # 定位part2, 不匹配part2但匹配part1的暂存
        if insn.opcode == m_mov:
            if insn.l.t == mop_n and insn.d.t == mop_r:
                n2 = insn.l.nnn.value
                f2 = n2 >> 60
                if f2 == 0xa or f2 == 0xe: # short, short&ascii
                    str_l = (n2 >> 56) & 0xf
                    if (str_l <= 8 and (n2 & 0xffffffffffffff) == 0) or (str_l > 8 and (n2 & 0xffffffffffffff) != 0):
                        str_lst.append(SimpleNamespace(part1=None, part2=insn, n2=n2))
                    else:
                        print(f"decode_swift_str warning: unexpected pattern at {insn.ea:08x}")
                else:
                    maybe_part1_lst.append(insn)
            elif insn.l.t == mop_a and insn.l.a.t == mop_v and insn.d.t == mop_r:
                n2 = insn.l.a.g
                f2 = n2 >> 60
                if f2 == 0x8: # long
                    str_p = (n2 & 0xfffffffffffffff) + 0x20
                    if idc.get_name(str_p):
                        str_lst.append(SimpleNamespace(part1=None, part2=insn, n2=n2))
                    else:
                        print(f"decode_swift_str warning: unexpected pattern {insn.ea:08x}")
        elif insn.opcode == m_stx:
            if insn.l.t == mop_n and insn.d.t == mop_d:
                if insn.d.d.opcode == m_add and insn.d.d.l.t == mop_r and insn.d.d.r.t == mop_n:
                    n2 = insn.l.nnn.value
                    f2 = n2 >> 60
                    if f2 == 0xa or f2 == 0xe: # short, short&ascii
                        str_l = (n2 >> 56) & 0xf
                        if (str_l <= 8 and (n2 & 0xffffffffffffff) == 0) or (str_l > 8 and (n2 & 0xffffffffffffff) != 0):
                            str_lst.append(SimpleNamespace(part1=None, part2=insn, n2=n2))
                        else:
                            print(f"decode_swift_str warning: unexpected pattern at {insn.ea:08x}")
                    else:
                        maybe_part1_lst.append(insn)
            elif insn.l.t == mop_a and insn.l.a.t == mop_v and insn.d.t == mop_d:
                if insn.d.d.opcode == m_add and insn.d.d.l.t == mop_r and insn.d.d.r.t == mop_n:
                    n2 = insn.l.a.g
                    f2 = n2 >> 60
                    if f2 == 0x8: # long
                        str_p = (n2 & 0xfffffffffffffff) + 0x20
                        if idc.get_name(str_p):
                            str_lst.append(SimpleNamespace(part1=None, part2=insn, n2=n2))
                        else:
                            print(f"decode_swift_str warning: unexpected pattern {insn.ea:08x}")
        insn = insn.next
    todo_lst = list()
    for item in str_lst:
        item.part1 = next((part1 for part1 in maybe_part1_lst if is_part1_match(part1, item.part2)), None)
        part1, part2 = item.part1, item.part2
        if part1 is None:
            print(f"decode_swift_str warning: failed to find match, skip {part2.ea:08x}")
            continue
        n1 = item.part1.l.nnn.value
        n2 = item.n2
        f2 = n2 >> 60
        isSmall = bool((f2 >> 1) & 1)
        try:
            if isSmall:
                str_l = (n2 >> 56) & 0xf
                if str_l == 0:
                    print(f"decode_swift_str warning: empty str {part2.ea:08x}")
                    continue
                if str_l <= 8:
                    bs = n1.to_bytes(str_l, "little")
                else:
                    s_i2 = n2 & 0xffffffffffffff
                    bs = n1.to_bytes(8, "little") + s_i2.to_bytes(str_l - 8, "little")
                s = bs.decode()
                print(f"decode_swift_str info: parse short swift str at: {part2.ea:08x}")
            else:
                str_l = n1 & 0xffffffffffff
                str_p = (n2 & 0xfffffffffffffff) + 0x20
                if str_l == 0:
                    print(f"decode_swift_str warning: empty str {part2.ea:08x}")
                    continue
                elif str_l > 0x100:
                    print(f"decode_swift_str warning: too long to show {part2.ea:08x}")
                    continue
                bs = idaapi.get_bytes(str_p, str_l)
                s = bs.decode()
                print(f"decode_swift_str info: parse long swift str at: {part2.ea:08x}")
            todo_lst.append([part1, part2, s])
        except Exception as e:
            print(f"decode_swift_str warning: decode failed {e}")
    for part1, part2, s in todo_lst:
        part1.l._make_strlit(f"@swift({s})")
        part2.l._make_strlit(f"@swift({s})")

class DeSwiftStr(Hexrays_Hooks):
    def mba_maturity(self, mba, reqmat):
        if mba.maturity == MMAT_LOCOPT:
            for i in range(1, mba.qty):
                blk = mba.get_mblock(i)
                if blk.get_reginsn_qty() < 2:
                    continue
                decode_swift_str_mblock(blk)
        return idaapi.MERR_OK


