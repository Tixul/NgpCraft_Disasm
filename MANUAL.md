# ngpc_disasm — User Manual

**NgpCraft NGPC/NGP Disassembler**  
Single-file Python disassembler for Neo Geo Pocket Color / Neo Geo Pocket ROMs.  
Full TLCS-900/H decoder with NGPC-specific hardware register annotations.

Released under the **MIT License** — free to use, modify, and redistribute.  
Part of the [NgpCraft](https://github.com/ngpcraft) open-source toolchain.

---

## Requirements

- Python 3.6+
- No external dependencies

---

## Quick Start

```bash
# Disassemble an entire ROM (auto-detects entry point from header)
python ngpc_disasm.py game.ngc

# Disassemble a specific address range
python ngpc_disasm.py game.ngc --start 0x200040 --end 0x200200

# Write output to file
python ngpc_disasm.py game.ngc -o game_disasm.asm

# Raw binary (no ROM header) at a custom base address
python ngpc_disasm.py code.bin --base 0x200040
```

---

## Command-Line Options

| Option | Description |
|--------|-------------|
| `input` | ROM file to disassemble (`.ngc`, `.ngp`, or raw `.bin`) |
| `--base ADDR` | ROM base address in memory (default: `0x200000` for NGPC ROMs) |
| `--start ADDR` | First address to disassemble (default: ROM entry point or base) |
| `--end ADDR` | Last address to disassemble (default: end of file) |
| `-o FILE` | Write output to FILE instead of stdout |

All addresses accept hex (`0x200040`) or decimal notation.

---

## Output Format

```
; ============================================================
; NgpCraft Disassembler — game.ngc
; Title    : MYGAME
; System   : NGPC Color  (Licensed)
; ROM size : 65536 bytes (64.0 KB)
; Base     : 0x200000
; Entry    : 0x200040
; ============================================================

; --- ROM Header (64 bytes) ---
0x200000: (header — 64 bytes, entry = 0x200040)

entry_point:
0x200040: D8 8E             ld       XIZ, XWA
0x200042: D8 D8             cp       XWA, 0
0x200044: 65 0A             jr       MI, 0x200050
0x200046: 1E A5 F1          calr     0x2011EE       ; -> sub_2011EE
```

### Line format

```
ADDR: hex_bytes        MNEMONIC  OPERANDS    ; comment/annotation
```

- `ADDR` — 24-bit ROM address (always `0x2xxxxx` for cartridge code)
- `hex_bytes` — raw bytes of the instruction, space-separated
- Annotations appear as `; comment` on the same line

---

## Labels

The disassembler runs in **two passes**:

1. **Pass 1** — linear sweep collecting all jump/call targets
2. **Pass 2** — emit assembly with labels resolved

Labels are generated automatically:

| Prefix | Meaning |
|--------|---------|
| `entry_point:` | ROM entry point (from header) |
| `sub_2XXXXX:` | Target of a `call`/`calr` instruction |
| `loc_2XXXXX:` | Target of a `jp`/`jr`/`jrl` instruction |

Labels appear on the line immediately before the labeled instruction, and call/jump operands include a cross-reference comment: `; -> sub_200100`.

---

## Hardware Register Annotations

Any instruction that references a known NGPC hardware address is annotated automatically.

### Examples

```asm
0x200100: C1 82 6F 21    ld     A, (HW_JOYPAD)       ; = 0x6F82
0x200108: F1 CC 6F 40 67 ldw    (VBL_VECTOR_LO), WA  ; = 0x6FCC
0x200114: C1 6F 00 20    ld     A, (HW_WATCHDOG)      ; = 0x006F
```

### Known registers

**CPU I/O (0x0000–0x00FF)**

| Address | Name | Description |
|---------|------|-------------|
| `0x0020` | `HW_TRUN` | Timer run control |
| `0x006F` | `HW_WATCHDOG` | Write `0x4E` to reset watchdog |
| `0x007C`–`0x007F` | `HW_DMA0V`–`HW_DMA3V` | DMA channel vectors |

**Memory-mapped (0x6F80–0xA000)**

| Address | Name | Description |
|---------|------|-------------|
| `0x6F82` | `HW_JOYPAD` | Joypad state (read) |
| `0x6F91` | `HW_OS_VERSION` | `0`=NGP mono, `!0`=NGPC color |
| `0x6FCC` | `VBL_VECTOR_LO` | VBlank ISR vector low word |
| `0x6FCE` | `VBL_VECTOR_HI` | VBlank ISR vector high word |
| `0x8002` | `K2GE_TRANSPARENCY` | K2GE transparency color |
| `0x8008`–`0x800B` | `K2GE_SCR1/2_SCROLL_X/Y` | Scroll plane offsets |
| `0x8800` | `SPR_VRAM_BASE` | Sprite VRAM (64 sprites × 4 bytes) |
| `0x9000` | `SCR1_MAP_BASE` | Scroll plane 1 tilemap |
| `0x9800` | `SCR2_MAP_BASE` | Scroll plane 2 tilemap |
| `0xA000` | `TILE_RAM_BASE` | Character/Tile RAM |

---

## BIOS Call Annotations

`swi` instructions are annotated with BIOS function names:

```asm
0x200040: F9    swi  1    ; BIOS_CLOCKGEARSET
0x200050: FD    swi  5    ; BIOS_SYSFONTSET
0x200060: FE    swi  6    ; BIOS_FLASHWRITE
```

| SWI | Name |
|-----|------|
| 0 | `BIOS_SHUTDOWN` |
| 1 | `BIOS_CLOCKGEARSET` |
| 2 | `BIOS_RTCGET` |
| 5 | `BIOS_SYSFONTSET` |
| 6 | `BIOS_FLASHWRITE` |
| 8 | `BIOS_FLASHERS` |
| 9 | `BIOS_ALARMSET` |

---

## Broken Opcode Detection

Instructions that are **known to crash or hang on NGPC silicon** are annotated with `; !BROKEN`:

```asm
0x200100: D0 61    inc   8, WA    ; !BROKEN D0 word-reg ALU prefix (NGPC silicon bug)
0x200102: CB 81    add   A, C     ; !BROKEN — CB family broken on NGPC
```

### Known broken opcodes

| Opcode(s) | Issue |
|-----------|-------|
| `D0 xx` | D0 prefix (all sub-ops) — hangs watchdog |
| `CB xx` | Entire CB family — causes infinite loop |
| `LINK XIY, N` where N≥5 | Stack frame too large — corrupts SP |
| `ADC W, B` when W > 0 | ADC high byte produces wrong result |

> **Note:** `D1` as abs16 load (`LD R16, (abs16)`) is **safe** and will decode normally without a warning. Similarly, `D2..D7` used as abs-address memory loads are safe and decode without warning.

---

## Instruction Coverage

The decoder handles the full TLCS-900/H instruction set as used on NGPC:

| Category | Examples |
|----------|---------|
| Fixed opcodes | `NOP`, `RET`, `RETI`, `RETD`, `EI`, `DI`, `HALT`, `SWI` |
| Flag ops | `RCF`, `SCF`, `CCF`, `ZCF`, `INCF`, `DECF`, `EX F,F'`, `LDF` |
| SR/A/F stack | `PUSH`/`POP` `SR`, `A`, `F` |
| Load immediate | `LD R8, #imm8` / `LD R16, #imm16` / `LD R32, #imm32` |
| Stack | `PUSH`/`POP` R16/R32, `PUSHW #imm16`, `PUSH #imm8` |
| Branches | `JP`, `CALL`, `JR cc, d8`, `JRL cc, d16`, `CALR d16` |
| C8+zz+r ALU | `ADD`, `SUB`, `AND`, `XOR`, `OR`, `CP`, `LD`, `INC`, `DEC` |
| E8+r special | `LINK`, `UNLK`, `EXTZ`, `EXTS`, `DJNZ` |
| Indirect loads | `LD R, (r32+d8)`, `LD R, (abs16)`, `LD R, (abs24)` |
| Indirect stores | `LD (r32+d8), R`, `LD (abs16), R`, `LD (abs16), #imm` |
| Post-inc/pre-dec | `LD (r32+), R8`, `LD R8, (r32+)` |
| B0+mem forms | `JP/CALL cc, (mem)`, `LD (mem), R`, `LDA R, (mem)`, bit ops |
| Bit manipulation | `BIT`, `RES`, `SET`, `CHG`, `TSET`, `ANDCF`/`ORCF`/`XORCF` |
| Shifts/rotates | `RLC`, `RRC`, `RL`, `RR`, `SLA`, `SRA`, `SLL`, `SRL` |
| Block copy | `LDIW`, `LDIRW` |
| LDC | `LDC cr, r` / `LDC r, cr` with DMA register names |
| Multiply/Divide | `MUL`, `MULS`, `DIV`, `DIVS` |

---

## Understanding the Output

### Function boundaries

The disassembler detects `LINK`/`UNLK` prologue/epilogue patterns from the NgpCraft toolchain. These appear as function delimiters in the output.

For CC900-compiled code (official toolchain), function boundaries are identified by call/return patterns and label detection rather than `link`/`unlk` (CC900 doesn't use these).

### Linear sweep limitations

The disassembler uses **linear sweep** — it decodes bytes sequentially from the start address. This means:

- **Jump tables** may be decoded as instructions (they aren't). Look for runs of `db` bytes between valid instruction sequences.
- **Data sections** embedded in code (e.g., ROM strings) will produce garbage instructions before the next real code.
- Use `--start` and `--end` to focus on known code regions.

### Unknown bytes

Bytes that cannot be decoded appear as:

```asm
0x200100: XX    db    0xXX    ; ?? unknown opcode
```

This usually means:
1. The byte is part of a data table (jump target offsets, strings, graphics data)
2. The preceding instruction was decoded with wrong length, breaking alignment
3. A genuinely rare/unused opcode

---

## Working with Real ROMs

### NGPC color ROM

```bash
python ngpc_disasm.py game.ngc
```

The disassembler auto-detects the NGPC ROM header and:
- Skips the 64-byte header (shown as a comment)
- Sets base address to `0x200000`
- Uses the header's entry point as the start address
- Reports title, color/mono, and software ID

### NGP mono ROM

```bash
python ngpc_disasm.py game.ngp
```

Same as above, `System: NGP Mono`.

### Raw binary (no header)

```bash
python ngpc_disasm.py code.bin --base 0x200040
```

If no valid ROM header is detected, the file is treated as raw binary starting at `--base`.

### BIOS ROM

```bash
python ngpc_disasm.py ngp.bios --base 0xFF0000
```

The NGPC BIOS occupies `0xFF0000–0xFFFFFF` (64 KB). Use the appropriate base.

---

## Output File

```bash
python ngpc_disasm.py game.ngc -o game.asm
```

The output file uses the same format as stdout. It can serve as a starting point for:
- Re-assembly with `t900as.py` (NgpCraft toolchain)
- Study and annotation in a text editor
- Diff-based comparison between ROM versions

---

## Example: Entry Point Analysis

```bash
python ngpc_disasm.py Stargunner.ngc --start 0x2079C5 --end 0x207A60
```

Output (excerpt):

```asm
entry_point:
0x2079C5: 2E                push     IZ
0x2079C6: 1D D5 D0 20       call     0x20D0D5      ; -> sub_20D0D5
0x2079CA: 1D A8 D1 20       call     0x20D1A8      ; -> sub_20D1A8
0x2079CE: 1D EA F5 20       call     0x20F5EA      ; -> sub_20F5EA
0x2079D2: 1D 00 1D 21       call     0x211D00      ; -> sub_211D00
...
0x2079E6: DE AC             ld       XIZ, 4
0x2079E8: 1D F9 DF 20       call     0x20DFF9      ; -> sub_20DFF9
0x2079EC: D2 BC 5E 00 20    ld       WA, (0x005EBC)
0x2079F1: D8 DC             cp       XWA, 4
0x2079F3: 66 04             jr       Z, 0x2079F9   ; -> loc_2079F9
```

---

## Known Limitations

- **Linear sweep only** — no recursive descent. Data-embedded-in-code sections may confuse the decoder.
- **No symbol import** — labels are auto-generated (`sub_XXXXXX`, `loc_XXXXXX`). No way to import a symbol table yet.
- **D0 family** — decoded for annotation but always flagged as BROKEN (correct behavior for NGPC).
- **LDAR** — decoded but rare; relative addressing is shown as absolute computed address.
- **ARI mode 3 complex forms** — decoded when r32 index is in range; invalid combinations fall back to `db`.

---

## Toolchain Integration

This disassembler is part of the NgpCraft toolchain:

| Tool | Purpose |
|------|---------|
| `t900as.py` | TLCS-900 assembler (source of truth for opcode encoding) |
| `ngpc_romtool.py` | ROM packer / header inspector |
| `ngpc_disasm.py` | This disassembler |

The output format is designed to be compatible with `t900as.py` for round-trip study (disassemble → edit → re-assemble).
