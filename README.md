# ngpc_disasm

**TLCS-900/H disassembler for Neo Geo Pocket Color / Neo Geo Pocket ROMs**

Single-file, zero-dependency Python disassembler for NGPC and NGP cartridges.
Part of the [NgpCraft](https://github.com/ngpcraft) open-source toolchain.

---

## Features

- **Full TLCS-900/H decoder** — fixed opcodes, all prefix families (B0/C0/C8/D8/E8/F0/F8), indirect and immediate addressing, bit ops, shifts, block copy, multiply/divide
- **NGPC hardware register annotations** — joypad, VBlank vector, watchdog, K2GE, sprite VRAM, scroll planes, tile RAM
- **BIOS SWI names** — `swi 1` → `BIOS_CLOCKGEARSET`, `swi 5` → `BIOS_SYSFONTSET`, etc.
- **DMA LDC register names** — `DMAC0`, `DMAS0`, `DMAD0`, `DMAM1`… (58 instructions correctly annotated on *Ganbare Neo Poke-kun*)
- **Broken opcode detection** — `D0` prefix, `CB` family, `link XIY, N≥5`, `adc W, B` with W>0 all flagged `; !BROKEN` identified during toolchain development and validated through testing on real hardware.
- **Two-pass label resolution** — `entry_point:`, `sub_2XXXXX:` (call targets), `loc_2XXXXX:` (jump targets) with `; -> sub_XXXXXX` cross-references on every call/jump
- **Auto ROM header parsing** — detects title, entry point, color/mono, software ID from the 64-byte SNK/Toshiba header

---

## Quick Start

```bash
# Disassemble a full NGPC ROM (entry point from header)
python ngpc_disasm.py game.ngc

# Disassemble a specific address range
python ngpc_disasm.py game.ngc --start 0x200040 --end 0x200200

# Write output to file
python ngpc_disasm.py game.ngc -o game.asm

# Raw binary at a custom base address
python ngpc_disasm.py code.bin --base 0x200040

# NGPC BIOS ROM
python ngpc_disasm.py ngp.bios --base 0xFF0000
```

**Requirements:** Python 3.6+, no external dependencies.

---

## Output Example

```asm
; ============================================================
; NgpCraft Disassembler — Stargunner.ngc
; Title    : STARGUNNER
; System   : NGPC Color  (Licensed)
; ROM size : 81920 bytes (80.0 KB)
; Base     : 0x200000
; Entry    : 0x2079C5
; ============================================================

entry_point:
0x2079C5: 2E                push     IZ
0x2079C6: 1D D5 D0 20       call     0x20D0D5      ; -> sub_20D0D5
0x2079CA: 1D A8 D1 20       call     0x20D1A8      ; -> sub_20D1A8
0x2079D2: 1D 00 1D 21       call     0x211D00      ; -> sub_211D00
0x2079E8: 1D F9 DF 20       call     0x20DFF9      ; -> sub_20DFF9
0x2079EC: D2 BC 5E 00 20    ld       WA, (0x005EBC)
0x2079F3: 66 04             jr       Z, 0x2079F9   ; -> loc_2079F9

sub_20D0D5:
0x20D0D5: C0 60 6F 82       ld       A, (HW_JOYPAD)  ; = 0x6F82
```

---

## Validation

Tested against real NGPC cartridges:

| ROM | Size | Unknown rate | Notes |
|-----|------|-------------|-------|
| Stargunner *(homebrew, CC900)* | 80 KB | 8.5% | Source code available — all unknowns are data |
| Delta Warp *(official)* | 512 KB | 9.1% | All unknowns are graphics tiles |
| Ganbare Neo Poke-kun *(official, 2 MB)* | 2 MB | 6.7% | Heaviest DMA usage — all 58 `ldc` correctly annotated |

Unknown bytes are always data sections (tiles, strings, jump tables) — no missing code opcodes.

---

## Command-Line Reference

| Option | Description |
|--------|-------------|
| `input` | ROM file (`.ngc`, `.ngp`, or raw `.bin`) |
| `--base ADDR` | ROM base address (default: `0x200000`) |
| `--start ADDR` | First address to disassemble (default: entry point) |
| `--end ADDR` | Last address to disassemble (default: end of file) |
| `-o FILE` | Write to file instead of stdout |

All addresses accept hex (`0x200040`) or decimal.

---

## NgpCraft Toolchain

| Tool | Purpose |
|------|---------|
| `t900as.py` | TLCS-900/H assembler |
| `ngpc_romtool.py` | ROM packer / header inspector |
| `ngpc_disasm.py` | This disassembler |

The output format is designed to be compatible with `t900as.py` for round-trip study (disassemble → edit → re-assemble).

---

## License

MIT — see [LICENSE](LICENSE).
