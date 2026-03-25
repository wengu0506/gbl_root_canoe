#!/usr/bin/env python3
import struct
import sys
import os
import lzma
import argparse

# add unique code
EFI_FV_SIGNATURE = b'_FVH'
PE_MZ_SIGNATURE = b'MZ'
BMP_SIGNATURE = b'BM'

def calc_pe_real_size(data):
    pe_ptr = struct.unpack_from('<H', data, 0x3C)[0]
    if data[pe_ptr:pe_ptr + 2] != b'PE':
        raise ValueError("Not a valid PE")

    num_sec = struct.unpack_from('<H', data, pe_ptr + 0x06)[0]
    opt_size = struct.unpack_from('<H', data, pe_ptr + 0x14)[0]
    sec_table = pe_ptr + 0x18 + opt_size

    # SizeOfHeaders 作为初始最小值，防止截断头部数据
    real_len = struct.unpack_from('<I', data, pe_ptr + 0x54)[0]

    for i in range(num_sec):
        sec_off = sec_table + i * 0x28
        size_of_raw    = struct.unpack_from('<I', data, sec_off + 0x10)[0]  # SizeOfRawData
        pointer_to_raw = struct.unpack_from('<I', data, sec_off + 0x14)[0]  # PointerToRawData
        end = pointer_to_raw + size_of_raw
        if end > real_len:
            real_len = end

    return real_len

class HeavyExtractor:
    def __init__(self, verbose=False, info_only=False):
        self.pe_files = []
        self.images = [] 
        self.scanned_hashes = set()
        self.verbose = verbose
        self.info_only = info_only

    def log(self, msg, depth=0):
        if self.verbose or self.info_only:
            prefix = "  " * depth
            print(f"{prefix}[*] {msg}")

    def try_lzma_decompress(self, data):
        data = bytes(data)
        for skip in range(0, 32): 
            if skip >= len(data): break
            d = data[skip:]
            if len(d) < 5 or d[0] != 0x5D: continue 
            try:
                header = d[:5] + struct.pack('<Q', 2**64 - 1)
                return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(header + d[5:])
            except:
                try: return lzma.decompress(d)
                except: continue
        return None

    def parse_pe_info(self, data, offset):
        try:
            pe_ptr = struct.unpack_from('<H', data, 0x3C)[0]
            machine = struct.unpack_from('<H', data, pe_ptr + 4)[0]
            subsystem = struct.unpack_from('<H', data, pe_ptr + 0x5C)[0]
            
            m_map = {0xAA64: "ARM64", 0x014C: "x86", 0x8664: "x64", 0x01C0: "ARM"}
            s_map = {10: "EFI_APP", 11: "EFI_DRIVER", 12: "EFI_RUNTIME"}
            
            m_str = m_map.get(machine, f"0x{machine:X}")
            s_str = s_map.get(subsystem, f"0x{subsystem:X}")
            return f"Arch: {m_str}, Type: {s_str}"
        except:
            return "Unknown PE structure"

    def deep_scan(self, data, depth=0):
        if depth > 5 or not data or len(data) < 0x40: return
        
        h = hash(data[:1000])
        if h in self.scanned_hashes: return
        self.scanned_hashes.add(h)

        prefix = '  ' * depth
        
        off = 0
        while True:
            off = data.find(PE_MZ_SIGNATURE, off)
            if off == -1: break
            if off + 0x40 < len(data):
                try:
                    pe_ptr = struct.unpack_from('<H', data, off + 0x3C)[0]
                    if data[off + pe_ptr : off + pe_ptr + 2] == b'PE':
                        info = self.parse_pe_info(data[off:], off)
                        self.log(f"FOUND PE: Offset 0x{off:X} | {info}", depth)
                        self.pe_files.append((off, data[off:], info))
                except: pass
            off += 2

        off = 0
        while True:
            off = data.find(BMP_SIGNATURE, off)
            if off == -1: break
            if off + 14 < len(data):
                f_size = struct.unpack_from('<I', data, off + 2)[0]
                if 100 < f_size < 10 * 1024 * 1024:
                    self.log(f"FOUND BMP: Offset 0x{off:X} | Size: {f_size} bytes", depth)
                    self.images.append((off, f_size, data[off:off+f_size]))
            off += 2

        off = 0
        while True:
            off = data.find(b'\x5d\x00\x00', off)
            if off == -1: break
            decomp = self.try_lzma_decompress(data[off:off+0x200000])
            if decomp:
                print(f"{prefix}[Decompressed Layer {depth+1}] Size: 0x{len(decomp):X}")
                self.deep_scan(decomp, depth + 1)
            off += 1

        off = 0
        while True:
            off = data.find(EFI_FV_SIGNATURE, off)
            if off == -1: break
            fv_start = off - 0x28
            if fv_start >= 0:
                try:
                    fv_len = struct.unpack_from('<Q', data, fv_start + 0x20)[0]
                    if 0x100 < fv_len < len(data) - fv_start:
                        self.log(f"Entering Firmware Volume (FV) at 0x{fv_start:X}", depth)
                        self.deep_scan(data[fv_start : fv_start + fv_len], depth + 1)
                except: pass
            off += 4

def main():
    parser = argparse.ArgumentParser(description="Advanced QCOM ABL Investigator")
    parser.add_argument("input", help="Path to ABL.elf/img")
    parser.add_argument("-o", "--output", default="extracted", help="Output directory (default: extracted)")
    parser.add_argument("-e", "--extract", choices=["pe32", "bmp", "all"], help="Extract target: pe32, bmp, or all (default: largest PE only)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all scanning details")
    parser.add_argument("-i", "--info", action="store_true", help="Info mode: List contents without extracting")
    
    args = parser.parse_args()
    if not os.path.exists(args.input):
        print(f"Error: {args.input} not found."); sys.exit(1)

    with open(args.input, 'rb') as f: raw_data = f.read()

    print(f"[*] Analyzing {os.path.basename(args.input)} (Size: {len(raw_data)} bytes)")
    ext = HeavyExtractor(verbose=args.verbose, info_only=args.info)
    ext.deep_scan(raw_data)

    if args.info:
        print("\n--- Scan Summary ---")
        print(f"Total PE Files Found: {len(ext.pe_files)}")
        print(f"Total BMP Images Found: {len(ext.images)}")
        return

    if not os.path.exists(args.output):
        os.makedirs(args.output)
        print(f"[*] Created output directory: {args.output}")

    if ext.pe_files or ext.images:
        if args.extract is None:
            ext.pe_files.sort(key=lambda x: len(x[1]), reverse=True)
            _, loader_data, _ = ext.pe_files[0]
            try:
                real_len = calc_pe_real_size(loader_data)
                final_path = os.path.join(args.output, "LinuxLoader.efi")
                with open(final_path, 'wb') as f: f.write(loader_data[:real_len])
                print(f"[+] Extracted LinuxLoader.efi to {final_path}")
            except Exception as e:
                # 失败时保存整个块
                final_path = os.path.join(args.output, "LinuxLoader.efi")
                with open(final_path, 'wb') as f: f.write(loader_data)
                print(f"[!] Saved raw PE chunk to {final_path} (trimming failed: {e})")
        
        if args.extract in ["pe32", "all"]:
            for i, (off, data, info) in enumerate(ext.pe_files):
                try:
                    real_len = calc_pe_real_size(data)
                    pe_slice = data[:real_len]
                except:
                    pe_slice = data
                
                fname = os.path.join(args.output, f"extracted_{i}.efi")
                with open(fname, 'wb') as f: f.write(pe_slice)
                print(f"  -> Extracted PE {i}: {fname}")

        if args.extract in ["bmp", "all"]:
            for i, (off, size, data) in enumerate(ext.images):
                fname = os.path.join(args.output, f"image_0x{off:X}.bmp")
                with open(fname, 'wb') as f: f.write(data)
                print(f"  -> Extracted BMP: {fname}")
    else:
        print("\n[-] No PE or BMP files found.")

if __name__ == '__main__':
    main()