// dumpexe.cpp - MS-DOS MZ EXE header dumper, analyzer, and single-pass disassembler
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
// Target: 16-bit MS-DOS MZ EXE files only

#include "dumpexe.h"

int main(int argc, char* argv[]) {
    Options opt;
    if (!opt.parse(argc, argv)) {
        return 1;
    }

    if (opt.showHelp) {
        usage(argv[0]);
        return 0;
    }

    if (opt.showVersion) {
        std::cout << "dumpexe 1.0 — 16-bit MS-DOS MZ EXE Analyzer & Single-Pass Disassembler\n";
        std::cout << "Copyright (c) 2026 EdgeOfAssembly <haxbox2000@gmail.com>\n";
        std::cout << "License: GPLv2 | Commercial (contact author)\n";
#if HAS_CAPSTONE
        std::cout << "Built with Capstone disassembly support: yes\n";
#else
        std::cout << "Built with Capstone disassembly support: no\n";
#endif
        return 0;
    }

    if (opt.filename.empty()) {
        std::cerr << "Error: No input file specified\n";
        usage(argv[0]);
        return 1;
    }

    // Read the entire file
    std::ifstream file(opt.filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open file '" << opt.filename << "'\n";
        return 1;
    }

    std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
    file.close();

    if (fileData.size() < sizeof(MZHeader)) {
        std::cerr << "Error: File too small to be a valid MZ EXE\n";
        return 1;
    }

    // Parse MZ header
    MZHeader header;
    std::memcpy(&header, fileData.data(), sizeof(MZHeader));

    // Validate MZ signature
    if (header.signature != 0x5A4D) {  // "MZ"
        std::cerr << "Error: Not a valid MZ EXE file (signature mismatch)\n";
        return 1;
    }

    // Calculate important values
    uint32_t headerBytes = header.header_size * 16;
    uint32_t imageSize = (header.num_blocks - 1) * 512 + header.final_len;
    if (header.final_len == 0 && header.num_blocks > 0) {
        imageSize = header.num_blocks * 512;
    }
    uint32_t codeSize = imageSize - headerBytes;
    uint32_t fileSize = fileData.size();
    uint32_t overlaySize = (fileSize > imageSize) ? (fileSize - imageSize) : 0;

    // Display header information (TDUMP-style)
    std::cout << "====================================================================\n";
    std::cout << "File: " << opt.filename << "\n";
    std::cout << "====================================================================\n\n";
    std::cout << "MS-DOS MZ EXE Header Information\n";
    std::cout << "====================================================================\n";
    
    printField("Signature (4Dh 5Ah = 'MZ')", header.signature, 4);
    printField("Bytes in last page", header.final_len, 4);
    printField("Pages in file (512 bytes each)", header.num_blocks, 4);
    printField("Number of relocation entries", header.num_reloc, 4);
    printField("Header size in paragraphs (16 bytes each)", header.header_size, 4);
    printField("Minimum extra paragraphs needed", header.mem_extra, 4);
    printField("Maximum extra paragraphs wanted", header.mem_max, 4);
    printField("Initial SS (stack segment)", (uint16_t)header.ss, 4);
    printField("Initial SP (stack pointer)", header.sp, 4);
    printField("Checksum (usually not validated)", header.checksum, 4);
    printField("Initial IP (instruction pointer)", header.ip, 4);
    printField("Initial CS (code segment)", (uint16_t)header.cs, 4);
    printField("Relocation table file offset", header.off_reloc, 4);
    printField("Overlay number", header.overlay_index, 4);

    std::cout << "\nCalculated Values\n";
    std::cout << "====================================================================\n";
    printField("Header size in bytes", headerBytes, 4);
    printField("Image size (header + code/data)", imageSize, 4);
    printField("Code/data size", codeSize, 4);
    printField("File size", fileSize, 4);
    printField("Overlay size (if any)", overlaySize, 4);

    if (opt.simulate) {
        std::cout << "\n=== DOS Load Simulation ===\n";
        std::cout << "Load base segment: " << hexFormat(opt.loadBase, 4) << "\n";
        
        // Simulate DOS loading
        uint16_t psp_seg = opt.loadBase;
        uint16_t load_seg = psp_seg + 0x10;  // PSP is 256 bytes = 16 paragraphs
        
        CS = load_seg + header.cs;
        IP = header.ip;
        SS = load_seg + header.ss;
        SP = header.sp;
        DS = psp_seg;
        ES = psp_seg;
        
        std::cout << "\nInitial Register State:\n";
        printSegOff("CS:IP", CS, IP);
        printSegOff("SS:SP", SS, SP);
        printSegOff("DS   ", DS, 0);
        printSegOff("ES   ", ES, 0);
        
        uint32_t entryLinear = (CS * 16) + IP;
        std::cout << "\nEntry point linear address: " << hexFormat(entryLinear, 8) << "\n";
    }

    // Show relocation table
    if (opt.showReloc && header.num_reloc > 0) {
        std::cout << "\n=== Relocation Table ===\n";
        std::cout << "Number of entries: " << header.num_reloc << "\n\n";
        
        size_t relocOffset = header.off_reloc;
        if (relocOffset + header.num_reloc * sizeof(RelocEntry) > fileData.size()) {
            std::cerr << "Warning: Relocation table extends beyond file size\n";
        } else {
            std::cout << "Offset   Segment\n";
            std::cout << "------   -------\n";
            
            for (uint16_t i = 0; i < header.num_reloc; i++) {
                RelocEntry reloc;
                std::memcpy(&reloc, fileData.data() + relocOffset + i * sizeof(RelocEntry), sizeof(RelocEntry));
                std::cout << hexFormat(reloc.offset, 4) << "   " << hexFormat(reloc.segment, 4) << "\n";
            }
        }
    }

    // Calculate entry point offset in file
    size_t entryOffset = headerBytes + (header.cs * 16) + header.ip;
    
    // Show hexdump
    if (opt.showHexdump) {
        if (entryOffset < fileData.size()) {
            size_t dumpSize = fileData.size() - entryOffset;
            printHexDump(fileData, entryOffset, dumpSize, "\n=== Hex Dump (from entry point to EOF) ===");
        } else {
            std::cout << "\nHex Dump: Entry point is beyond end of file.\n";
        }
    }

    // Show disassembly
    if (opt.showDisasm) {
        if (entryOffset < fileData.size()) {
            disassemble(fileData, entryOffset, header.cs, header.ip);
        } else {
            std::cout << "\nDisassembly: Entry point is beyond end of file.\n";
        }
    }

    return 0;
}
