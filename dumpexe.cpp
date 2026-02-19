// dumpexe.cpp - MS-DOS MZ EXE header dumper, analyzer, and single-pass disassembler
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
// Target: 16-bit MS-DOS MZ EXE files only

#include "dumpexe.h"
#include <filesystem>

int main(int argc, char* argv[]) {
    Options opts;
    if (!opts.parse(argc, argv)) {
        usage(argv[0]);
        return 1;
    }
    
    // Handle --help
    if (opts.showHelp) {
        usage(argv[0]);
        return 0;
    }
    
    // Handle --version
    if (opts.showVersion) {
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
    
    // Must have filename if not help/version
    if (opts.filename.empty()) {
        std::cerr << "Error: No EXE file specified\n\n";
        usage(argv[0]);
        return 1;
    }
    
    // Check for disassembly request without Capstone support
#if !HAS_CAPSTONE
    if (opts.showDisasm || opts.showAll) {
        std::cerr << "Warning: Disassembly requested but Capstone support not available\n";
        std::cerr << "         Rebuild with libcapstone-dev installed for disassembly features\n\n";
        opts.showDisasm = false;
        // showAll can still show other sections (reloc, hexdump) even without disasm
    }
#endif


   int64_t dosFileSize64;
   try {
	dosFileSize64 = static_cast<int64_t>(std::filesystem::file_size(opts.filename));
   } catch (...) {
	std::cerr << "Error: Cannot get file size of '" << opts.filename << "'\n";
	return 1;
   }

    // Open file
    std::ifstream file(opts.filename, std::ios::binary );
    if (!file) {
        std::cerr << "Error: Cannot open file '" << opts.filename << "'\n";
        return 1;
    }

    // Read header
    MZHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    // Validate MZ signature
    if (header.signature != 0x5A4D) {	// 'MZ'
        std::cerr << "Error: Not a valid MZ EXE file\n";
        return 1;
    }

    // Validate num_blocks
    if (header.num_blocks == 0) {
        std::cerr << "Error: Invalid header (zero pages)\n";
        return 1;
    }

    // Calculate sizes
    int64_t headerSizeBytes64 = static_cast<int64_t>(header.header_size) * 16LL;
    if(headerSizeBytes64 <= 0 || headerSizeBytes64 > dosFileSize64) {
	std::cerr << "Error: Invalid header size field\n";
	return 1;
    }

    int64_t csBytes = static_cast<int64_t>(header.cs) * 16LL;
    int64_t entryPointImageOffset64 = csBytes + static_cast<int64_t>(header.ip);
    int64_t loadImageSize64 = ((header.num_blocks - 1) * 512 + header.final_len) - headerSizeBytes64;
    int64_t entryPointFileOffset64 = headerSizeBytes64 + entryPointImageOffset64;

    if (csBytes < 0 || entryPointImageOffset64 < 0 || entryPointFileOffset64 < 0 ||
	entryPointFileOffset64 > dosFileSize64) {
        std::cerr << "Error: Invalid CS:IP or entry point outside file\n";
        return 1;
    }


    size_t headerSizeBytes = static_cast<size_t>(headerSizeBytes64);
    size_t entryPointFileOffset = static_cast<size_t>(entryPointFileOffset64);
    size_t entryPointImageOffset = static_cast<size_t>(entryPointImageOffset64);

    int64_t extraBytes = dosFileSize64 - loadImageSize64;

    // Print static header info
    std::cout << "Display of File " << opts.filename << "\n\n";
    
    printField("DOS File Size", dosFileSize64, 5);
    printField("Load Image Size", loadImageSize64, 5);
    printField("Relocation Table entry count", header.num_reloc, 4);
    printField("Relocation Table address", header.off_reloc, 4);
    printField("Header Size", headerSizeBytes, 4);
    printField("Minimum Extra Memory", header.mem_extra, 4);
    
    if (header.mem_max == 0xFFFF) {
        std::cout << std::left << std::setw(50) << "Maximum Memory Requirement"
                  << std::right << std::setw(5) << "FFFFh"
                  << "  ( 65535. paragraphs = 1048560 bytes, all available )\n";
    } else {
        printField("Maximum Memory Requirement", header.mem_max * 16, 4);
    }
    
    printField("File load checksum", header.checksum, 4);
    printField("Overlay Number", header.overlay_index, 4);
    printField("Entry Point File Offset", entryPointFileOffset, 5);
    printField("Entry Point Image Offset", entryPointImageOffset, 5);
    
    std::cout << "\n";
    printSegOff("Initial Stack Segment  (SS:SP)", header.ss, header.sp);
    printSegOff("Program Entry Point    (CS:IP)", header.cs, header.ip);
    
    if (extraBytes > 0) {
        std::cout << "\nNote: File contains " << std::dec << extraBytes
                  << " extra bytes beyond declared size (overlay/debug data?)\n";
    }
    
    // Read entire file
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> fileData(dosFileSize64);
    file.read(reinterpret_cast<char*>(fileData.data()), dosFileSize64);
    file.close();
    
    // ──────────────────────────────────────────────────────────────
    // Relocation table + padding
    // ──────────────────────────────────────────────────────────────
    std::vector<RelocEntry> relocs;
    if (opts.showReloc || opts.showAll) {
        size_t relocStart = header.off_reloc;
        size_t relocEntrySize = sizeof(RelocEntry);
        size_t relocTableBytes = static_cast<size_t>(header.num_reloc) * relocEntrySize;
        size_t relocEnd = relocStart + relocTableBytes;

        // Padding after fixed header, before relocation area
        if (relocStart > sizeof(MZHeader)) {
            size_t padSize = relocStart - sizeof(MZHeader);
            if (padSize > 0) {
                printHexDump(fileData, sizeof(MZHeader), padSize, "Padding:");
            }
        }

        if (header.num_reloc > 0) {
	    if (relocStart <= static_cast<size_t>(dosFileSize64) &&
                relocTableBytes <= static_cast<size_t>(dosFileSize64) - relocStart) {
                relocs.resize(header.num_reloc);
                std::memcpy(relocs.data(), fileData.data() + relocStart, relocTableBytes);

                std::cout << "\n=== Relocation Table (" << std::dec << header.num_reloc << " entries) ===\n";
                std::cout << "Entry  Segment:Offset  File Location (Hex)  Linear Offset\n";
                std::cout << "-----  --------------  -------------------  -------------\n";

                for (size_t i = 0; i < relocs.size(); ++i) {
                    uint32_t fileLoc = headerSizeBytes + (relocs[i].segment * 16u) + relocs[i].offset;
                    uint32_t linear  =                   (relocs[i].segment * 16u) + relocs[i].offset;

                    std::cout << std::right << std::setw(5) << std::dec << i << "  "
                              << std::hex << std::uppercase << std::setfill('0')
                              << std::setw(4) << relocs[i].segment << ":"
                              << std::setw(4) << relocs[i].offset << "        "
                              << std::setw(8) << fileLoc << "h          "
                              << std::setw(6) << linear  << "h\n";
                }
            } else {
                std::cerr << "\n[Warning] Relocation table extends beyond file end. Skipped.\n";
            }
        }

        // Padding between end of reloc area and start of load image
        if (relocEnd < headerSizeBytes) {
            size_t padSize = headerSizeBytes - relocEnd;
            if (padSize > 0) {
                printHexDump(fileData, relocEnd, padSize, "Padding:");
            }
        }
    }


    
    // ──────────────────────────────────────────────────────────────
    // Hexdump
    // ──────────────────────────────────────────────────────────────
    if (opts.showHexdump || opts.showAll) {
        if (entryPointFileOffset < fileData.size()) {
            size_t dumpSize = fileData.size() - entryPointFileOffset;
            printHexDump(fileData, entryPointFileOffset, dumpSize,
                         "=== Hex+ASCII Dump (from entry point to EOF) ===");
        }
    } else {
        if (!opts.showReloc && !opts.showDisasm) {
            if (entryPointFileOffset < fileData.size()) {
                size_t dumpSize = std::min((size_t)64, fileData.size() - entryPointFileOffset);
                printHexDump(fileData, entryPointFileOffset, dumpSize,
                             "Code at Entry Point (first 64 bytes):");
            }
        }
    }
    
    // Disassembly section
#if HAS_CAPSTONE
    if (opts.showDisasm || opts.showAll) {
        disassemble(fileData, entryPointFileOffset, header.cs, header.ip);
    }
#endif
    
    // Simulation mode
    if (opts.simulate) {
        std::cout << "\n========================================\n";
        std::cout << "=== DOS LOAD SIMULATION ===\n";
        std::cout << "========================================\n";
        std::cout << "Load Base Segment: " << hexFormat(opts.loadBase, 4) << "\n\n";
        
        CS = opts.loadBase + header.cs;
        IP = header.ip;
        SS = opts.loadBase + header.ss;
        SP = header.sp;
        DS = opts.loadBase;
        ES = opts.loadBase;
        AX = 0; BX = 0; CX = 0; DX = 0;
        SI = 0; DI = 0; BP = 0;
        FLAGS = 0x0002;
        
        std::cout << "Initial Register State:\n";
        std::cout << "  CS:IP = " << hexFormat(CS, 4) << ":" << hexFormat(IP, 4) << "\n";
        std::cout << "  SS:SP = " << hexFormat(SS, 4) << ":" << hexFormat(SP, 4) << "\n";
        std::cout << "  DS    = " << hexFormat(DS, 4) << "\n";
        std::cout << "  ES    = " << hexFormat(ES, 4) << "\n";
        std::cout << "  FLAGS = " << hexFormat(FLAGS, 4) << "\n\n";
        
        if (!relocs.empty()) {
            std::cout << "=== Relocation Fixups ===\n";
            std::cout << "Entry  Image Offset  Original Seg  Relocated Seg  Change\n";
            std::cout << "-----  ------------  ------------  -------------  ------\n";
            
            for (size_t i = 0; i < relocs.size(); i++) {
                uint32_t fileLocation = headerSizeBytes + (relocs[i].segment * 16) + relocs[i].offset;
                uint32_t imageOffset = (relocs[i].segment * 16) + relocs[i].offset;
                
                uint16_t originalSeg = 0;
                if (fileLocation + 1 < fileData.size()) {
                    originalSeg = fileData[fileLocation] | (fileData[fileLocation + 1] << 8);
                }
                
                uint16_t relocatedSeg = originalSeg + opts.loadBase;
                
                std::cout << std::right << std::setw(5) << std::dec << i << "  "
                          << std::hex << std::uppercase << std::setfill('0')
                          << std::setw(6) << imageOffset << "h      "
                          << std::setw(4) << originalSeg << "h          "
                          << std::setw(4) << relocatedSeg << "h         +"
                          << std::setw(4) << opts.loadBase << "h\n";
            }
        }
        
#if HAS_CAPSTONE
        std::cout << "\n=== Register Tracing ===\n";
        std::cout << "Note: Best-effort trace for common instructions.\n\n";
        
        // Guard against entry point beyond file size
        if (entryPointFileOffset >= fileData.size()) {
            std::cout << "Register tracing skipped: entry point file offset ("
                      << entryPointFileOffset
                      << ") is beyond file size (" << fileData.size()
                      << ").\n";
        } else {
            csh handle;
            cs_insn *insn;
            
            // Calculate entry linear address for disassembly
            uint32_t entryLinear = (CS * 16) + IP;
            
            if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) == CS_ERR_OK) {
                size_t codeSize = std::min((size_t)128, fileData.size() - entryPointFileOffset);
                const uint8_t* code = fileData.data() + entryPointFileOffset;
                
                size_t count = cs_disasm(handle, code, codeSize, entryLinear, 20, &insn);
            
            if (count > 0) {
                for (size_t i = 0; i < count; i++) {
                    std::string mnem = insn[i].mnemonic;
                    std::string ops = insn[i].op_str;
                    
                    std::cout << std::hex << std::setw(4) << std::setfill('0')
                              << (insn[i].address & 0xFFFF) << ": "
                              << std::setw(8) << std::left << mnem << " " << ops;
                    
                    if (mnem == "xor" && ops.find("ax,ax") != std::string::npos) {
                        AX = 0;
                        std::cout << "  ; AX = 0000h";
                    } else if (mnem == "xor" && ops.find("bx,bx") != std::string::npos) {
                        BX = 0;
                        std::cout << "  ; BX = 0000h";
                    } else if (mnem == "push") {
                        SP -= 2;
                        std::cout << "  ; SP = " << hexFormat(SP, 4);
                    } else if (mnem == "pop") {
                        SP += 2;
                        std::cout << "  ; SP = " << hexFormat(SP, 4);
                    } else if (mnem == "int") {
                        std::cout << "  ; interrupt";
                    }
                    
                    std::cout << "\n";
                }
                    cs_free(insn, count);
                }
                cs_close(&handle);
            }
        }
#endif
    }
    
    return 0;
}
