// bin2ne - rebuild an NE (Win16) file from dumpexe's per-segment listings.
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Usage: bin2ne MAP OUT
//   MAP is the STEM.nemap that `dumpexe --uasm` wrote next to the listings.
//   Each `seg N OFFSET LENGTH BIN` line names the `uasm -bin` output of
//   STEM_segN.asm; it is laid onto the skeleton (STEM.neskel) at OFFSET.
// Run with no arguments it prints usage and exits 0.

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

static bool read_file(const std::filesystem::path& p, std::vector<uint8_t>& out)
{
    std::ifstream f(p, std::ios::binary);
    if (!f)
        return false;
    out.assign(std::istreambuf_iterator<char>(f), {});
    return true;
}

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cout << "usage: bin2ne MAP OUT\n"
                     "  MAP  STEM.nemap written by dumpexe --uasm on an NE file\n"
                     "  OUT  rebuilt NE file\n";
        return argc == 1 ? 0 : 2;
    }
    const std::filesystem::path map_path(argv[1]);
    const std::filesystem::path dir = map_path.parent_path();
    std::ifstream map(map_path);
    if (!map)
    {
        std::cerr << "bin2ne: cannot read " << map_path << "\n";
        return 1;
    }
    std::vector<uint8_t> out;
    size_t want_size = 0;
    std::string line;
    size_t lineno = 0;
    while (std::getline(map, line))
    {
        ++lineno;
        if (line.empty() || line[0] == '#')
            continue;
        std::istringstream ss(line);
        std::string kw;
        ss >> kw;
        if (kw == "skel")
        {
            std::string f;
            ss >> f;
            if (!read_file(dir / f, out))
            {
                std::cerr << "bin2ne: cannot read skeleton " << f << "\n";
                return 1;
            }
        }
        else if (kw == "size")
        {
            ss >> want_size;
        }
        else if (kw == "seg")
        {
            unsigned n = 0;
            size_t off = 0;
            size_t len = 0;
            std::string f;
            ss >> n >> off >> len >> f;
            std::vector<uint8_t> b;
            if (!read_file(dir / f, b))
            {
                std::cerr << "bin2ne: segment " << n << ": cannot read " << f << "\n";
                return 1;
            }
            if (b.size() != len)
            {
                std::cerr << "bin2ne: segment " << n << ": " << f << " is " << b.size()
                          << " bytes, map says " << len << "\n";
                return 1;
            }
            if (off + len > out.size())
            {
                std::cerr << "bin2ne: segment " << n << " past the skeleton end\n";
                return 1;
            }
            std::copy(b.begin(), b.end(), out.begin() + static_cast<std::ptrdiff_t>(off));
        }
        else
        {
            std::cerr << "bin2ne: " << map_path << ":" << lineno << ": unknown keyword " << kw << "\n";
            return 1;
        }
    }
    if (want_size != 0 && out.size() != want_size)
    {
        std::cerr << "bin2ne: skeleton size mismatch\n";
        return 1;
    }
    std::ofstream o(argv[2], std::ios::binary);
    o.write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
    return o ? 0 : 1;
}
