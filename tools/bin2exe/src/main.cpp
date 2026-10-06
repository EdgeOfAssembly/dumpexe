/**
 * @file main.cpp
 * @brief bin2exe command line. Library code does not exit or open the output.
 */
#include "bin2exe/header.hpp"
#include "bin2exe/version.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace
{

namespace fs = std::filesystem;

constexpr const char k_usage[] =
    "Usage: bin2exe [options] [inputs...]\n"
    "\n"
    "  inputs    Flat binaries, or directories of them.\n"
    "            Options and inputs may be interleaved.\n"
    "            A directory expands to non-hidden *.bin and *.com\n"
    "            files in that directory only (not recursive).\n"
    "\n"
    "Options:\n"
    "  -h, --help           Show this help and exit\n"
    "  -v, --version        Show version and exit\n"
    "  -o, --output PATH    Output file, directory, or - for stdout\n"
    "      --header PATH    Copy this EXE header in front of each image\n"
    "      --no-tail        Do not append a matching original-file tail\n"
    "\n"
    "Default: write <stem>.exe beside each input, with a COM-style MZ\n"
    "header (CS:IP and SS:SP wrap to the PSP, minalloc 0). An existing\n"
    "<stem>.exe is left unchanged; pass -o to replace a regular file.\n"
    "An image larger than 65280 bytes is refused; pass --header to copy\n"
    "an original EXE header instead. --header does not rewrite page\n"
    "counts, relocations, or SS:SP. When the flat image is a prefix of\n"
    "the original file, the bytes after that prefix are appended unless\n"
    "--no-tail is set. A symlink output path is refused.\n"
    "\n";

/** Absolute read cap for one flat image. */
constexpr std::uint64_t k_max_image_bytes = 32ull * 1024ull * 1024ull;

/**
 * Whole --header file, including a tail past the 64 KiB MZ header cap.
 * The MZ header structure itself is still refused above that cap.
 */
constexpr std::uint64_t k_max_header_file_bytes =
    k_max_image_bytes + static_cast<std::uint64_t>(bin2exe::k_mz_header_max);

struct options
{
    bool help = false;
    bool version = false;
    bool have_output = false;
    bool have_header = false;
    /** Tail carry is the default. This is set only by --no-tail. */
    bool no_tail = false;
    std::string output{};
    std::string header{};
    std::vector<fs::path> inputs{};
};

void print_usage(std::FILE *stream)
{
    if (std::fputs(k_usage, stream) < 0)
    {
        return;
    }
    std::fprintf(stream, "%s\n", bin2exe::k_version_line);
}

int fail_usage(const char *message)
{
    if (message != nullptr)
    {
        std::fprintf(stderr, "bin2exe: %s\n", message);
    }
    print_usage(stderr);
    return 2;
}

bool starts_with(std::string_view text, std::string_view prefix)
{
    return text.size() >= prefix.size() && text.substr(0, prefix.size()) == prefix;
}

int parse_args(int argc, char **argv, options *out)
{
    bool end_opts = false;
    for (int i = 1; i < argc; ++i)
    {
        const std::string_view arg = argv[i] == nullptr ? std::string_view{}
                                                        : std::string_view{argv[i]};
        if (!end_opts && arg == "--")
        {
            end_opts = true;
            continue;
        }
        if (!end_opts && (arg == "-h" || arg == "--help"))
        {
            out->help = true;
            continue;
        }
        if (!end_opts && (arg == "-v" || arg == "--version"))
        {
            out->version = true;
            continue;
        }
        if (!end_opts && arg == "--no-tail")
        {
            if (out->no_tail)
            {
                return fail_usage("--no-tail given twice");
            }
            out->no_tail = true;
            continue;
        }
        if (!end_opts && (arg == "-o" || arg == "--output" || arg == "--header"))
        {
            if (i + 1 >= argc || argv[i + 1] == nullptr)
            {
                return fail_usage("missing value after option");
            }
            const std::string value = argv[++i];
            if (value.empty())
            {
                return fail_usage("missing value after option");
            }
            if (arg == "--header")
            {
                if (out->have_header)
                {
                    return fail_usage("--header given twice");
                }
                out->have_header = true;
                out->header = value;
            }
            else
            {
                if (out->have_output)
                {
                    return fail_usage("-o given twice");
                }
                out->have_output = true;
                out->output = value;
            }
            continue;
        }
        if (!end_opts && starts_with(arg, "--output="))
        {
            if (out->have_output)
            {
                return fail_usage("-o given twice");
            }
            out->have_output = true;
            out->output = std::string{arg.substr(std::string_view{"--output="}.size())};
            if (out->output.empty())
            {
                return fail_usage("missing value after option");
            }
            continue;
        }
        if (!end_opts && starts_with(arg, "--header="))
        {
            if (out->have_header)
            {
                return fail_usage("--header given twice");
            }
            out->have_header = true;
            out->header = std::string{arg.substr(std::string_view{"--header="}.size())};
            if (out->header.empty())
            {
                return fail_usage("missing value after option");
            }
            continue;
        }
        if (!end_opts && starts_with(arg, "-o") && arg.size() > 2)
        {
            if (out->have_output)
            {
                return fail_usage("-o given twice");
            }
            out->have_output = true;
            out->output = std::string{arg.substr(2)};
            continue;
        }
        if (!end_opts && starts_with(arg, "-"))
        {
            const std::string rendered{arg};
            std::fprintf(stderr, "bin2exe: unknown option: %s\n", rendered.c_str());
            print_usage(stderr);
            return 2;
        }
        out->inputs.emplace_back(std::string{arg});
    }
    return 0;
}

std::string lower_ext(const fs::path &path)
{
    std::string ext = path.extension().string();
    for (char &ch : ext)
    {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return ext;
}

bool is_batch_name(const fs::path &path)
{
    const std::string name = path.filename().string();
    if (name.empty() || name[0] == '.')
    {
        return false;
    }
    const std::string ext = lower_ext(path);
    return ext == ".bin" || ext == ".com";
}

int expand_inputs(const std::vector<fs::path> &operands, std::vector<fs::path> *files)
{
    for (const fs::path &operand : operands)
    {
        std::error_code ec;
        const bool is_dir = fs::is_directory(operand, ec);
        if (ec)
        {
            std::fprintf(stderr, "bin2exe: %s: %s\n", operand.c_str(), ec.message().c_str());
            return 1;
        }
        if (is_dir)
        {
            std::vector<fs::path> found{};
            for (const fs::directory_entry &entry : fs::directory_iterator{operand})
            {
                std::error_code child_ec;
                if (!entry.is_regular_file(child_ec) || child_ec)
                {
                    continue;
                }
                if (is_batch_name(entry.path()))
                {
                    found.push_back(entry.path());
                }
            }
            std::sort(found.begin(), found.end());
            if (found.empty())
            {
                std::fprintf(stderr, "bin2exe: no .bin or .com files in %s\n", operand.c_str());
                return 1;
            }
            files->insert(files->end(), found.begin(), found.end());
            continue;
        }
        if (!fs::is_regular_file(operand, ec) || ec)
        {
            std::fprintf(stderr, "bin2exe: cannot read %s\n", operand.c_str());
            return 1;
        }
        files->push_back(operand);
    }
    return 0;
}

fs::path exe_filename(const fs::path &input)
{
    fs::path name = input.filename();
    name.replace_extension(".exe");
    return name;
}

bool same_path(const fs::path &left, const fs::path &right)
{
    std::error_code ec;
    if (fs::exists(left, ec) && fs::exists(right, ec))
    {
        const bool same = fs::equivalent(left, right, ec);
        if (!ec && same)
        {
            return true;
        }
    }
    const fs::path canon_left = fs::weakly_canonical(left, ec);
    if (ec)
    {
        return left == right;
    }
    const fs::path canon_right = fs::weakly_canonical(right, ec);
    if (ec)
    {
        return left == right;
    }
    return canon_left == canon_right;
}

struct job
{
    fs::path input{};
    fs::path output{};
    bool to_stdout = false;
    /** True when the output path is the default <stem>.exe, not an -o path. */
    bool default_name = false;
};

int plan_jobs(const options &opt, const std::vector<fs::path> &files, std::vector<job> *jobs)
{
    if (!opt.have_output)
    {
        for (const fs::path &input : files)
        {
            job one{};
            one.input = input;
            one.output = input.parent_path() / exe_filename(input);
            one.default_name = true;
            jobs->push_back(std::move(one));
        }
        return 0;
    }
    if (opt.output == "-")
    {
        if (files.size() != 1u)
        {
            std::fprintf(stderr, "bin2exe: -o - accepts one input\n");
            return 2;
        }
        job one{};
        one.input = files[0];
        one.to_stdout = true;
        jobs->push_back(std::move(one));
        return 0;
    }

    const fs::path spec{opt.output};
    const std::string spec_text = opt.output;
    const bool trailing_sep = !spec_text.empty() &&
                              (spec_text.back() == '/' || spec_text.back() == '\\');
    std::error_code ec;
    const fs::file_status spec_status = fs::symlink_status(spec, ec);
    if (spec_status.type() == fs::file_type::not_found)
    {
        ec.clear();
    }
    else if (ec)
    {
        std::fprintf(stderr, "bin2exe: %s: %s\n", spec.c_str(), ec.message().c_str());
        return 1;
    }
    if (fs::is_symlink(spec_status))
    {
        std::fprintf(stderr, "bin2exe: refusing to follow symlink %s\n", spec.c_str());
        return 1;
    }
    const bool exists = spec_status.type() != fs::file_type::not_found;
    const bool is_dir = fs::is_directory(spec_status);

    if (is_dir || trailing_sep || (!exists && files.size() > 1u))
    {
        if (!exists)
        {
            std::fprintf(stderr, "bin2exe: note: creating directory %s\n", spec.c_str());
        }
        fs::create_directories(spec, ec);
        if (ec)
        {
            std::fprintf(stderr, "bin2exe: cannot create %s: %s\n",
                         spec.c_str(), ec.message().c_str());
            return 1;
        }
        for (const fs::path &input : files)
        {
            job one{};
            one.input = input;
            one.output = spec / exe_filename(input);
            jobs->push_back(std::move(one));
        }
        return 0;
    }

    if (files.size() == 1u)
    {
        if (spec.has_parent_path() && !spec.parent_path().empty())
        {
            fs::create_directories(spec.parent_path(), ec);
            if (ec)
            {
                std::fprintf(stderr, "bin2exe: cannot create %s: %s\n",
                             spec.parent_path().c_str(), ec.message().c_str());
                return 1;
            }
        }
        job one{};
        one.input = files[0];
        one.output = spec;
        jobs->push_back(std::move(one));
        return 0;
    }

    std::fprintf(stderr,
                 "bin2exe: warning: -o names one file and there are %zu inputs; "
                 "writing separate <stem>_<input>.exe files\n",
                 files.size());
    const fs::path dir = spec.parent_path();
    if (!dir.empty())
    {
        fs::create_directories(dir, ec);
        if (ec)
        {
            std::fprintf(stderr, "bin2exe: cannot create %s: %s\n",
                         dir.c_str(), ec.message().c_str());
            return 1;
        }
    }
    const std::string stem = spec.stem().string();
    for (const fs::path &input : files)
    {
        job one{};
        one.input = input;
        one.output = dir / (stem + "_" + input.filename().stem().string() + ".exe");
        jobs->push_back(std::move(one));
    }
    return 0;
}

int reject_collisions(const std::vector<job> &jobs, const fs::path *header_path)
{
    for (std::size_t i = 0; i < jobs.size(); ++i)
    {
        if (jobs[i].to_stdout)
        {
            continue;
        }
        if (same_path(jobs[i].output, jobs[i].input))
        {
            std::fprintf(stderr, "bin2exe: refusing to overwrite %s (pass -o)\n",
                         jobs[i].input.c_str());
            return 1;
        }
        if (header_path != nullptr && same_path(jobs[i].output, *header_path))
        {
            std::fprintf(stderr, "bin2exe: refusing to overwrite header %s (pass -o)\n",
                         header_path->c_str());
            return 1;
        }
        for (std::size_t j = 0; j < i; ++j)
        {
            if (!jobs[j].to_stdout && same_path(jobs[i].output, jobs[j].output))
            {
                std::fprintf(stderr, "bin2exe: %s and %s would both write %s\n",
                             jobs[j].input.c_str(), jobs[i].input.c_str(),
                             jobs[i].output.c_str());
                return 1;
            }
        }
    }
    return 0;
}

int reject_existing_defaults(const std::vector<job> &jobs)
{
    for (const job &one : jobs)
    {
        if (!one.default_name || one.to_stdout)
        {
            continue;
        }
        std::error_code ec;
        const fs::file_status st = fs::symlink_status(one.output, ec);
        if (st.type() == fs::file_type::not_found)
        {
            continue;
        }
        if (ec)
        {
            std::fprintf(stderr, "bin2exe: %s: %s\n", one.output.c_str(), ec.message().c_str());
            return 1;
        }
        std::fprintf(stderr, "bin2exe: %s exists; pass -o\n", one.output.c_str());
        return 1;
    }
    return 0;
}

int read_file(const fs::path &path, std::uint64_t max_bytes, bool whole_file,
              std::vector<std::uint8_t> *bytes, std::uint64_t *file_size)
{
    std::FILE *fp = std::fopen(path.c_str(), "rb");
    if (fp == nullptr)
    {
        std::fprintf(stderr, "bin2exe: cannot read %s: %s\n", path.c_str(), std::strerror(errno));
        return 1;
    }
    if (::fseeko(fp, 0, SEEK_END) != 0)
    {
        std::fprintf(stderr, "bin2exe: cannot read %s: %s\n", path.c_str(), std::strerror(errno));
        std::fclose(fp);
        fp = nullptr;
        return 1;
    }
    const off_t end = ::ftello(fp);
    if (end < 0)
    {
        std::fprintf(stderr, "bin2exe: cannot read %s: %s\n", path.c_str(), std::strerror(errno));
        std::fclose(fp);
        fp = nullptr;
        return 1;
    }
    const auto size = static_cast<std::uint64_t>(end);
    *file_size = size;
    if (whole_file && size > max_bytes)
    {
        std::fprintf(stderr, "bin2exe: %s is %llu bytes; the limit is %llu\n",
                     path.c_str(),
                     static_cast<unsigned long long>(size),
                     static_cast<unsigned long long>(max_bytes));
        std::fclose(fp);
        fp = nullptr;
        return 1;
    }
    const std::uint64_t want = whole_file ? size : (size < max_bytes ? size : max_bytes);
    if (::fseeko(fp, 0, SEEK_SET) != 0)
    {
        std::fprintf(stderr, "bin2exe: cannot read %s: %s\n", path.c_str(), std::strerror(errno));
        std::fclose(fp);
        fp = nullptr;
        return 1;
    }
    bytes->assign(static_cast<std::size_t>(want), 0);
    if (want > 0u)
    {
        const std::size_t got = std::fread(bytes->data(), 1, static_cast<std::size_t>(want), fp);
        if (got != static_cast<std::size_t>(want))
        {
            std::fprintf(stderr, "bin2exe: short read of %s\n", path.c_str());
            std::fclose(fp);
            fp = nullptr;
            bytes->clear();
            return 1;
        }
    }
    if (std::fclose(fp) != 0)
    {
        fp = nullptr;
        std::fprintf(stderr, "bin2exe: cannot read %s: %s\n", path.c_str(), std::strerror(errno));
        bytes->clear();
        return 1;
    }
    fp = nullptr;
    return 0;
}

bool write_all(int fd, const std::vector<std::uint8_t> &bytes)
{
    std::size_t offset = 0;
    while (offset < bytes.size())
    {
        const ssize_t wrote = ::write(fd, bytes.data() + offset, bytes.size() - offset);
        if (wrote < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        if (wrote == 0)
        {
            errno = EIO;
            return false;
        }
        offset += static_cast<std::size_t>(wrote);
    }
    return true;
}

/**
 * @brief Write @p bytes to @p path via mkstemp in the output directory.
 *
 * The temporary file is created with mkostemp and O_NOFOLLOW, so a symlink
 * at the temporary name is an error rather than a truncate. A symlink at
 * @p path is refused before the temporary file is created. rename replaces
 * a regular file only after the write and close succeed.
 */
int write_bytes(const fs::path &path, const std::vector<std::uint8_t> &bytes)
{
    static_assert(O_NOFOLLOW != 0, "O_NOFOLLOW is required for the temp file");

    std::error_code ec;
    const fs::file_status dest = fs::symlink_status(path, ec);
    if (dest.type() == fs::file_type::not_found)
    {
        ec.clear();
    }
    else if (ec)
    {
        std::fprintf(stderr, "bin2exe: cannot write %s: %s\n", path.c_str(), ec.message().c_str());
        return 1;
    }
    if (fs::is_symlink(dest))
    {
        std::fprintf(stderr, "bin2exe: refusing to follow symlink %s\n", path.c_str());
        return 1;
    }
    if (dest.type() != fs::file_type::not_found && !fs::is_regular_file(dest))
    {
        std::fprintf(stderr, "bin2exe: refusing to replace %s\n", path.c_str());
        return 1;
    }

    fs::path dir = path.parent_path();
    if (dir.empty())
    {
        dir = ".";
    }
    const std::string pattern = (dir / "bin2exe.XXXXXX").string();
    std::vector<char> tmpl(pattern.begin(), pattern.end());
    tmpl.push_back('\0');
    const int fd = ::mkostemp(tmpl.data(), O_NOFOLLOW);
    if (fd < 0)
    {
        std::fprintf(stderr, "bin2exe: cannot write %s: %s\n", path.c_str(), std::strerror(errno));
        return 1;
    }
    const fs::path temporary{std::string{tmpl.data()}};
    const fs::file_status tmp_status = fs::symlink_status(temporary, ec);
    if (ec || !fs::is_regular_file(tmp_status))
    {
        std::fprintf(stderr, "bin2exe: refusing to follow symlink %s\n", path.c_str());
        ::close(fd);
        std::remove(temporary.c_str());
        return 1;
    }
    if (!write_all(fd, bytes))
    {
        std::fprintf(stderr, "bin2exe: cannot write %s: %s\n", path.c_str(), std::strerror(errno));
        ::close(fd);
        std::remove(temporary.c_str());
        return 1;
    }
    if (::close(fd) != 0)
    {
        std::fprintf(stderr, "bin2exe: cannot write %s: %s\n", path.c_str(), std::strerror(errno));
        std::remove(temporary.c_str());
        return 1;
    }
    if (std::rename(temporary.c_str(), path.c_str()) != 0)
    {
        std::fprintf(stderr, "bin2exe: cannot write %s: %s\n", path.c_str(), std::strerror(errno));
        std::remove(temporary.c_str());
        return 1;
    }
    return 0;
}

int write_stdout(const std::vector<std::uint8_t> &bytes)
{
    if (bytes.empty())
    {
        return 0;
    }
    const std::size_t wrote = std::fwrite(bytes.data(), 1, bytes.size(), stdout);
    if (wrote != bytes.size() || std::fflush(stdout) != 0)
    {
        std::fprintf(stderr, "bin2exe: cannot write stdout: %s\n", std::strerror(errno));
        return 1;
    }
    return 0;
}

const char *status_label(bin2exe::status code)
{
    switch (code)
    {
    case bin2exe::status::ok:
        return "ok";
    case bin2exe::status::empty_image:
        return "empty input";
    case bin2exe::status::com_too_large:
        return "image is larger than 65280 bytes; use --header";
    case bin2exe::status::page_overflow:
        return "file does not fit in DOS page fields";
    case bin2exe::status::not_mz:
        return "header is not an MZ executable";
    case bin2exe::status::header_too_small:
        return "EXE header is shorter than 32 bytes";
    case bin2exe::status::header_truncated:
        return "EXE header does not fit in the file";
    case bin2exe::status::header_too_large:
        return "EXE header is larger than 65536 bytes";
    }
    return "failed";
}

bool header_fault(bin2exe::status code)
{
    switch (code)
    {
    case bin2exe::status::not_mz:
    case bin2exe::status::header_too_small:
    case bin2exe::status::header_truncated:
    case bin2exe::status::header_too_large:
        return true;
    case bin2exe::status::ok:
    case bin2exe::status::empty_image:
    case bin2exe::status::com_too_large:
    case bin2exe::status::page_overflow:
        return false;
    }
    return false;
}

int convert_one(const job &one, bool header_mode, bool carry_tail,
                const fs::path &header_path,
                std::span<const std::uint8_t> header_prefix,
                std::uint64_t header_file_size)
{
    std::error_code ec;
    const auto file_size = static_cast<std::uint64_t>(fs::file_size(one.input, ec));
    if (ec)
    {
        std::fprintf(stderr, "bin2exe: cannot read %s: %s\n",
                     one.input.c_str(), ec.message().c_str());
        return 1;
    }
    if (file_size == 0u)
    {
        std::fprintf(stderr, "bin2exe: %s: empty input\n", one.input.c_str());
        return 1;
    }
    if (!header_mode && file_size > bin2exe::k_com_image_max)
    {
        std::fprintf(stderr,
                     "bin2exe: %s is %llu bytes; a COM wrap holds at most 65280; use --header\n",
                     one.input.c_str(),
                     static_cast<unsigned long long>(file_size));
        return 1;
    }
    if (file_size > k_max_image_bytes)
    {
        std::fprintf(stderr, "bin2exe: %s is %llu bytes; the limit is %llu\n",
                     one.input.c_str(),
                     static_cast<unsigned long long>(file_size),
                     static_cast<unsigned long long>(k_max_image_bytes));
        return 1;
    }

    std::vector<std::uint8_t> image{};
    std::uint64_t size_again = 0;
    if (read_file(one.input, k_max_image_bytes, true, &image, &size_again) != 0)
    {
        return 1;
    }

    bin2exe::build_result built{};
    if (header_mode)
    {
        built = bin2exe::copy_mz_header(header_prefix, header_file_size, image, carry_tail);
    }
    else
    {
        built = bin2exe::wrap_com(image);
    }
    if (built.code != bin2exe::status::ok)
    {
        const char *named = one.input.c_str();
        if (header_mode && header_fault(built.code))
        {
            named = header_path.c_str();
        }
        std::fprintf(stderr, "bin2exe: %s: %s\n", named, status_label(built.code));
        return 1;
    }
    /* Length mismatch is quiet when the matching tail was appended. */
    if (built.payload_length_differs && !built.tail_appended)
    {
        std::fprintf(stderr,
                     "bin2exe: warning: %s is %llu bytes; original payload is %llu bytes\n",
                     one.input.c_str(),
                     static_cast<unsigned long long>(image.size()),
                     static_cast<unsigned long long>(built.original_payload_bytes));
    }
    if (one.to_stdout)
    {
        return write_stdout(built.bytes);
    }
    return write_bytes(one.output, built.bytes);
}

int run(int argc, char **argv)
{
    options opt{};
    const int parsed = parse_args(argc, argv, &opt);
    if (parsed != 0)
    {
        return parsed;
    }
    if (opt.help || argc <= 1)
    {
        print_usage(stdout);
        return 0;
    }
    if (opt.version)
    {
        if (std::fprintf(stdout, "%s\n", bin2exe::k_version_line) < 0)
        {
            return 1;
        }
        return 0;
    }
    if (opt.inputs.empty())
    {
        return fail_usage("missing input file");
    }

    std::vector<fs::path> files{};
    const int expanded = expand_inputs(opt.inputs, &files);
    if (expanded != 0)
    {
        return expanded;
    }

    std::vector<job> jobs{};
    const int planned = plan_jobs(opt, files, &jobs);
    if (planned != 0)
    {
        return planned;
    }

    std::vector<std::uint8_t> header_prefix{};
    std::uint64_t header_file_size = 0;
    fs::path header_path{};
    const fs::path *header_ptr = nullptr;
    if (opt.have_header)
    {
        header_path = opt.header;
        header_ptr = &header_path;
        if (read_file(header_path, k_max_header_file_bytes, true,
                      &header_prefix, &header_file_size) != 0)
        {
            return 1;
        }
    }

    const int collisions = reject_collisions(jobs, header_ptr);
    if (collisions != 0)
    {
        return collisions;
    }
    const int existing = reject_existing_defaults(jobs);
    if (existing != 0)
    {
        return existing;
    }

    for (const job &one : jobs)
    {
        const int rc = convert_one(one, opt.have_header, !opt.no_tail, header_path,
                                   header_prefix, header_file_size);
        if (rc != 0)
        {
            return rc;
        }
    }
    return 0;
}

} /* namespace */

int main(int argc, char **argv)
{
    try
    {
        return run(argc, argv);
    }
    catch (const std::exception &ex)
    {
        std::fprintf(stderr, "bin2exe: %s\n", ex.what());
        return 1;
    }
}
