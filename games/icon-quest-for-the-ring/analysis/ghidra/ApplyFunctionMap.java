// Apply function_map labels at LOAD-IMAGE offsets (file_offset - 0x200).
// Ghidra MZ: CODE @ 1000:0000 is the load image, NOT the raw file.
//
// labels.tsv (v1.1) columns:
//   image  file_offset  image_offset  ip  ghidra_name  tier  kind  role  prologue_hex
//
// BUGFIX: v1.0 used file_offset as CODE address (+0x200 wrong). Always use image_offset.
//@category ICON
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ApplyFunctionMap extends GhidraScript {
	/** MZ header size for ICON images (e_cparhdr * 16 = 0x200). */
	private static final long MZ_HEADER_BYTES = 0x200L;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String tsv = args.length > 0 ? args[0]
			: "/tmp/dumpexe/games/icon-quest-for-the-ring/analysis/ghidra/labels.tsv";
		boolean clearFirst = !(args.length > 1 && "noclear".equalsIgnoreCase(args[1]));

		String progName = currentProgram.getName().toUpperCase();
		String pn = progName.split("\\.")[0].toUpperCase();
		List<String> lines = Files.readAllLines(Paths.get(tsv));
		if (lines.isEmpty()) {
			printerr("empty TSV: " + tsv);
			return;
		}

		// Detect header: v1.1 has image_offset column
		String header = lines.get(0).toLowerCase();
		boolean v11 = header.contains("image_offset");

		Set<String> ourNames = new HashSet<>();
		for (int i = 1; i < lines.size(); i++) {
			String[] p = split(lines.get(i));
			if (p == null) {
				continue;
			}
			if (!matchesImage(p[0], pn, progName)) {
				continue;
			}
			String name = v11 ? p[4] : p[3];
			ourNames.add(name);
		}

		if (clearFirst && !ourNames.isEmpty()) {
			int removed = removeLabelsByName(ourNames);
			println("ApplyFunctionMap: removed stale labels=" + removed);
		}

		Address min = currentProgram.getMinAddress();
		Memory mem = currentProgram.getMemory();
		int applied = 0;
		int skipped = 0;

		for (int i = 1; i < lines.size(); i++) {
			String[] p = split(lines.get(i));
			if (p == null) {
				continue;
			}
			if (!matchesImage(p[0], pn, progName)) {
				continue;
			}

			long imageOff;
			String name;
			if (v11) {
				// image, file_offset, image_offset, ip, ghidra_name, ...
				if (p.length < 5) {
					skipped++;
					continue;
				}
				imageOff = parseHex(p[2]);
				name = p[4];
			}
			else {
				// legacy v1.0: image, file_offset, ip, ghidra_name — convert file→image
				if (p.length < 4) {
					skipped++;
					continue;
				}
				long fo = parseHex(p[1]);
				imageOff = fo >= MZ_HEADER_BYTES ? fo - MZ_HEADER_BYTES : fo;
				name = p[3];
			}

			Address addr = min.add(imageOff);
			if (!mem.contains(addr)) {
				println("skip OOR " + name + " image_off=0x" + Long.toHexString(imageOff));
				skipped++;
				continue;
			}
			createLabel(addr, name, true, SourceType.USER_DEFINED);
			applied++;
		}

		println("ApplyFunctionMap.java: " + progName
			+ " applied=" + applied
			+ " skipped=" + skipped
			+ " addressing=image_offset"
			+ " minAddress=" + min
			+ " tsv=" + (v11 ? "v1.1" : "v1.0-legacy"));
	}

	private static String[] split(String line) {
		if (line == null) {
			return null;
		}
		line = line.trim();
		if (line.isEmpty() || line.startsWith("#")) {
			return null;
		}
		return line.split("\t", -1);
	}

	private static long parseHex(String s) {
		s = s.trim();
		if (s.startsWith("0x") || s.startsWith("0X")) {
			return Long.parseLong(s.substring(2), 16);
		}
		// bare hex (may be decimal-looking; treat as hex if has a-f or leading 0)
		if (s.matches("(?i)[0-9a-f]+")) {
			return Long.parseLong(s, 16);
		}
		return Long.parseLong(s);
	}

	private static boolean matchesImage(String image, String pn, String progName) {
		String imgBase = image.split("\\.")[0].toUpperCase();
		return pn.equals(imgBase) || progName.equalsIgnoreCase(image);
	}

	private int removeLabelsByName(Set<String> names) throws Exception {
		SymbolTable st = currentProgram.getSymbolTable();
		int removed = 0;
		for (String name : names) {
			SymbolIterator it = st.getSymbols(name);
			while (it.hasNext()) {
				Symbol sym = it.next();
				st.removeSymbolSpecial(sym);
				removed++;
			}
		}
		return removed;
	}
}
