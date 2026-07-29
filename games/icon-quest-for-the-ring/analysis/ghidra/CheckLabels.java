// Verify USER_DEFINED labels sit on bytes matching label_expect.json / labels.tsv prologues.
// Proof that image_offset addressing is correct (not file_offset +0x200).
//@category ICON
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class CheckLabels extends GhidraScript {
	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String tsv = args.length > 0 ? args[0]
			: "/tmp/dumpexe/games/icon-quest-for-the-ring/analysis/ghidra/labels.tsv";
		String progName = currentProgram.getName().toUpperCase();
		String pn = progName.split("\\.")[0].toUpperCase();
		List<String> lines = Files.readAllLines(Paths.get(tsv));
		Address min = currentProgram.getMinAddress();
		Memory mem = currentProgram.getMemory();
		SymbolTable st = currentProgram.getSymbolTable();

		int ok = 0;
		int fail = 0;
		int missing = 0;
		List<String> failures = new ArrayList<>();

		for (int i = 1; i < lines.size(); i++) {
			String line = lines.get(i).trim();
			if (line.isEmpty()) {
				continue;
			}
			String[] p = line.split("\t", -1);
			if (p.length < 5) {
				continue;
			}
			String imgBase = p[0].split("\\.")[0].toUpperCase();
			if (!pn.equals(imgBase) && !progName.equalsIgnoreCase(p[0])) {
				continue;
			}

			long imageOff = Long.decode(normHex(p[2]));
			String name = p[4];
			String expectHex = (p.length > 8 && p[8] != null && !p[8].isEmpty())
				? p[8].toLowerCase()
				: "";

			// Locate symbol
			Symbol found = null;
			SymbolIterator it = st.getSymbols(name);
			while (it.hasNext()) {
				found = it.next();
				break;
			}
			if (found == null) {
				missing++;
				failures.add("MISSING " + name);
				continue;
			}

			Address want = min.add(imageOff);
			Address got = found.getAddress();
			if (!got.equals(want)) {
				fail++;
				failures.add("ADDR " + name + " want=" + want + " got=" + got);
				continue;
			}

			// Byte check when prologue known
			if (!expectHex.isEmpty() && expectHex.matches("[0-9a-f]+")) {
				int n = expectHex.length() / 2;
				if (n > 16) {
					n = 16;
				}
				byte[] buf = new byte[n];
				try {
					mem.getBytes(got, buf);
				}
				catch (Exception ex) {
					fail++;
					failures.add("READ " + name + " @ " + got + ": " + ex.getMessage());
					continue;
				}
				StringBuilder sb = new StringBuilder();
				for (byte b : buf) {
					sb.append(String.format("%02x", b & 0xff));
				}
				String actual = sb.toString();
				String exp = expectHex.substring(0, n * 2);
				if (!actual.equals(exp)) {
					fail++;
					failures.add("BYTES " + name + " @ " + got
						+ " expect=" + exp + " actual=" + actual);
					continue;
				}
			}

			ok++;
		}

		println("CheckLabels: " + progName
			+ " ok=" + ok
			+ " fail=" + fail
			+ " missing=" + missing
			+ " minAddress=" + min);

		// Critical spot-checks for ICON.EXE
		if (pn.equals("ICON") && progName.contains("EXE")) {
			spot(mem, min, st, "jt_01_pascal_near", 0xD5L, "558bec");
			spot(mem, min, st, "pascal_mt_startup_call__0200", 0x0L, "e82865");
			spot(mem, min, st, "rtl_error_string__02EE", 0xEEL, "506173"); // "Pas"
		}

		for (String f : failures) {
			if (failures.indexOf(f) < 40) {
				println("  FAIL: " + f);
			}
		}
		if (fail > 0 || missing > 0) {
			throw new Exception("CheckLabels failed: fail=" + fail + " missing=" + missing);
		}
	}

	private void spot(Memory mem, Address min, SymbolTable st, String name, long off, String expPrefix)
		throws Exception {
		Symbol sym = null;
		SymbolIterator it = st.getSymbols(name);
		if (it.hasNext()) {
			sym = it.next();
		}
		if (sym == null) {
			println("  SPOT FAIL missing " + name);
			throw new Exception("spot missing " + name);
		}
		Address want = min.add(off);
		if (!sym.getAddress().equals(want)) {
			println("  SPOT FAIL " + name + " addr " + sym.getAddress() + " want " + want);
			throw new Exception("spot addr " + name);
		}
		byte[] buf = new byte[expPrefix.length() / 2];
		mem.getBytes(want, buf);
		StringBuilder sb = new StringBuilder();
		for (byte b : buf) {
			sb.append(String.format("%02x", b & 0xff));
		}
		if (!sb.toString().startsWith(expPrefix.toLowerCase())) {
			println("  SPOT FAIL " + name + " bytes " + sb + " expect prefix " + expPrefix);
			throw new Exception("spot bytes " + name);
		}
		println("  SPOT OK " + name + " @ " + want + " bytes=" + sb);
	}

	private static String normHex(String s) {
		s = s.trim();
		if (s.startsWith("0x") || s.startsWith("0X")) {
			return s;
		}
		return "0x" + s;
	}
}
