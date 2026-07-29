//Apply function_map.json labels (minimal: read labels.tsv for current program)
//@category ICON
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.Address;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class ApplyFunctionMap extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String tsv = args.length > 0 ? args[0]
            : "/tmp/dumpexe/games/icon-quest-for-the-ring/analysis/ghidra/labels.tsv";
        String progName = currentProgram.getName().toUpperCase();
        String baseName = progName.contains(".") ? progName : progName + ".EXE";
        // normalize
        if (!progName.contains(".")) {
            // try match ICON / ICON0
        }
        int applied = 0, skipped = 0;
        List<String> lines = Files.readAllLines(Paths.get(tsv));
        Address min = currentProgram.getMinAddress();
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) continue;
            String[] p = line.split("\t");
            if (p.length < 4) continue;
            String image = p[0];
            String imgBase = image.split("\\.")[0].toUpperCase();
            String pn = progName.split("\\.")[0].toUpperCase();
            if (!pn.equals(imgBase) && !progName.equalsIgnoreCase(image)) {
                continue;
            }
            long fo = Long.decode(p[1]);
            String name = p[3];
            Address addr = min.add(fo);
            if (!currentProgram.getMemory().contains(addr) && fo >= 0x200) {
                addr = min.add(fo - 0x200);
            }
            if (!currentProgram.getMemory().contains(addr)) {
                skipped++;
                continue;
            }
            createLabel(addr, name, true, SourceType.USER_DEFINED);
            applied++;
        }
        println("ApplyFunctionMap.java: " + progName + " applied=" + applied + " skipped=" + skipped);
    }
}
