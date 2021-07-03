package supermonkeyballtools;

/*
Ideas:
- Don't export separate fields for unknown fields in structs (export single array)
- Static assert struct sizes / pack structs?
- Export enums as modern C++ fixed-size enums
- Sort enums
- Fix undefined/pointer types for extern exporting
 */

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Iterator;
import java.util.regex.Pattern;

public class CppExport {
    private Program program;
    private static String EOL = System.getProperty("line.separator");
    private static Pattern cIdentifierPattern = Pattern.compile("[a-zA-Z_][a-zA-Z0-9_]*");

    public CppExport(Program program) {
        this.program = program;
    }

    private void genExternDecls(CppDataTypeWriter typeWriter, Writer out) throws CancelledException, IOException {
        out.write("extern \"C\" {" + EOL);

        // Write extern global variable decls
        out.write("/* Global data */" + EOL);
        for (Iterator<Symbol> it = program.getSymbolTable().getSymbolIterator(); it.hasNext(); ) {
            Symbol s = it.next();

            if (!s.getSymbolType().equals(SymbolType.LABEL)) continue;
            Data data = program.getListing().getDataAt(s.getAddress());
            if (data == null) continue;
            DataType type = data.getDataType();
            if (!cIdentifierPattern.matcher(s.getName()).matches()) continue;

            String typeDecl = typeWriter.getTypeDeclaration(s.getName(), type, data.getLength(),
                    false, false, TaskMonitor.DUMMY);
            out.write("    extern " + typeDecl + ";" + EOL);
        }

        // Write function decls
        out.write(EOL + "/* Function decls */" + EOL);
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function func = it.next();

            // Only export functions with non-null, valid names
            String name = func.getName();
            if (name.startsWith("FUN_")) continue;
            if (!cIdentifierPattern.matcher(name).matches()) continue;

            String funcDecl = func.getPrototypeString(true, false);
            out.write("    " + funcDecl + ";" + EOL);
        }

        out.write("} // extern \"C\"" + EOL + EOL);
    }

    public String genCppHeader() {
        // TODO write directly to a file instead of generating an intermediate String first
        StringWriter buf = new StringWriter();
        CppDataTypeWriter typeWriter = null;
        try {
            typeWriter = new CppDataTypeWriter(program.getDataTypeManager(), buf);
            typeWriter.write(program.getDataTypeManager(), TaskMonitor.DUMMY);
            genExternDecls(typeWriter, buf);
        } catch (CancelledException | IOException e) {
            // What can we realistically do?
        }

        return buf.toString();
    }
}
