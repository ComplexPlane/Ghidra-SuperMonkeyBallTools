package supermonkeyballtools;

import ghidra.program.model.data.*;
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
    private final Program program;
    private static final String EOL = System.getProperty("line.separator");
    private static final Pattern cIdentifierPattern = Pattern.compile("[a-zA-Z_][a-zA-Z0-9_]*");

    public CppExport(Program program) {
        this.program = program;
    }

    private void genExternDecls(CppDataTypeWriter typeWriter, Writer out) throws CancelledException, IOException {
        out.write("typedef void *pointer;" + EOL + EOL);

        out.write("extern \"C\" {" + EOL);

        // Write extern global variable decls
        out.write("    /* Global data */" + EOL);
        for (Iterator<Symbol> it = program.getSymbolTable().getSymbolIterator(); it.hasNext(); ) {
            Symbol s = it.next();

            if (!s.getSymbolType().equals(SymbolType.LABEL)) continue;
            Data data = program.getListing().getDataAt(s.getAddress());
            if (data == null) continue;
            DataType type = data.getDataType();
            if (!cIdentifierPattern.matcher(s.getName()).matches()) continue;

            String vol = program.getMemory().getBlock(s.getAddress()).isVolatile() ? "volatile " : "";
            String typeDecl = typeWriter.getTypeDeclaration(s.getName(), type, data.getLength(),
                    false, false, false, TaskMonitor.DUMMY);
            out.write("    extern " + vol + typeDecl + ";" + EOL);
        }

        // Write function decls
        out.write(EOL + "    /* Function decls */" + EOL);
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function func = it.next();
            FunctionDefinition def = (FunctionDefinition) func.getSignature();

            // Only export functions with non-null, valid names
            String name = func.getName();
            if (name.startsWith("FUN_")) continue;
            if (!cIdentifierPattern.matcher(name).matches()) continue;

            String funcDecl = typeWriter.getFunctionPointerString(def, func.getName(), null, false, TaskMonitor.DUMMY);
            out.write("    " + funcDecl + ";" + EOL);
        }

        out.write("} // extern \"C\"" + EOL + EOL);
    }

    public String genCppHeader() {
        // TODO write directly to a file instead of generating an intermediate String first
        StringWriter buf = new StringWriter();
        buf.write("#pragma once" + EOL + EOL);
        CppDataTypeWriter typeWriter;
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
