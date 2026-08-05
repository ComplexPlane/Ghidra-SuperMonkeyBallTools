package supermonkeyballtools.export;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Iterator;
import java.util.regex.Pattern;

public class BetterHeaderExport {
    private final Program program;
    private static final String EOL = System.getProperty("line.separator");
    private static final Pattern cIdentifierPattern = Pattern.compile("[a-zA-Z_][a-zA-Z0-9_]*");

    public BetterHeaderExport(Program program) {
        this.program = program;
    }

    private static String namePrefix(String name) {
        return "MKB(" + name + ")";
    }

    private void genExternDecls(BetterDataTypeWriter typeWriter, Writer out) throws CancelledException, IOException {
        out.write("typedef void *pointer;" + EOL + EOL);

        out.write("#ifdef __cplusplus" + EOL);
        out.write("extern \"C\" {" + EOL);
        out.write("#endif" + EOL);

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
            String typeDecl = typeWriter.getTypeDeclaration(namePrefix(s.getName()), type, data.getLength(),
                    false, TaskMonitor.DUMMY);
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
            name = namePrefix(name);

            String funcDecl = typeWriter.getFunctionPointerString(def, name, null, false, TaskMonitor.DUMMY);
            out.write("    " + funcDecl + ";" + EOL);
        }

        out.write("#ifdef __cplusplus" + EOL);
        out.write("} // extern \"C\"" + EOL);
        out.write("} // namespace mkb" + EOL);
        out.write("#endif" + EOL);
    }

    private void genPrelude(Writer writer) throws IOException {
        writer.write("#pragma once" + EOL);
        writer.write(EOL);

        writer.write("#define MKB_CONCAT_IMPL(a, b) a##b" + EOL);
        writer.write("#define MKB_CONCAT(a, b) MKB_CONCAT_IMPL(a, b)" + EOL);

        writer.write("#ifdef __cplusplus" + EOL);
        writer.write("#define MKB(name) name" + EOL);
        writer.write("#else" + EOL);
        writer.write("#define MKB(name) MKB_CONCAT(mkb_, name)" + EOL);
        writer.write("#endif" + EOL);

        writer.write("#ifdef __cplusplus" + EOL);
        writer.write("namespace mkb {" + EOL);
        writer.write("#endif" + EOL);
        writer.write(EOL);
    }

    private void genPostlude(Writer writer) throws IOException {
        writer.write(EOL);
        writer.write("#undef MKB_CONCAT" + EOL);
        writer.write("#undef MKB_CONCAT_IMPL" + EOL);
        writer.write("#undef MKB" + EOL);
    }

    public String genCxxHeader() {
        // TODO write directly to a file instead of generating an intermediate String first
        StringWriter writer = new StringWriter();

        try {
            genPrelude(writer);

            BetterDataTypeWriter typeWriter;
            typeWriter = new BetterDataTypeWriter(program.getDataTypeManager(), writer);
            typeWriter.write(program.getDataTypeManager(), TaskMonitor.DUMMY);
            genExternDecls(typeWriter, writer);

            genPostlude(writer);

        } catch (CancelledException | IOException e) {
            Msg.error(getClass(), e);
        }

        return writer.toString();
    }
}
