package supermonkeyballtools;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class DmeWatchList {

    /*
    TODO
    Remember to delete comma
        Deal with commas in general
    Convert addresses to actual GC REL addresses
    Deal with undefined
    Export the different sizes of integers
     */

    private enum TypeIndex {
        BYTE, SHORT, WORD, FLOAT,
    }

    private static void genStruct(Structure structType, Address addr, List<String> outLines) {
        outLines.add("{");
        outLines.add("\"groupEntries\": [");

        for (int i = 0; i < structType.getNumComponents(); i++) {
            DataTypeComponent compon = structType.getComponent(i);
            Address fieldAddr = addr.add(compon.getOffset());
            genDataType(compon.getDataType(), compon.getFieldName(), fieldAddr, outLines);
        }

        outLines.add("],");
        outLines.add(String.format("\"groupName\": \"%s\"", structType.getName()));
        outLines.add("},");
    }

    private static void genDataType(DataType type, String name, Address addr, List<String> outLines) {
        if (type instanceof TypeDef) {
            type = ((TypeDef) type).getBaseDataType();
        }

        if (type instanceof AbstractIntegerDataType || type instanceof Undefined) {
            TypeIndex ti;
            if (type.getLength() == 1) {
                ti = TypeIndex.BYTE;
            } else if (type.getLength() == 2) {
                ti = TypeIndex.SHORT;
            } else if (type.getLength() == 4) {
                ti = TypeIndex.WORD;
            } else {
                return; // Don't support an integer of this unknown size
            }
            boolean signed = true;
            if (type instanceof AbstractIntegerDataType) {
                signed = ((AbstractIntegerDataType) type).isSigned();
            }

            outLines.add("{");
            outLines.add(String.format("\"address\": \"%s\",", addr.toString()));
            outLines.add("\"baseIndex\": 0,");
            outLines.add(String.format("\"label\": \"%s\",", name));
            outLines.add(String.format("\"typeIndex\": %d,", ti.ordinal()));
            outLines.add(String.format("\"unsigned\": %b", signed));
            outLines.add("},");

        } else if (type instanceof Structure) {
            genStruct((Structure) type, addr, outLines);
        }
    }

    public static String genDmeWatchList(Program program) {
        // TODO use some sort of string buffer?
        List<String> lines = new ArrayList<>();

        lines.add("{");
        lines.add("\"watchList\": [");

        SymbolTable table = program.getSymbolTable();
        for (Iterator<Symbol> it = table.getSymbolIterator(); it.hasNext(); ) {
            Symbol s = it.next();

            if (!s.getSymbolType().equals(SymbolType.LABEL)) continue;
            Data data = program.getListing().getDataAt(s.getAddress());
            if (data == null) continue;

            DataType type = data.getDataType();
            genDataType(type, s.getName(), data.getAddress(), lines);
        }

        lines.add("]");
        lines.add("}");

        return String.join("\n", lines);
    }
}
