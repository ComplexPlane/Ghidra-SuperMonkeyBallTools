package supermonkeyballtools;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
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

/*
TODO
Fix outputting hardware-range addresses
Convert addresses to actual GC REL addresses
Output floats/doubles, arrays, strings
 */

public class DmeWatchList {

    private static class WatchList {
        private List<Object> watchList;

        public WatchList(List<Object> watchList) {
            this.watchList = watchList;
        }
    }

    private static class VarWatch {
        private String address;
        private int baseIndex;
        private String label;
        private int typeIndex;
        private boolean unsigned;

        public VarWatch(String address, int baseIndex, String label, int typeIndex, boolean unsigned) {
            this.address = address;
            this.baseIndex = baseIndex;
            this.label = label;
            this.typeIndex = typeIndex;
            this.unsigned = unsigned;
        }
    }

    private static class GroupWatch {
        private List<Object> groupEntries;
        private String groupName;

        public GroupWatch(List<Object> groupEntries, String groupName) {
            this.groupEntries = groupEntries;
            this.groupName = groupName;
        }
    }

    private enum TypeIndex {
        BYTE, SHORT, WORD, FLOAT,
    }

    private static GroupWatch genStruct(String name, Structure structType, Address addr) {
        List<Object> groupEntries = new ArrayList<>();

        for (int i = 0; i < structType.getNumComponents(); i++) {
            DataTypeComponent compon = structType.getComponent(i);
            Address fieldAddr = addr.add(compon.getOffset());
            Object fieldWatch = genDataType(compon.getFieldName(), compon.getDataType(), fieldAddr);
            if (fieldWatch != null) {
                groupEntries.add(fieldWatch);
            }
        }

        return new GroupWatch(groupEntries, name);
    }

    private static Object genDataType(String name, DataType type, Address addr) {
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
                return null; // Don't support an integer of this unknown size
            }
            boolean signed = true;
            if (type instanceof AbstractIntegerDataType) {
                signed = ((AbstractIntegerDataType) type).isSigned();
            }

            return new VarWatch(addr.toString(), 0, name, ti.ordinal(), !signed);
        }
        if (type instanceof Structure) {
            return genStruct(name, (Structure) type, addr);
        }
        return null;
    }

    public static String genDmeWatchList(Program program) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        List<Object> watchList = new ArrayList<>();

        SymbolTable table = program.getSymbolTable();
        Address hardwareRegion = program.getMinAddress().getNewAddress(0xCC000000);

        for (Iterator<Symbol> it = table.getSymbolIterator(); it.hasNext(); ) {
            Symbol s = it.next();

            // If address is a hardware register region and not a memory region, ignore it
            if (s.getAddress().compareTo(hardwareRegion) >= 0) continue;

            if (!s.getSymbolType().equals(SymbolType.LABEL)) continue;
            Data data = program.getListing().getDataAt(s.getAddress());
            if (data == null) continue;

            DataType type = data.getDataType();
            Object watch = genDataType(s.getName(), type, data.getAddress());
            if (watch != null) {
                watchList.add(watch);
            }
        }

        return gson.toJson(new WatchList(watchList));
    }
}
