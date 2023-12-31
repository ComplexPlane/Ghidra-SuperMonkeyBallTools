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

public class DmeExport {

    private final int ARRAY_LEN_LIMIT = 1;

    private Program program;
    private GameModuleIndex regionIndex;

    public DmeExport(Program program, GameModuleIndex regionIndex) {
        this.program = program;
        this.regionIndex = regionIndex;
    }

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
        BYTE, SHORT, WORD, FLOAT, DOUBLE,
    }

    private GroupWatch genStruct(String name, Structure structType, Address addr) {
        List<Object> groupEntries = new ArrayList<>();

        for (int i = 0; i < structType.getNumComponents(); i++) {
            DataTypeComponent compon = structType.getComponent(i);
            Address fieldAddr = addr.add(compon.getOffset());
            String fieldName = compon.getFieldName();
            if (fieldName == null) {
                fieldName = String.format("field_0x%08X", compon.getOffset());
            }
            Object fieldWatch = genDataType(fieldName, compon.getDataType(), fieldAddr);
            if (fieldWatch != null) {
                groupEntries.add(fieldWatch);
            }
        }

        return new GroupWatch(groupEntries, name);
    }

    private GroupWatch genArray(String name, Array arrayType, Address addr) {
        List<Object> groupEntries = new ArrayList<>();

        int numElems = Math.min(arrayType.getNumElements(), ARRAY_LEN_LIMIT);
        for (int i = 0; i < numElems; i++) {
            String elemLabel = String.format("%s[%d]", name, i);
            Address elemAddr = addr.add((long) i * arrayType.getElementLength());
            DataType innerType = arrayType.getDataType();
            Object elemWatch = genDataType(elemLabel, innerType, elemAddr);
            if (elemWatch != null) {
                groupEntries.add(elemWatch);
            }
        }

        return new GroupWatch(groupEntries, name);
    }

    private Object genDataType(String name, DataType type, Address addr) {
        if (type instanceof TypeDef) {
            type = ((TypeDef) type).getBaseDataType();
        }

        if (type instanceof AbstractIntegerDataType
                || type instanceof Undefined
                || type instanceof AbstractFloatDataType) {
            TypeIndex ti;
            if (type instanceof FloatDataType) {
                ti = TypeIndex.FLOAT;
            } else if (type instanceof DoubleDataType) {
                ti = TypeIndex.DOUBLE;
            } else if (type.getLength() == 1) {
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

            long convertedAddr = regionIndex.addressToRam(program, addr);
            String addrStr = String.format("%08X", convertedAddr);
            return new VarWatch(addrStr, 0, name, ti.ordinal(), !signed);
        }
        if (type instanceof Structure) {
            return genStruct(name, (Structure) type, addr);
        }
        if (type instanceof Array) {
            return genArray(name, (Array) type, addr);
        }
        return null;
    }

    public String genDmeWatchList() {
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
