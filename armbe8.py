
import os
from binaryninja.binaryview import *
from binaryninja.architecture import *
from binaryninja.enums import *
from binaryninja.types import *
from binaryninja.log import log_error
from binaryninja.log import log_info
import binascii

class ARMBE8Arch(Architecture):

    _subarch = Architecture['armv7eb']

    name = "armbe8"
    address_size = _subarch.address_size
    default_int_size = _subarch.default_int_size
    max_instr_length = _subarch.max_instr_length
    regs = _subarch.regs
    stack_pointer = _subarch.stack_pointer
    flags = _subarch.flags
    flag_write_types = _subarch.flag_write_types
    flag_roles = _subarch.flag_roles
    flags_required_for_flag_condition = _subarch.flags_required_for_flag_condition
    flags_written_by_flag_write_type = _subarch.flags_written_by_flag_write_type
    endianess = Endianness.BigEndian

    def __init__(self):
        super(ARMBE8Arch, self).__init__()

    def _get_endianness(self, ctxt): # HACK HACK HACK, there is a bug that prevents propagating endianess
        return Endianness.BigEndian

    def byte_swap_for_armeb(self, data):
        this_data = ""
        for cnt in xrange(0, len(data), self.max_instr_length):
            this_data += data[cnt:cnt+self.max_instr_length][::-1]
        return this_data

    def perform_get_instruction_info(self, data, addr):
        result = self._subarch.get_instruction_info(self.byte_swap_for_armeb(data), addr)
        if result and result.branches:
            for b in result.branches:
                b.arch = self
        return result

    def perform_get_instruction_text(self, data, addr):
        return self._subarch.get_instruction_text(self.byte_swap_for_armeb(data), addr)

    def perform_get_instruction_low_level_il(self, data, addr, il):
        il.arch = self
        r = self._subarch.get_instruction_low_level_il(self.byte_swap_for_armeb(data), addr, il)
        return r 

    def perform_get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
        return self._subarch.get_flag_write_low_level_il(op, size, write_type, flag, operands, il)

    def perform_is_never_branch_patch_available(self, data, addr):
        return self._subarch.is_never_branch_patch_available(self.byte_swap_for_armeb(data), addr)

    def perform_is_invert_branch_patch_available(self, data, addr):
        return self._subarch.is_invert_branch_patch_available(self.byte_swap_for_armeb(data), addr)

    def perform_is_always_branch_patch_available(self, data, addr):
        return self._subarch.is_always_branch_patch_available(self.byte_swap_for_armeb(data), addr)

    def perform_is_skip_and_return_zero_patch_available(self, data, addr):
        return self._subarch.is_skip_and_return_zero_patch_available(self.byte_swap_for_armeb(data), addr)

    def perform_is_skip_and_return_value_patch_available(self, data, addr):
        return self._subarch.is_skip_and_return_value_patch_available(self.byte_swap_for_armeb(data), addr)

    def perform_convert_to_nop(self, data, addr):
        return self._subarch.convert_to_nop(self.byte_swap_for_armeb(data), addr)

    def perform_never_branch(self, data, addr):
        return self._subarch.never_branch(self.byte_swap_for_armeb(data), addr)

    def perform_invert_branch(self, data, addr):
        return self._subarch.invert_branch(self.byte_swap_for_armeb(data), addr)

    def perform_skip_and_return_value(self, data, addr, value):
        return self._subarch.skip_and_return_value(self.byte_swap_for_armeb(data), addr, value)

ARMBE8Arch.register()

class ARMBE8View(BinaryView):
    name = "ARMBE8View"
    long_name = "ARM BE8 View"

    @classmethod
    def is_valid_for_data(self, data):
        hdr = data.read(0, 4)
        if hdr != "BE8": # Replace this with your architecture identifier
            return False
        return True

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata = data.file, parent_view = data)
        self.arch = Architecture["armbe8"]
        self.platform = self.arch.standalone_platform
        self.add_auto_segment(0, len(data), 0, len(data),
            SegmentFlag.SegmentWritable | SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        self.add_entry_point(0)
        sym_file = self.file.filename + ".syms"  # Custom symbols, replace with your own implementation
        if os.path.exists(sym_file):
            with open(sym_file, "r") as sym_contents:
                for line in sym_contents:
                    syms = line.split(',')
                    if len(syms) < 5:
                        continue
                    name = syms[0]
                    start_addr = long(syms[1], 16)
                    end_addr = long(syms[2], 16)
                    if start_addr < end_addr:
                        self.add_function(start_addr)
                        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, start_addr, name))
                    else:
                        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, start_addr, name))

    def perform_is_executable(self):
        return True
    
    def perform_get_default_endianness(self):
        return Endianness.BigEndian

ARMBE8View.register()
