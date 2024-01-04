
from binaryninja import Architecture
from binaryninja import BinaryView
from binaryninja.enums import SegmentFlag, SectionSemantics, Endianness

class ARMBE8View(BinaryView):
    name = "ARMBE8View"
    long_name = "ARM BE8 View"

    @classmethod
    def is_valid_for_data(cls, data):
        return True

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self._endianness = Endianness.BigEndian
        self.arch = Architecture["armv7"]
        self.platform = self.arch.standalone_platform
        code_start = 0x00090020
        data_start = 0x01C40000
        rw_data_start = 0x2CEF000
        self.add_auto_segment(code_start, data_start - code_start, 0, data_start - code_start, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        self.add_auto_segment(data_start, rw_data_start - data_start, data_start - code_start, rw_data_start - data_start, SegmentFlag.SegmentReadable)
        self.add_auto_segment(rw_data_start, len(data) - rw_data_start, rw_data_start - code_start, len(data) - rw_data_start, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        self.add_entry_point(0x90020)
        self.get_function_at(0x90020).name = 'entry'

    def perform_is_executable(self):
        return True
    
    def perform_get_default_endianness(self):
        return Endianness.BigEndian

    def perform_get_entry_point(self):
        return 0x90020

ARMBE8View.register()