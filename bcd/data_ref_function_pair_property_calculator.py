import angr 
import itertools
from bcd.function_pair_property_calculator import SymmetricFunctionPairPropertyCalculator
from bcd.data_ref_extraction import DataRefExtraction
from elftools.elf.elffile import ELFFile

class DataRefFunctionPairPropertyCalulator(SymmetricFunctionPairPropertyCalculator, DataRefExtraction):

    def __init__(self, proj, cfg, func_list, section_offsets):
        SymmetricFunctionPairPropertyCalculator.__init__(self, proj, cfg, func_list, section_offsets)
        DataRefExtraction.__init__(self, proj, cfg, func_list, section_offsets)

    def _get_property(self, i, j):
        func1 = self._func_list[i]
        func2 = self._func_list[j]
        func1_df = self.compute_function_data_references(func1)
        func2_df = self.compute_function_data_references(func2)

        return self.common_elements(func1_df, func2_df)

    def common_elements(self, l1, l2):
        l1_set = set(l1)
        l2_set = set(l2)
 
        if (l1_set & l2_set):
            return list(l1_set & l2_set)
        else:
            return [] 
