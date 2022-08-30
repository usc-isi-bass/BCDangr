
from bcd.function_pair_property_calculator import SymmetricFunctionPairPropertyCalculator

class DataRefFunctionPairPropertyCalulator(SymmetricFunctionPairPropertyCalculator):

    def _get_property(self, i, j):
        func1 = self._func_list[i]
        func2 = self._func_list[j]
        # TODO: return data references common to func1 and func2

        return []
