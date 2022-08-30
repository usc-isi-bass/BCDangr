
from bcd.function_pair_property_calculator import FunctionPairPropertyCalculator

class CallFunctionPairPropertyCalulator(FunctionPairPropertyCalculator):

    def _get_property(self, i, j):
        func1 = self._func_list[i]
        func2 = self._func_list[j]

        num_calls_to_func2 = 0
        for call_site_addr in func1.get_call_sites():
            call_target = func1.get_call_target(call_site_addr)
            assert call_target is not None
            if call_target == func2.addr:
                num_calls_to_func2 += 1

        return num_calls_to_func2


