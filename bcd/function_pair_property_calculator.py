from abc import abstractmethod
class FunctionPairPropertyCalculator:

    def __init__(self, proj, cfg, func_list):
        self._proj = proj
        self._cfg = cfg
        self._func_list = func_list

        self._func_property_pairs = {}


    def get_property(self, i, j):

        if (i, j) in self._func_property_pairs:
            return self._func_property_pairs[(i, j)]
        prop = self._get_property(i, j)
        self._func_property_pairs[(i, j)] = prop
        return prop

    @abstractmethod
    def _get_property(self, i, j):
        raise Exception("Abstract method")


class SymmetricFunctionPairPropertyCalculator(FunctionPairPropertyCalculator):

    def get_property(self, i, j):
        i, j = self._symmetrize(i, j)

        return super().get_property(i, j)

    def _symmetrize(self, i, j):
        return min(i, j), max(i, j)


