import angr
import networkx as nx

from bcd.data_ref_function_pair_property_calculator import DataRefFunctionPairPropertyCalulator
from bcd.call_function_pair_property_calculator import CallFunctionPairPropertyCalulator

class BCDangr:

    def __init__(self, bin_path):
        self._bin_path = bin_path
        self._proj = angr.Project(bin_path, auto_load_libs=False)

        self._cfg = self._proj.analyses.CFGFast(normalize=True)

        self._func_list = sorted(self._cfg.functions.keys())
        self._num_funcs = len(self._func_list)

        self._drfpp = DataRefFunctionPairPropertyCalulator(self._proj, self._cfg, self._func_list)
        self._cfpp = CallFunctionPairPropertyCalulator(self._proj, self._cfg, self._func_list)

        self._sequence_graph = self._compute_sequence_graph()
        self._data_reference_graph = self._compute_data_reference_graph()
        self._call_graph = self._compute_call_graph()

        self._matrix_sequence = self._compute_matrix_sequence()
        self._matrix_data_reference = self._compute_matrix_data_reference()
        self._matrix_call = self._compute_matrix_call()

        self._matrix_dissimilarity_score = self._compute_matrix_dissimilarity_score()

        # TODO: Compute penalty matrix N

        # TODO Compute final edge weight matrix

        # TODO: use Newman's algorithm to compute components
        self._components = None

    # Graph Calculation

    def _compute_sequence_graph(self):
        sg = nx.DiGraph()
        sg.add_nodes_from(range(self._num_funcs))

        for i in range(0, self._num_funcs - 1):
            sg.add_edge(i, i + 1)

        assert sg.number_of_nodes() == sg.number_of_edges() + 1

        return sg

    def _compute_data_reference_graph(self):
        drg = nx.DiGraph()
        drg.add_nodes_from(range(self._num_funcs))

        for i in range(self._num_funcs):
            for j in range(i + 1, self._num_funcs):
                if len(self._drfpp.get_property(i, j)) > 0:
                    drg.add_edge(i, j)
                    drg.add_edge(j, i)
        return drg

    def _compute_call_graph(self):
        cg = nx.DiGraph()
        cg.add_nodes_from(range(self._num_funcs))

        for (i, j) in itertools.product(range(self._num_funcs), repeat=2):
            if self._cfpp.get_property(i, j) > 0:
                cg.add_edge(i, j)
        return cg

    # Matrix Calculation

    def _compute_matrix_sequence(self):
        m = [[None for i in range(self._num_funcs)] for j in range(self._num_funcs)]
        for (i, j) in itertools.product(range(self._num_funcs), repeat=2):
            if self._sequence_graph.has_edge(i, j):
                m[i][j] = 1
            else:
                m[i][j] = 0
        assert all([c is not None for r in m for c in r])
        return m


    def _compute_matrix_data_reference(self):
        m = [[None for i in range(self._num_funcs)] for j in range(self._num_funcs)]
        for (i, j) in itertools.product(range(self._num_funcs), repeat=2):
            if self._data_reference_graph.has_edge(i, j):
                m[i][j] = self._drfpp.get_property(i, j)
            else:
                m[i][j] = 0
        assert all([c is not None for r in m for c in r])
        return m           

    def _compute_matrix_call(self):
        m = [[None for i in range(self._num_funcs)] for j in range(self._num_funcs)]
        for (i, j) in itertools.product(range(self._num_funcs), repeat=2):
            if self._data_reference_graph.has_edge(i, j):
                m[i][j] = self._cfpp.get_property(i, j)
            else:
                m[i][j] = 0
        assert all([c is not None for r in m for c in r])
        return m

    def _compute_matrix_dissimilarity_score(self):
        rho = [[None for i in range(self._num_funcs)] for j in range(self._num_funcs)]
        for (i, j) in itertools.product(range(self._num_funcs), repeat=2):
            if self._data_reference_graph.has_edge(i, j): # TODO Check Di or Dj have length > 0
                # TODO
                rho[i][j] = -1
            else:
                rho[i][j] = 0
        assert all([c is not None for r in rho for c in r])
        return rho
            
