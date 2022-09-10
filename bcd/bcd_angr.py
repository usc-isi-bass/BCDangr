import angr
import textdistance
import networkx as nx
import itertools
from elftools.elf.elffile import ELFFile
from bcd.data_ref_function_pair_property_calculator import DataRefFunctionPairPropertyCalulator
from bcd.call_function_pair_property_calculator import CallFunctionPairPropertyCalulator
from bcd.sections import Section

import itertools

class BCDangr:

    def __init__(self, bin_path):
        self._bin_path = bin_path
        self.elffile = ELFFile(open(bin_path, 'rb'))
        self._proj = angr.Project(bin_path, auto_load_libs=False)
        self._cfg = self._proj.analyses.CFGFast(normalize=True)

        self._func_list = sorted(self._cfg.functions.keys())
        self._num_funcs = len(self._func_list)
        self.sections = self.elffile.iter_sections()
        self.section_offsets = [Section(sec).compute_section_offsets() for sec in self.sections] 
        self._drfpp = DataRefFunctionPairPropertyCalulator(self._proj, self._cfg, self._func_list, self.section_offsets)
        self._cfpp = CallFunctionPairPropertyCalulator(self._proj, self._cfg, self._func_list, self.section_offsets)

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
                #print(i)
                #print(j)
                dfi = self._drfpp.compute_function_data_references(self._func_list[i])
                dfj = self._drfpp.compute_function_data_references(self._func_list[j])
                print("look at me")
                print(dfi)
                print(dfj)
                drg.nodes[i]['df'] = dfi
                drg.nodes[j]['df'] = dfj
                if len(self._drfpp.common_elements(dfi, dfj)) > 0:
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
            m[i][j] = len(self._drfpp.get_property(i, j))

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
            Di = self._data_reference_graph.nodes[i]['df']
            Dj = self._data_reference_graph.nodes[j]['df']
            p = len(Di)
            q = len(Dj)
            #print(self._data_reference_graph.has_edge(i, j))
            if self._data_reference_graph.has_edge(i, j) and max(p,q) >0:
                # TODO
                rho[i][j] = 1 - (self.levenshtein_distance(Di,Dj)/max(p,q))
                #print(rho[i][j])
            else:
                rho[i][j] = 0
        assert all([c is not None for r in rho for c in r])
        return rho
            
    def levenshtein_distance(self,arr1, arr2):
        return textdistance.levenshtein.distance(arr1,arr2)

