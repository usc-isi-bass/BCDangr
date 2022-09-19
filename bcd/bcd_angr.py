import angr
import textdistance
import networkx as nx
import numpy as np

import itertools
from elftools.elf.elffile import ELFFile
from bcd.data_ref_function_pair_property_calculator import DataRefFunctionPairPropertyCalulator
from bcd.call_function_pair_property_calculator import CallFunctionPairPropertyCalulator
from bcd.sections import Section

import itertools

class BCDangr:

    def __init__(self, bin_path, proj=None, cfg=None, elffile=None):
        self._bin_path = bin_path
        if proj is None:
            self._proj = angr.Project(bin_path, auto_load_libs=False)
        else:
            self._proj = proj
        if cfg is None:
            self._cfg = self._proj.analyses.CFGFast(normalize=True)
        else:
            self._cfg = cfg
        if elffile is None:
            self.elffile = ELFFile(open(bin_path, 'rb'))
        else:
            self.elffile = elffile


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

        self._matrix_penalty = self._compute_penalty_matrix()

    def get_communities(self, alpha, beta, gamma):
        communities_iter = self._get_communities(alpha, beta, gamma)

        # Translate community back to function addresses
        for community_tup in communities_iter:
            yield tuple(set(self._func_list[i] for i in community_set) for community_set in community_tup)

    def _get_communities(self, alpha, beta, gamma):
        assert np.isclose(alpha + beta + gamma, 1.0), "Sum of alpha, beta and gamma should be 1, but instead it is: {}".format(alpha + beta + gamma)
        H, W = self._calculate_decomposition_graph(alpha, beta, gamma)
        nx.set_edge_attributes(H, {(u, v): W[u][v] for u, v in H.edges()}, "weight")
        def find_mve(G):
            u, v, w = max(G.edges(data="weight"), key=itemgetter(2))
            mve_nodes = (u, v)
            return mve_nodes

        communities = nx.algorithms.community.girvan_newman(H, most_valuable_edge=find_mve)

        return communities


    def _calculate_decomposition_graph(self, alpha, beta, gamma):
        G_s = self._sequence_graph
        G_d = self._data_reference_graph
        G_c = self._call_graph

        assert set(G_s.nodes()) == set(G_d.nodes()) == set(G_c.nodes()), "Gs: {} Gd: {} Gc: {}".format(G_s.nodes(), G_d.nodes(), G_c.nodes())
        H = nx.compose(G_s, nx.compose(G_d, G_c))
        assert set(H.nodes()) == set(G_s.nodes())

        W = self._calculate_final_weight_matrix(alpha, beta, gamma)
        return H, W

    def _calculate_final_weight_matrix(self, alpha, beta, gamma):
        N = np.array(self._matrix_penalty)
        M_s = np.array(self._matrix_sequence)
        M_c = np.array(self._matrix_call)
        M_d = np.array(self._matrix_data_reference)
        rho_d = np.array(self._matrix_dissimilarity_score)

        W = np.multiply(N, alpha * M_s + beta * M_c + gamma * (np.multiply(rho_d, M_d)))

        return W


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
                #dfi = self._drfpp.compute_function_data_references(self._func_list[i])
                #dfj = self._drfpp.compute_function_data_references(self._func_list[j])
                #drg.nodes[i]['df'] = dfi
                #drg.nodes[j]['df'] = dfj
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
                m[i][j] = len(self._drfpp.get_property(i, j))
            else:
                m[i][j] = 0

        assert all([c is not None for r in m for c in r])
        return m

    def _compute_matrix_call(self):
        m = [[None for i in range(self._num_funcs)] for j in range(self._num_funcs)]
        for (i, j) in itertools.product(range(self._num_funcs), repeat=2):
            if self._call_graph.has_edge(i, j):
                m[i][j] = self._cfpp.get_property(i, j)
            else:
                m[i][j] = 0
        assert all([c is not None for r in m for c in r])
        return m

    def _compute_matrix_dissimilarity_score(self):
        rho = [[None for i in range(self._num_funcs)] for j in range(self._num_funcs)]
        for (i, j) in itertools.product(range(self._num_funcs), repeat=2):
            Di = self._drfpp.compute_function_data_references(self._func_list[i])
            Dj = self._drfpp.compute_function_data_references(self._func_list[j])
            p = len(Di)
            q = len(Dj)
            #print(self._data_reference_graph.has_edge(i, j))
            if self._data_reference_graph.has_edge(i, j) and max(p,q) > 0:
                rho[i][j] = 1 - (self.levenshtein_distance(Di,Dj)/max(p,q))
                #print(rho[i][j])
            else:
                rho[i][j] = 0
        assert all([c is not None for r in rho for c in r])
        return rho

    def _compute_penalty_matrix(self):
        N = [[None for i in range(self._num_funcs)] for j in range(self._num_funcs)]
        for (i, j) in itertools.product(range(self._num_funcs), repeat=2):
            if i != j:
                N[i][j] = 1.0 / np.abs(i - j)
            else:
                N[i][j] = 1
        assert all([c is not None for r in N for c in r])
        return N
    def levenshtein_distance(self,arr1, arr2):
        return textdistance.levenshtein.distance(arr1,arr2)

