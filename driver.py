import argparse
import angr
import networkx as nx
import joblib

from bcd.bcd_angr import BCDangr

def main():
    parser = argparse.ArgumentParser(description='Implementation of BCD using angr')

    parser.add_argument('--bin-path', required=True, help='The path to the binary to analyze.')
    parser.add_argument('--break-limit', type=int, help='Break after this many iterations')

    args = parser.parse_args()

    bin_path = args.bin_path
    break_limit = args.break_limit
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    print("Created CFG")
    callgraph = proj.kb.callgraph

    alpha = 0.5
    beta = 0.25
    gamma = 0.25
    bcd = BCDangr(bin_path, proj=proj, cfg=cfg)

    community_graph = nx.DiGraph(callgraph)
    func_addrs = sorted(set(community_graph.nodes()))
    for addr in func_addrs:
        if addr not in bcd._func_list:
            community_graph.remove_node(addr)

    relabel_map = {}
    communities_functions = {}
    for break_counter, communities_set in enumerate(bcd.get_communities(alpha, beta, gamma)):
        print("COMMUNITIES SET: {}".format(len(communities_set)))
        for i, community in enumerate(communities_set):
            
            funcs = []
            sorted_community = sorted(community)
            print("  Community: {} / {} size: {}".format(i, len(communities_set), len(community)))
            
            for func_addr in sorted_community:
                func = cfg.functions.function(addr=func_addr)
                print("    {}@0x{:x}".format(func.demangled_name, func_addr))
                funcs.append((func.demangled_name, func_addr))
            communities_functions[(i,len(communities_set), len(community))] = funcs
            first_addr = sorted_community[0]
            relabel_map[first_addr] = i
            for func_addr in sorted_community[1:]:
                community_graph = nx.contracted_nodes(community_graph, first_addr, func_addr, copy=True)
        if break_limit is not None and break_counter >= break_limit:
            break
    community_graph = nx.relabel_nodes(community_graph, relabel_map)
    joblib.dump(communities_functions, 'communities_functions.pkl')
    nx.drawing.nx_pydot.write_dot(community_graph, 'community_graph.dot')


if __name__ == "__main__":
    main()
