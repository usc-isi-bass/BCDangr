import argparse
import angr
import os
import magic
import networkx as nx
import joblib

from bcd.bcd_angr import BCDangr
from bcd.evaluate.compilation_unit import Compile_Unit
from bcd.evaluate.evaluate_community import Evaluate_Community

def main():
    # folder is path to ardupilot binaries
    folder = 'ardupilot_compiled_binaries'
    for dirpath, dirnames, filenames in os.walk(folder):
        for file_name in filenames:
            file_path = os.path.join(dirpath, file_name)
            res = magic.from_file(file_path)
            if 'ELF' in res:
                print(file_path)
                ardupilot_name = file_path.split('/')[-2]
                pribnt(ardupilot_name)
                ###############################run bcd on ardupilot binaries###############################
                proj = angr.Project(file_path, auto_load_libs=False)
                cfg = proj.analyses.CFGFast(normalize=True)
                print("Created CFG")
                callgraph = proj.kb.callgraph

                alpha = 0.5
                beta = 0.25
                gamma = 0.25
                bcd = BCDangr(file_path, proj=proj, cfg=cfg)
                print('bcd object created')

                community_graph = nx.DiGraph(callgraph)
                func_addrs = sorted(set(community_graph.nodes()))
                for addr in func_addrs:
                    if addr not in bcd._func_list:
                        community_graph.remove_node(addr)

                relabel_map = {}
                communities_functions = {}
                communities_set = bcd.get_communities(alpha, beta, gamma)
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
                community_graph = nx.relabel_nodes(community_graph, relabel_map)
                joblib.dump(communities_functions, 'ardupilot_results/'+ardupilot_name+'_'+'bcd_communities_functions.pkl')

                ##################################find grandthrough compilation unit########################################
                cu = Compile_Unit(file_path)
                function_cu = cu.extract_die_tree()
                print('compilation units were found')

                ###################################evaluate bcd modularization ##############################################

                evaluate = Evaluate_Community( communities_functions, function_cu)
                print(evaluate.average_score_community)







if __name__ == "__main__":
    main()
