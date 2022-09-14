import argparse
import angr

from bcd.bcd_angr import BCDangr

def main():
    parser = argparse.ArgumentParser(description='Implementation of BCD using angr')

    parser.add_argument('--bin-path', required=True, help='The path to the binary to analyze.')

    args = parser.parse_args()

    bin_path = args.bin_path
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    print("Created CFG")

    alpha = 0.5
    beta = 0.25
    gamma = 0.25
    bcd = BCDangr(bin_path, proj=proj, cfg=cfg)

    for communities_set in bcd.get_communities(alpha, beta, gamma):
        print("COMMUNITIES SET: {}".format(len(communities_set)))
        for i, community in enumerate(communities_set):
            print("  Community: {} / {} size: {}".format(i, len(communities_set), len(community)))
            for func_addr in sorted(community):
                func = cfg.functions.function(addr=func_addr)
                print("    {}@0x{:x}".format(func.name, func_addr))


if __name__ == "__main__":
    main()
