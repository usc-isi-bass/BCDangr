import argparse

from bcd.bcd_angr import BCDangr

def main():
    parser = argparse.ArgumentParser(description='Implementation of BCD using angr')

    parser.add_argument('--bin-path', required=True, help='The path to the binary to analyze.')

    args = parser.parse_args()

    bin_path = args.bin_path

    alpha = 0.5
    beta = 0.25
    gamma = 0.25
    bcd = BCDangr(bin_path)
    print(bcd._func_list)
    print(list(bcd.get_communities(alpha, beta, gamma)))


if __name__ == "__main__":
    main()
