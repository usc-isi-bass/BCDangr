import argparse

from bcd.bcd_angr import BCDangr

def main():
    parser = argparse.ArgumentParser(description='Implementation of BCD using angr')

    parser.add_argument('--bin-path', required=True, help='The path to the binary to analyze.')

    args = parser.parse_args()

    bin_path = args.bin_path

    bcd = BCDangr(bin_path)
    print(bcd._func_list)
    print(bcd._components)


if __name__ == "__main__":
    main()
