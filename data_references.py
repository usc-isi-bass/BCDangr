import argparse
from bcd.bcd_angr import BCDangr
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='test function data refrences')
    parser.add_argument('binary_file',  help='insert the path to the binary file')
    args = parser.parse_args()
    bin_path = args.binary_file
    bcd = BCDangr(bin_path)
    print(bcd._matrix_dissimilarity_score)