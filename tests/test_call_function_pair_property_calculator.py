from nose.tools import *
import os
import angr
from elftools.elf.elffile import ELFFile

from bcd.call_function_pair_property_calculator import CallFunctionPairPropertyCalulator
from bcd.sections import Section


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'binaries', 'test_binaries', 'bin')

def test001():
    elf_file_path = os.path.join(test_location, 'test001')

    elffile = ELFFile(open(elf_file_path, 'rb'))
    proj = angr.Project(elf_file_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)

    func_list = sorted(cfg.functions.keys())

    func_name_to_index = {cfg.functions.function(addr=func_addr).name: i for i, func_addr in enumerate(func_list)}

    sections = elffile.iter_sections()
    section_offsets = [Section(sec).compute_section_offsets() for sec in sections]
    cfpp = CallFunctionPairPropertyCalulator(proj, cfg, func_list, section_offsets)

    p = _func_name_get_property('f1', 'f2', func_name_to_index, cfpp)
    assert_equal(p, 1)

    p = _func_name_get_property('f2', 'f3', func_name_to_index, cfpp)
    assert_equal(p, 1)

    p = _func_name_get_property('f2', 'f4', func_name_to_index, cfpp)
    assert_equal(p, 2)

    p = _func_name_get_property('f2', 'f5', func_name_to_index, cfpp)
    assert_equal(p, 1)

    p = _func_name_get_property('f2', 'f6', func_name_to_index, cfpp)
    assert_equal(p, 1)

    p = _func_name_get_property('f2', 'f7', func_name_to_index, cfpp)
    assert_equal(p, 1)

    p = _func_name_get_property('f3', 'f2', func_name_to_index, cfpp)
    assert_equal(p, 1)

    p = _func_name_get_property('f2', 'f1', func_name_to_index, cfpp)
    assert_equal(p, 0)

    p = _func_name_get_property('f3', 'f1', func_name_to_index, cfpp)
    assert_equal(p, 0)

    p = _func_name_get_property('f4', 'f2', func_name_to_index, cfpp)
    assert_equal(p, 0)


def _func_name_get_property(func1_name, func2_name, func_name_to_index, cfpp):
    i = func_name_to_index[func1_name]
    j = func_name_to_index[func2_name]
    p = cfpp.get_property(i, j)
    return p


