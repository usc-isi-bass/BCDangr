
# This module is for computing and extracting compilation units from binaries
#for modularization evaluation
from elftools.elf.elffile import ELFFile
from collections import defaultdict
import joblib
import angr

class Compile_Unit:
    def __init__(self, binary_file):
        self.binary_file = binary_file
        self.elffile = None
        self.dwarfinfo = None
        self.check_contain_dwarf()
    
    def check_contain_dwarf(self):

        with open(self.binary_file, 'rb') as f:
            self.elffile = ELFFile(f)
            if not elffile.has_dwarf_info():
                print('  file has no DWARF info')
                return None
            
            self.dwarfinfo = self.elffile.get_dwarf_info()

    def extract_die_tree(self):
        # it should continue till find the first compile_unit (fix bug)
        proj = angr.Project(self.binary_file)
        
        cu_dies = defaultdict(list)
        list_cu_dies = []

        for CU in self.dwarfinfo.iter_CUs():
            compile_unit_name = self.return_name(CU.get_top_DIE())

            for die in CU.iter_DIEs():
                if die.tag == 'DW_TAG_subprogram':
                    func_name = ""
                    die_series_compilation_unit = []
                    die_name = return_name(die)
                    func_name = die_name
                    #print(die_name)
                    die_series_compilation_unit.append(die_name)
                    while die_name != compile_unit_name and die is not None:
                        die = die.get_parent()
                        die_name = return_name(die)
                        #print(die_name)
                        if die_name is not None:
                            if '../' in die_name:
                                new_name = die_name.replace("../", '')
                                #print(new_name)
                                die_series_compilation_unit.append(new_name)
                            else:
                                die_series_compilation_unit.append(die_name)

                    #self.find_function_address(proj, func_name)
                    #Since we can have sam function name for different class, we append alist to a function name
                    cu_dies[func_name].append(die_series_compilation_unit)
                    #print(cu_dies)
            
            #print(CU)
        return cu_dies    

            
    def return_name(self, _die):
        if _die is None:
            return None
        for att in _die.attributes:
            if att == 'DW_AT_name':
                return _die.attributes[att].value.decode("utf-8")
    
    def find_function_address(self, proj, function):

        function_symbol = proj.loader.find_symbol(function)
        if function_symbol is not None:
            return hex(function_symbol.rebased_addr)
        else:
            print("symbol was not found")
            print(function)
            print("*******************")
        return None

    def return_if_function_external(self, die_object):
        for att in die_object.attributes:
            if att == 'DW_AT_external':
                return die_object.attributes[att].value
    
    def die_info_rec(die, dies):
        """ A recursive function for showing information about a DIE and its
            children.
        """
    
        for child in die.iter_children():
            #print(child)
            dies.append(child)
            die_info_rec(child, dies)