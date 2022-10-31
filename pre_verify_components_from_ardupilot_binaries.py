from elftools.elf.elffile import ELFFile
import joblib
import angr

def check_contain_dwarf(binary):
    with open(binary, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return None
        return elffile

def extract_die_tree(filename):
    proj = angr.Project(filename)
    
    cu_dies = {}
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()
        #print(dwarfinfo)

        for CU in dwarfinfo.iter_CUs():
            #print(CU)
            
            for die in CU.iter_DIEs():
                if die.tag == 'DW_TAG_subprogram':
                    #print(die)
                    #print(die.get_parent())
                    func_name = return_name(die)
                    compile_unit_name = return_name(die.get_parent())
                    if compile_unit_name is not None and func_name is not None:
                        if compile_unit_name.endswith(".cpp") or compile_unit_name.endswith(".c"):
                            print(compile_unit_name)
                            print(func_name)
                            function_address = find_function_address(proj, func_name)

                            cu_dies[compile_unit_name] = (func_name, function_address)

                    #print(func_name)
                    #print(compile_unit_name)
                    
            #print("*************************")
    
    return cu_dies
        
def return_name(_die):
    for att in _die.attributes:
        if att == 'DW_AT_name':
            return _die.attributes[att].value.decode("utf-8")


def die_info_rec(die, dies):
    """ A recursive function for showing information about a DIE and its
        children.
    """
   
    for child in die.iter_children():
        #print(child)
        dies.append(child)
        die_info_rec(child, dies)
def return_if_function_external(die_object):
    for att in die_object.attributes:
        if att == 'DW_AT_external':
            return die_object.attributes[att].value


def find_function_address(proj, function):
    print(function)
    function_symbol = proj.loader.find_symbol(function)
    if function_symbol is not None:
        return hex(function_symbol.rebased_addr)
    return None

bin_path = 'arduplane'

#elf_content = check_contain_dwarf(bin_path)
cu_funcs = extract_die_tree(bin_path)
#print(dies)
joblib.dump(cu_funcs, 'cu_funcs.pkl')