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
    # it should continue till find the first compile_unit (fix bug)
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

                    die_series_compilation_unit = ""
                    #print(die)
                    #print(die.get_parent())

                    func_name = return_name(die)
                    parent = die.get_parent()
                    compile_unit_name = return_name(parent)
                    
                    if func_name is not None and compile_unit_name is not None:
                        die_series_compilation_unit = die_series_compilation_unit+"/"+compile_unit_name
                        #print(compile_unit_name)
                        die = parent
                        while not compile_unit_name.endswith(".cpp") :
                            parent = die.get_parent()
                            compile_unit_name = return_name(parent)
                            if compile_unit_name is None:
                                break
                            if not compile_unit_name.endswith(".cpp"):
                                die_series_compilation_unit= die_series_compilation_unit+"/"+compile_unit_name
                                #print(compile_unit_name)
                            else:
                                compile_unit_name = compile_unit_name.split("/")[-1]
                                die_series_compilation_unit= die_series_compilation_unit+"/"+compile_unit_name

                            die = parent
                            
                        print(func_name)
                        function_address = find_function_address(proj, func_name)
                        cu_dies[die_series_compilation_unit] = (func_name, function_address)
                        print(die_series_compilation_unit)
                        print((func_name, function_address))

    return cu_dies      

        
def return_name(_die):
    if _die is None:
        return None
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
    #print(function)
    function_symbol = proj.loader.find_symbol(function)
    if function_symbol is not None:
        return hex(function_symbol.rebased_addr)
    return None

bin_path = 'arduplane'

#elf_content = check_contain_dwarf(bin_path)
cu_funcs = extract_die_tree(bin_path)
#print(dies)
joblib.dump(cu_funcs, 'cu_funcs.pkl')