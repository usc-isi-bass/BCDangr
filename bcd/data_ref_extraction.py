
from elftools.elf.elffile import ELFFile

class DataRefExtraction:

    def __init__(self, bin_path, proj, cfg, func_list, section_offsets):
        self._bin_path = bin_path
        self._proj = proj
        self._cfg = cfg
        self.func_list = func_list
        self.section_offsets = section_offsets

        self._cache = {}

    def compute_function_data_references(self, func_address):
        if func_address in self._cache:
            return self._cache[func_address]
        func_references = self._compute_function_data_references(func_address) 
        self._cache[func_address] = func_references
        return func_references

    def _compute_function_data_references(self, func_address):
        
        #print(self._func_list)
        func_refs = []
        sec_offsets = self.dic_section_offsets()
        #print(sec_offsets)
        base_address = self._proj.loader.main_object.min_addr
        #print(hex(base_address))
        instructions = []
        func = self._cfg.functions.function(addr=func_address)
        func_blocks = sorted(func.blocks, key=lambda b: b.addr) # Apparrently blocks aren't sorted by default
        
        for block in func_blocks:
            for ins in block.capstone.insns:
                instructions.append(ins)

        with open(self._bin_path, 'rb') as f:
            elffile = ELFFile(f)
            arch = elffile.get_machine_arch()
            if arch == 'x64':
                func_refs = self.function_references_for_amd(instructions, base_address, sec_offsets)
            elif arch == 'ARM':
                func_refs = self.function_references_for_arm(instructions, base_address, sec_offsets)

        return func_refs


    def function_references_for_amd(self, instructions, base_adrs, sec_offsets):
        function_references = []
        for instruct in instructions:
            if 'rip' in instruct.op_str and '[' in instruct.op_str :
                mnemonic = instruct.op_str
                parts = mnemonic.split(",")
                for part in parts:
                    if 'rip' in part:
                        whole_address = part.split("[")[-1][:-1]
                        if '+' in whole_address:
                            if instructions.index(instruct)+1 < len(instructions):
                                offset = whole_address.split("+")[-1].strip()
                                rip = instructions[instructions.index(instruct)+1].address
                                new_offset = int(offset, 16)
                                data_reference = rip+new_offset-base_adrs
                                if self.check_validity_data_references(hex(data_reference), sec_offsets):
                                    function_references.append(data_reference)

        return function_references
    
    def function_references_for_arm(self, instrucs, base_adr, sec_offsets):
        func_refs = []
        for instruct in instrucs:
            #print(instruct)
            if 'pc' in instruct.op_str and '[' in instruct.op_str :
                mnemonic = instruct.op_str
                parts = mnemonic.split("[")
                #print(parts)
                for part in parts:
                    if 'pc' in part:
                        #print(instruct)
                        #part = part.replace("[","")
                        part = part.replace("]","")
                        mnemo_parts = part.split(",")
                        if len(mnemo_parts) >1:
                            offset = mnemo_parts[-1].strip().replace("#",'')
                            #print(offset)

                        if instrucs.index(instruct)+1 < len(instrucs) and offset.startswith('0x'):
                            pc = instrucs[instrucs.index(instruct)+1].address
                            #print("this is pc")
                            #print(pc)
                            new_offset = int(offset, 16)
                            #print("this is new offset")
                            #print(new_offset)
                            data_reference = pc+new_offset-base_adr
                            #print(data_reference)
                            if self.check_validity_data_references(hex(data_reference), sec_offsets):
                                #print("valid")
                                func_refs.append(data_reference)

            
        #print(func_refs)
        return func_refs


    def dic_section_offsets(self):

        section_offset = {}

        for entry in self.section_offsets:
            section_offset[entry[0]] = entry[1]
        return section_offset

    def check_validity_data_references(self, data_ref, dictionary_sections):
        # This function checks if a data reference exists in one of the three sections(.bss, .rodata, .data)
        bss_low_address = dictionary_sections['.bss'][0]
        bss_high_address = dictionary_sections['.bss'][1]
        rodata_low_address = dictionary_sections['.rodata'][0]
        rodata_high_address = dictionary_sections['.rodata'][1]
        data_low_address = dictionary_sections['.data'][0]
        data_high_address = dictionary_sections['.data'][1]
        A = (data_ref>=bss_low_address and data_ref<=bss_high_address)
        B = (data_ref>=rodata_low_address and data_ref<=rodata_high_address)
        C = (data_ref>=data_low_address and data_ref<=data_high_address)

        if A or B or C :
            return True
        else:
            return False
