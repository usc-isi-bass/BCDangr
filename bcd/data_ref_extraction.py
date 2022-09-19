
class DataRefExtraction:

    def __init__(self, proj, cfg, func_list, section_offsets):
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
        function_references = []
        #print(self._func_list)
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
                                data_reference = rip+new_offset-base_address
                                if self.check_validity_data_references(hex(data_reference), sec_offsets):
                                    function_references.append(data_reference)
        #function_references.sort()
        #print("it is here")
        #print(function_references)
        #func_references = list(set(function_references))
        return function_references

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
