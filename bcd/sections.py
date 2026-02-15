class Section:
    def __init__(self, elf_section):
        self.name = elf_section.name
        self.header = elf_section.header
    
    def compute_section_offsets(self):
        start_address = self.header['sh_addr']
        end_address = start_address+ self.header['sh_size']
        return (self.name, (hex(start_address), hex(end_address)))

        