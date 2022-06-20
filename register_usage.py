#
#@
from capstone import *
from capstone.x86 import *
class NodeLiveness():
    def __init__(self):
        self.live_in = set()
        self.live_out = set()
        self.successors = set()
        self.node_use = set()
        self.node_def = set()
        self.can_die = True
        self.node_length = 0

    def print(self):
        print("LIVE_IN -> ", end="")
        print(self.live_in)
        print("LIVE_OUT -> ", end="")
        print(self.live_out)
        print("USE -> ", end="")
        print(self.node_use)
        print("DEF -> ", end="")
        print(self.node_def)
        print("SUCCESSORS -> ", end="")
        for succ in self.successors:
            print(hex(succ),end=" ")
        print("\n----------------------------")
    
    def set_use_and_def(self, instruction_bytes, address):
        for insn in md.disasm(instruction_bytes, address):
            (regs_read, regs_write) = insn.regs_access()
            if len(regs_read) > 0:
                for r in regs_read:
                    self.node_use.add(get_biggest_reg(insn.reg_name(r)))
            if len(regs_write) > 0:
                for r in regs_write:
                    self.node_def.add(get_biggest_reg(insn.reg_name(r)))
            for operand in insn.operands:
                if operand.type == X86_OP_MEM:
                    self.can_die = False

    
def get_biggest_reg(reg):
    if reg in ["eax", "ax", "ah", "al"]:
        return "rax"

    elif reg in ["ebx", "bx", "bh", "bl"]:
        return "rbx"

    elif reg in ["ecx", "cx", "ch", "cl"]:
        return "rcx"

    elif reg in ["edx", "dx", "dh", "dl"]:
        return "rdx"

    elif reg in ["esi", "si", "sil"]:
        return "rsi"

    elif reg in ["edi", "di", "dil"]:
        return "rdi"

    elif reg in ["ebp", "bp", "bpl"]:
        return "rbp"

    elif reg in ["esp", "sp", "spl"]:
        return "rsp"

    elif reg in ["r8d", "r8w", "r8b"]:
        return "r8"

    elif reg in ["r9d", "r9w", "r9b"]:
        return "r9"

    elif reg in ["r10d", "r10w", "r10b"]:
        return "r10"

    elif reg in ["r11d", "r11w", "r11b"]:
        return "r11"

    elif reg in ["r12d", "r12w", "r12b"]:
        return "r12"

    elif reg in ["r13d", "r13w", "r13b"]:
        return "r13"

    elif reg in ["r14d", "r14w", "r14b"]:
        return "r14"

    elif reg in ["r15d", "r15w", "r15b"]:
        return "r15"
    else:
        return reg


def print_reg_usage(instruction_bytes, address):
    for insn in md.disasm(instruction_bytes, address):
        (regs_read, regs_write) = insn.regs_access()
        if len(regs_read) > 0:
            print("\n\tRegisters read:", end="")
            for r in regs_read:
                print(" %s" %(get_biggest_reg(insn.reg_name(r))), end="")
            print()
        if len(regs_write) > 0:
            print("\n\tRegisters modified:", end="")
            for r in regs_write:
                print(" %s" %(get_biggest_reg(insn.reg_name(r))), end="")
            print()


bv = current_view
br = BinaryReader(bv)


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


print("starting")
total_removed = 0
while True:
    nodes = dict()
    for bb in current_function.basic_blocks:
        address = bb.start
        br.seek(address)
        
    
        while address < bb.end:
            node_liveness = NodeLiveness()
        
            instruction_length = bv.get_instruction_length(address)
           
            node_liveness.set_use_and_def(br.read(instruction_length), address)
            node_liveness.node_length = instruction_length
            node_address = address    
    
            address = address + instruction_length
            if address != bb.end:
                node_liveness.successors.add(address)
            else:
                for edge in bb.outgoing_edges:
                    node_liveness.successors.add(edge.target.start)
            nodes[node_address] = node_liveness
    
    
    
    nodes[here].node_use.add("rax")
    nodes[here].node_use.add("rbx")
    nodes[here].node_use.add("rcx")
    nodes[here].node_use.add("rdx")
    nodes[here].node_use.add("rsi")
    nodes[here].node_use.add("rdi")
    nodes[here].node_use.add("rbp")
    nodes[here].node_use.add("rsp")
    nodes[here].node_use.add("r8")
    nodes[here].node_use.add("r9")
    nodes[here].node_use.add("r10")
    nodes[here].node_use.add("r11")
    nodes[here].node_use.add("r12")
    nodes[here].node_use.add("r13")
    nodes[here].node_use.add("r14")
    nodes[here].node_use.add("r15")
    nodes[here].node_use.add("rflags")
    nodes[here].node_def.clear()
    while True:
        should_stop = True
        for address, node in nodes.items():
            live_in_prime = node.live_in.copy()
            live_out_prime = node.live_out.copy()
            
            node.live_in = node.node_use.union(node.live_out - node.node_def)
            node.live_out.clear()
            for s in node.successors:
                if s in nodes:
                    node.live_out = node.live_out.union(nodes[s].live_in)
                else:
                    print("Error?")
            if live_in_prime != node.live_in:
                should_stop = False
            elif live_out_prime != node.live_out:
                should_stop = False
            
        if should_stop:
            break
    
    instructions_removed = 0
    
    for address, node in nodes.items():
        #print(f"Address -> {hex(address)}")    
        if node.node_def.isdisjoint(node.live_out) and node.can_die and (len(node.node_def) != 0):
        #    print("DEAD")
            for i in range(node.node_length):
                current_function.set_user_instr_highlight(address+i, HighlightStandardColor.RedHighlightColor)
            
            bv.convert_to_nop(address)
            instructions_removed = instructions_removed + 1
        #node.print()
    total_removed = total_removed + instructions_removed
    if instructions_removed == 0:
        break
print(f"done removed -> {total_removed} instructions")

