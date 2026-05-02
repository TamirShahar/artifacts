# the program:
# struct sock_filter bpf_code[] = {
#     { BPF_LD  | BPF_W | BPF_LEN, 0, 0, 0 },
#     { BPF_JMP | BPF_JGT | BPF_K, 1, 0, 100},
#     {BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF},
#
#     {BPF_LD | BPF_B | BPF_ABS, 0, 0, 8},
#     {BPF_ALU | BPF_JEQ | BPF_K, 0, 1, 1},
#     {BPF_RET | BPF_K, 0, 0, 32+1},

#     {BPF_LD | BPF_B | BPF_ABS, 0, 0, 8},
#     {BPF_ALU | BPF_JEQ | BPF_K, 0, 1, 2},
#     {BPF_RET | BPF_K, 0, 0, 32+2},

#     {BPF_LD | BPF_B | BPF_ABS, 0, 0, 8},
#     {BPF_ALU | BPF_JEQ | BPF_K, 0, 1, 3},
#     {BPF_RET | BPF_K, 0, 0, 32+3},

# etc...
# };

# python script that generates the above code:
import sys

ACK_START = 8  # Index of ACK in TCP header
# TCP_HEADER = 20
TCP_HEADER = 32


# def generate_bpf_code(part, header_len=TCP_HEADER, minimum_length=350):
def generate_bpf_code(part, header_len=TCP_HEADER, minimum_length=150):
    """
    part: 1-4 (the corresponding byte in the ISN)
    tcp_header_len: length of the TCP header in bytes
    minimum_length: minimum length of the packet (if it's shorter,
    it won't be changed).
    """
    bpf_code = []
    bpf_code.append("struct sock_filter bpf_code" + str(part) + "[] = {")
    bpf_code.append("{ BPF_LD  | BPF_W | BPF_LEN, 0, 0, 0 },")
    bpf_code.append("{ BPF_JMP | BPF_JGT | BPF_K, 1, 0, " + str(minimum_length) + "},")
    bpf_code.append("{BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF},")
    bpf_code.append("")
    for i in range(0, 256):
        if i == 0:
            bpf_code.append(
                "{BPF_LD | BPF_B | BPF_ABS, 0, 0, " + str(ACK_START + part - 1) + "},"
            )
        bpf_code.append("{BPF_JMP | BPF_JEQ | BPF_K, 0, 1, " + str(i) + "},")
        bpf_code.append("{BPF_RET | BPF_K, 0, 0," + str(header_len + i) + "},")
        bpf_code.append("")
    bpf_code.append("{BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF},")
    bpf_code.append("};")

    bpf_code.append("")
    bpf_code.append("struct sock_fprog bpf_prog" + str(part) + " = {")
    bpf_code.append(
        "    .len = sizeof(bpf_code" + str(part) + ") / sizeof(struct sock_filter),"
    )
    bpf_code.append("    .filter = bpf_code" + str(part) + ",")
    bpf_code.append("};")
    bpf_code.append("")

    return bpf_code


if __name__ == "__main__":
    # bpf_code = generate_bpf_code(part=4)
    bpf_code = []
    bpf_code.append("#include <linux/filter.h>")
    bpf_code.append("")
    for i in range(1, 5):
        bpf_code.extend(generate_bpf_code(i))
    bpf_code.append("")
    bpf_code.append("struct sock_filter bpf_code_no_filter[] = {")
    bpf_code.append("{ BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF},")
    bpf_code.append("};")
    bpf_code.append("")
    bpf_code.append("struct sock_fprog bpf_prog_no_filter = {")
    bpf_code.append(
        "    .len = sizeof(bpf_code_no_filter) / sizeof(struct sock_filter),"
    )
    bpf_code.append("    .filter = bpf_code_no_filter,")
    bpf_code.append("};")
    with open("cbpf_program.h", "w") as f:
        for line in bpf_code:
            f.write(line + "\n")
    print("Generated cbpf_program.h")
