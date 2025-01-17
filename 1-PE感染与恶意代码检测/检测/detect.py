import os
import pefile
import ahocorasick


# 创建 AC 自动机并添加病毒签名
def build_ac_automaton(signatures):
    automaton = ahocorasick.Automaton()# 创建一个 Aho-Corasick 自动机对象
    for idx, signature in enumerate(signatures):
        hex_string = signature[0].hex()# 将病毒签名的字节序列转换为十六进制字符串
        print(f"Adding signature: {hex_string} for virus {signature[1]}")
        automaton.add_word(hex_string, (idx, signature[1]))
    automaton.make_automaton()# 构建自动机
    print("Automaton built successfully.")
    return automaton


# 使用 AC 自动机搜索文件是否包含任何病毒签名
def is_file_infected(file_path, ac_automaton):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()# 读取文件的全部内容
            hex_content = content.hex()# 将文件内容转换为十六进制字符串
            # 使用 Aho-Corasick 自动机迭代搜索十六进制内容中的病毒签名
            for _, (index, virus_name) in ac_automaton.iter(hex_content):
                # 如果找到匹配的病毒签名，打印文件被感染的信息并返回 True
                print(f"Infected File: {file_path}, Virus: {virus_name}")
                return True
    # 处理文件读取和搜索过程中的异常
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    # 如果没有找到匹配的病毒签名，返回 False
    return False

# 递归扫描当前目录及其子目录并检查每个 PE 文件
def scan_directory(current_directory, ac_automaton):
    infected_files = []
    for root, dirs, files in os.walk(current_directory):
        for name in files:
            file_path = os.path.join(root, name)
            try:
                print(f"Checking file: {file_path}")
                pe = pefile.PE(file_path)
                if is_file_infected(file_path, ac_automaton):
                    infected_files.append(file_path)  # 存储完整文件路径
                    print(f"File {file_path} is infected.")
                pe.close()
            except pefile.PEFormatError:
                print(f"{file_path} is not a PE file, skipping.")
                continue  # 忽略非 PE 文件
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")
    return infected_files


if __name__ == "__main__":
    # 定义病毒签名（字节序列和对应的病毒名称）
    virus_signatures = [
        (b'\xD6\xD8\xB6\xA8\xCE\xBB\xCD\xEA\xB1\xCF\xA3\xAC\xB2\xA2\xBB\xF1\xB5\xC3\xCB\xF9\xD3\xD0\x41\x50\x49\xB5\xD8\xD6\xB7\xA3\xA1',"PEvirus"),
    ]

    # 构建 AC 自动机
    ac_automaton = build_ac_automaton(virus_signatures)

    # 扫描当前目录下的所有文件
    current_directory = os.getcwd()
    infected_files = scan_directory(current_directory, ac_automaton)

    if infected_files:
        print("Infected Files Found:")
        for file_path in infected_files:
            print(file_path)
    else:
        print("No infected files found.")