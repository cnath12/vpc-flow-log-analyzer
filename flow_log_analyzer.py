import csv
from collections import defaultdict
from typing import Dict, Tuple
import argparse

def load_lookup_table(file_path: str) -> Dict[Tuple[int, str], str]:
    lookup = {}
    with open(file_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            port = int(row['dstport'])
            protocol = row['protocol'].lower()
            tag = row['tag']
            lookup[(port, protocol)] = tag
    return lookup

def process_flow_logs(log_file: str, lookup_table: Dict[Tuple[int, str], str]) -> Tuple[Dict[str, int], Dict[Tuple[int, str], int]]:
    tag_counts = defaultdict(int)
    port_protocol_counts = defaultdict(int)
    with open(log_file, 'r') as f:
        for line in f:
            fields = line.strip().split()
            if len(fields) < 14 or fields[0] != '2':  # Ensure it's a valid v2 flow log entry
                continue
            dstport = int(fields[6])
            protocol = fields[7]
            
            # Convert protocol number to name
            protocol_name = {6: 'tcp', 17: 'udp', 1: 'icmp'}.get(int(protocol), 'tcp')  # Default to 'tcp' if unknown
            
            # For ICMP, ignore the port
            if protocol_name == 'icmp':
                lookup_key = (0, 'icmp')
            else:
                lookup_key = (dstport, protocol_name)
            
            tag = lookup_table.get(lookup_key, 'Untagged')
            tag_counts[tag] += 1
            
            if tag != 'Untagged':
                port_protocol_counts[lookup_key] += 1
    
    return dict(tag_counts), dict(port_protocol_counts)

def write_output(data: Dict, file_path: str, headers: list):
    with open(file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for key, value in data.items():
            if isinstance(key, tuple):
                writer.writerow([*key, value])
            else:
                writer.writerow([key, value])

def main():
    parser = argparse.ArgumentParser(description='Analyze VPC Flow Logs')
    parser.add_argument('log_file', help='Path to the flow log file')
    parser.add_argument('lookup_file', help='Path to the lookup table file')
    parser.add_argument('tag_output', help='Path to the tag counts output file')
    parser.add_argument('combo_output', help='Path to the port/protocol combination counts output file')
    args = parser.parse_args()

    lookup_table = load_lookup_table(args.lookup_file)
    tag_counts, port_protocol_counts = process_flow_logs(args.log_file, lookup_table)

    write_output(tag_counts, args.tag_output, ['Tag', 'Count'])
    write_output(port_protocol_counts, args.combo_output, ['Port', 'Protocol', 'Count'])

if __name__ == "__main__":
    main()