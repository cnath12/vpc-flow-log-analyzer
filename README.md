# VPC Flow Log Analyzer

This Python script analyzes AWS VPC Flow Logs and categorizes traffic based on a user-defined lookup table.

## Requirements

- Python 3.6+

## Usage

Run the script using the following command:

```
python flow_log_analyzer.py <flow_log_file> <lookup_table_file> <tag_output_file> <combo_output_file>
```

- `<flow_log_file>`: Path to the input VPC Flow Log file
- `<lookup_table_file>`: Path to the CSV file containing the lookup table
- `<tag_output_file>`: Path where the tag counts will be saved
- `<combo_output_file>`: Path where the port/protocol combination counts will be saved

Example:
```
python flow_log_analyzer.py flow_logs.txt lookup_table.csv tag_counts.csv port_protocol_counts.csv
```

## Input File Formats

1. Flow Log File:
   - Plain text file
   - Each line represents a single flow log entry
 
2. Lookup Table File:
   - CSV file with headers: dstport,protocol,tag
   
## Output Files

1. Tag Counts File:
   - CSV file with columns: Tag, Count

2. Port/Protocol Combination Counts File:
   - CSV file with columns: Port, Protocol, Count

## Assumptions

- Only the destination port is considered for tagging.
- ICMP traffic is matched solely based on the protocol number (port is ignored).
- The lookup table may include entries for port 0.
- Unmatched entries are tagged as 'Untagged'.
- The script is optimized for flow log files up to 10 MB and lookup tables up to 10,000 mappings.

