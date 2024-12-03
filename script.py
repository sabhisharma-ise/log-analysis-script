import re
from collections import defaultdict
import csv
from typing import List, Dict, Tuple

def parse_log_file(log_file_path: str) -> List[Dict[str, str]]:
    """
    Parse log file and extract structured log entries.
    
    Args:
        log_file_path (str): Path to the log file
    
    Returns:
        List of dictionaries containing log entry details
    """
    log_entries = []
    log_pattern = re.compile(r'^(\d+\.\d+\.\d+\.\d+) .* "(\w+) (/[^\s]*) HTTP/\d\.\d" (\d+)')
    
    with open(log_file_path, 'r') as file:
        for line in file:
            match = log_pattern.match(line)
            if match:
                log_entries.append({
                    'ip': match.group(1),
                    'method': match.group(2),
                    'endpoint': match.group(3),
                    'status_code': match.group(4)
                })
    
    return log_entries

def count_requests_per_ip(log_entries: List[Dict[str, str]]) -> List[Tuple[str, int]]:
    """
    Count number of requests per IP address.
    
    Args:
        log_entries (List[Dict[str, str]]): Parsed log entries
    
    Returns:
        Sorted list of IP addresses and their request counts
    """
    ip_counts = defaultdict(int)
    for entry in log_entries:
        ip_counts[entry['ip']] += 1
    
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

def find_most_accessed_endpoint(log_entries: List[Dict[str, str]]) -> Tuple[str, int]:
    """
    Find the most frequently accessed endpoint.
    
    Args:
        log_entries (List[Dict[str, str]]): Parsed log entries
    
    Returns:
        Tuple of most accessed endpoint and its access count
    """
    endpoint_counts = defaultdict(int)
    for entry in log_entries:
        endpoint_counts[entry['endpoint']] += 1
    
    return max(endpoint_counts.items(), key=lambda x: x[1])

def detect_suspicious_activity(log_entries: List[Dict[str, str]], threshold: int = 10) -> List[Tuple[str, int]]:
    """
    Detect potential brute force login attempts.
    
    Args:
        log_entries (List[Dict[str, str]]): Parsed log entries
        threshold (int): Number of failed login attempts to flag as suspicious
    
    Returns:
        List of suspicious IP addresses and their failed login counts
    """
    failed_login_counts = defaultdict(int)
    for entry in log_entries:
        if entry['endpoint'] == '/login' and entry['status_code'] == '401':
            failed_login_counts[entry['ip']] += 1
    
    return [
        (ip, count) for ip, count in failed_login_counts.items() 
        if count >= threshold
    ]

def save_results_to_csv(results: Dict[str, List[Tuple[str, int]]], output_file: str = 'log_analysis_results.csv'):
    """
    Save analysis results to a CSV file.
    
    Args:
        results (Dict): Dictionary containing analysis results
        output_file (str): Path to output CSV file
    """
    with open(output_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        
        # Write Requests per IP
        csv_writer.writerow(['IP Address', 'Request Count'])
        csv_writer.writerows(results['requests_per_ip'])
        csv_writer.writerow([])  # Add empty row between sections
        
        # Write Most Accessed Endpoint
        csv_writer.writerow(['Endpoint', 'Access Count'])
        csv_writer.writerow([results['most_accessed_endpoint'][0], results['most_accessed_endpoint'][1]])
        csv_writer.writerow([])  # Add empty row between sections
        
        # Write Suspicious Activity
        csv_writer.writerow(['IP Address', 'Failed Login Count'])
        csv_writer.writerows(results['suspicious_activity'])

def main(log_file_path: str = 'sample.log'):
    """
    Main function to perform log file analysis.
    
    Args:
        log_file_path (str): Path to log file
    """
    # Parse log file
    log_entries = parse_log_file(log_file_path)
    
    # Perform analyses
    requests_per_ip = count_requests_per_ip(log_entries)
    most_accessed_endpoint = find_most_accessed_endpoint(log_entries)
    suspicious_activity = detect_suspicious_activity(log_entries)
    
    # Print results to terminal
    print("Requests per IP Address:")
    for ip, count in requests_per_ip:
        print(f"{ip}: {count} requests")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity:")
    for ip, count in suspicious_activity:
        print(f"{ip}: {count} failed login attempts")
    
    # Save results to CSV
    save_results_to_csv({
        'requests_per_ip': requests_per_ip,
        'most_accessed_endpoint': most_accessed_endpoint,
        'suspicious_activity': suspicious_activity
    })
    
    print("\nResults saved to log_analysis_results.csv")

if __name__ == "__main__":
    main()