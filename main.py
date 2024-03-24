import socket
import subprocess
from ipwhois import IPWhois
import re
from prettytable import PrettyTable


def trace_domain(domain, max_hops):
    try:
        ip = socket.gethostbyname(domain)
        print(f"Tracing route to {domain} [{ip}]")
        traceroute_output = subprocess.check_output(["tracert", "-h", str(max_hops), domain]).decode("cp1251")
        return traceroute_output
    except socket.gaierror:
        print("Hostname could not be resolved.")


def get_info(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        as_info = results.get("asn", 'AS number not found')
        description = results.get('asn_description', 'AS description not found')
        country = results.get('asn_country_code', 'AS country not found')
        return [ip, as_info, description, country]
    except Exception as e:
        print(f"Error retrieving AS information for {ip}: {e}")


def main():
    domains = input().split()
    max_hops = 5
    for domain in domains:
        table = PrettyTable()
        table.field_names = ["IP Address", "AS number", "AS description", "AS country"]
        info = trace_domain(domain, max_hops)
        ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        if info:
            for trace in info.split('\n'):
                ipv4_matches = re.search(ipv4_pattern, trace)
                if ipv4_matches:
                    row = get_info(ipv4_matches.group(0))
                    if row:
                        table.add_row(row)
                else:
                    continue
            print(table)


if __name__ == "__main__":
    main()


