from scanner.nmap_scanner import scan_target


results, duration = scan_target("127.0.0.1")

print("Scan Duration:", duration)

print("\nScan Results:")

for result in results:
    print(result)