import socket
import threading
from queue import Queue

# Thread-safe queue of ports
q = Queue()
open_ports = []

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))

        # Send protocol-specific probes
        if port == 80 or port == 8080:  # HTTP
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 21:  # FTP
            s.send(b"HELP\r\n")
        elif port == 25:  # SMTP
            s.send(b"EHLO test\r\n")

        banner = s.recv(1024).decode(errors="ignore")
        return banner.strip()
    except:
        return None
    
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            banner = grab_banner(ip, port)
            if banner:
                print(f"[+] Port {port} is OPEN — {banner}")
            else:
                print(f"[+] Port {port} is OPEN")
            open_ports.append(port)
        sock.close()
    except:
        pass

def worker(ip):
    while not q.empty():
        port = q.get()
        scan_port(ip, port)
        q.task_done()

def threaded_scan(ip, num_threads):
    # put all ports into the queue
    for port in range(1, 65353):
        q.put(port)

    threads = []
    for _ in range(num_threads):  # start N worker threads
        t = threading.Thread(target=worker, args=(ip,))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()  # wait until all ports are scanned

    return open_ports

def identify_service(ip, port):
    banner = grab_banner(ip, port)
    service = "unknown"
    version = "unknown"
    if banner:
        if "HTTP" in banner:
            service = "HTTP"
            version = banner.split("\n")[0]
        elif "SSH" in banner:
            service = "SSH"
            version = banner.split("\n")[0]
        elif "FTP" in banner:
            service = "FTP"
            version = banner.split("\n")[0]
        # Add more protocols as needed
    return service, version



if __name__ == "__main__":
    targetip = input("Enter IP to scan: ")
    print(f"[*] Scanning {targetip} for open ports...")
    results = threaded_scan(targetip, num_threads=200)

    print("\nScan complete.")
    print(f"Open ports on {targetip}: {results if results else 'None found'}")

