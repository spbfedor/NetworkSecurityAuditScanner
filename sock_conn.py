import socket, threading
import json


HOST = "scanme.nmap.org"
PORTS = [21, 22, 23, 53, 80, 443, 8080, 8443]

all_ports = []

try:
    host = socket.gethostbyname(HOST)
except:
    print("Не удалось подключиться  к хосту")
    exit()

request = f"GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"

def check_port(host, port):
    with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        result = s.connect_ex((host, port))
        current_ports_data = {}
        current_ports_data["port"] = port

        if result == 0:
            try:
                current_ports_data["status"] = "open"
                if port in [80, 8080, 443]:
                    s.send(request.encode())
                response = s.recv(128)
            
                if response:
                    current_ports_data["banner"] = f"{response.decode(errors='ignore')}"
                else:
                    current_ports_data["banner"] = None
            except socket.timeout:
                current_ports_data["banner"] = None
            except Exception as e:
                print(f"Ошибка при получении баннера {e}")
        else:
            current_ports_data["status"] = "closed"
        
        all_ports.append(current_ports_data)

threads = []

for port in PORTS:
    t = threading.Thread(target=check_port, args=((host, port)))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

with open("scan_report.json", "w", encoding="utf-8") as f:
    json.dump(all_ports, f, indent=4, ensure_ascii=False)
