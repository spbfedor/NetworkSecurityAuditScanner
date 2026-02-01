import asyncio
import socket
import json
import ssl


with open("NetworkSecurityAuditScanner/config.json", "r") as file:
    data = json.loads(file.read())
    host, ports, timeout = [*data.values()]

all_ports = []

request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"

async def scan_port(host, port):
    current_ports_data = {"port": port, "status": "closed", "banner": None}
    try:
        ssl_context = None
        if port == 443:
            ssl_context = ssl.create_default_context()
            # Отключаем прверку что бы не падать
            #  на самоподписных сертификатах
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        connect = asyncio.open_connection(host, port, ssl=ssl_context)
        reader, writer = await asyncio.wait_for(connect, timeout=timeout)

        current_ports_data["status"] = "open"

        try:
            if port in [8080, 443, 80]:
                writer.write(request.encode())
                await writer.drain()

            data = await asyncio.wait_for(reader.read(100), timeout=1.0)
            current_ports_data["banner"] = data.decode(
                errors='ignore'
            ).strip()

        except:
            current_ports_data["banner"] = "No banner"

        writer.close()
        await writer.wait_closed()

    except Exception:
        pass
        
    all_ports.append(current_ports_data)


async def main():
    loop = asyncio.get_running_loop()
    try:
        info = await loop.getaddrinfo(host, None, family=socket.AF_INET)
    except socket.gaierror as e:
        print(f"Заданный хост не найден {e}")
        return
    ipaddr = info[0][4][0]   
    tasks = [scan_port(host, port) for port in ports]
    await asyncio.gather(*tasks)

asyncio.run(main())

with open(
    "NetworkSecurityAuditScanner/scan_report.json",
    "w",
    encoding="utf-8"
) as f:
        json.dump(all_ports, f, indent=4, ensure_ascii=False)