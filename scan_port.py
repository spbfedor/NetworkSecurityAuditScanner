import asyncio
import json
import logging
import socket
import ssl


class NetworkAuditScanner:
    def __init__(self, config_path):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("scanner.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

        with open(config_path, "r") as file:
            self.config = json.loads(file.read())

        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.results = []
        self.target_ip = None

    async def resolve_target(self):
        loop = asyncio.get_running_loop()
        try:
            self.logger.info(f"Начинаю поиск IP для {self.config['target']}")
            info = await loop.getaddrinfo(
                self.config["target"],
                None,
                family=socket.AF_INET
            )
        except socket.gaierror as e:
            self.logger.error(f"Хост {self.config['target']} не найден - {e}")
            return
        self.target_ip = info[0][4][0]   

    async def scan_port(self, port):
        request = (f"GET / HTTP/1.1\r\nHost: "
                   f"{self.config['target']}\r\nConnection: close\r\n\r\n")
        current_ports_data = {
            "port": port,
            "status": "closed",
            "banner": None
        }
        try:
            ssl_context = None
            if port == 443:
                ssl_context = self.ssl_context
            self.logger.info(f"Сканирую порт: {port}")
            connect = asyncio.open_connection(
                self.config["target"],
                port, ssl=ssl_context
            )
            reader, writer = await asyncio.wait_for(
                connect,
                timeout=self.config["timeout"]
            )

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

        self.results.append(current_ports_data)

    async def run(self):
        await self.resolve_target()
        if self.target_ip is None:
            return []
        tasks = [self.scan_port(port) for port in self.config["ports"]]
        await asyncio.gather(*tasks)
        return self.results


async def main():
    scanner = NetworkAuditScanner("config.json")
    report = await scanner.run()
    with open(
        "scan_report.json",
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

asyncio.run(main())
