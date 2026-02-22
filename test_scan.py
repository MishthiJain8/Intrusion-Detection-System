import socket, time

target = "127.0.0.1"
ports = [80, 443, 8080, 22, 21, 3306, 5432, 27017, 6379, 8888]

print("Simulating port scan...")
for port in ports:
    try:
        s = socket.socket()
        s.settimeout(0.3)
        s.connect((target, port))
        s.close()
    except:
        pass
    time.sleep(0.1)

print("Done! Check the IDS dashboard.")