import os
import time

i = 0
while True:
	i += 1
	time.sleep(60)
	os.system("cp /home/codex/developer/networkSniffer/log.txt /home/codex/developer/networkSniffer/log.bak")

