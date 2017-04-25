#print "hello"

import os
import re
import time
from subprocess import call

while True:
	time.sleep(1)
	ifData = os.popen("ifconfig wlxc4e98415edd0").read()
	if re.search(r'inet addr:192.168.1.1[\d]{2}',ifData):
		print "[runSniffAtBoot] Interface connected to intended SSID!"
#		os.system("cd /home/codex/developer/networkSniffer")
#		os.system("/home/codex/developer/networkSniffer/binary wlxc4e98415edd0 &")
		call(["/home/codex/developer/networkSniffer/binary","wlxc4e98415edd0","&"])
		break;
	else:
		print "[runSniffAtBoot] Bringing up interface!"

