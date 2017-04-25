import time


fp = open('dummyLog', 'w')
i = 0
while (i < 60):
	i += 1
	time.sleep(2)
	fp.write('Writing dummy line\n')

fp.close()
