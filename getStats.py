storeFile = 'analytics.txt'

fp = open(storeFile, 'r')
dm = eval(fp.readline().rstrip())
sm = eval(fp.readline().rstrip())
fp.close()

print "==============Destination MAC===============" 
for key in dm.keys():
	print key, dm[key]

print "\n"
print "================Source MAC=================="
for key in sm.keys():
	print key, sm[key]
