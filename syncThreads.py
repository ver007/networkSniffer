#!/usr/bin/python

import threading
import time

class myThread (threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
    def run(self):
        print "Starting " + self.name
        update_counter(self.name, self.counter)
        # Get lock to synchronize threads
        #threadLock.acquire()
        #print_time(self.name, self.counter, 3)
        # Free lock to release next thread
        #threadLock.release()





def update_counter(threadName, delay):
    global protectedCounter
    while (True):
        time.sleep(delay)
        #print "%s: %s" % (threadName, time.ctime(time.time()))
        #counter -= 1
        threadLock.acquire()
        protectedCounter += 1
        print "" + threadName + str(protectedCounter)
        threadLock.release()

threadLock = threading.Lock()
threads = []
protectedCounter = 0

# Create new threads
thread1 = myThread(1, "Thread-1", 2)
#thread2 = myThread(2, "Thread-2", 0.7)

# Start new Threads
thread1.start()
#thread2.start()
# Add threads to thread list
threads.append(thread1)
#threads.append(thread2)
update_counter("Main Thread", 0.5)

# Wait for all threads to complete
for t in threads:
    t.join()

print "Exiting Main Thread"
