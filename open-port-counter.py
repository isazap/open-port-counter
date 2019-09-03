#!/usr/bin/python

"""
    File name: open-port-counter.py
    Author: Paula Turnbull
    Description: Given a text file of IP4 addresses for Juniper devices, reports total no. open ports (incl. per device)
    Date created: 22/11/2018
    Date last modified:
    Python Version: 2.7
"""

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import *
from lxml import etree
from jnpr.junos.op.ethport import EthPortTable
import getpass
import datetime
import time
import re
import threading
import multiprocessing
import logging
import socket
import warnings
import os

total_ports_open = 0  # these two will be global variables
device_dict = {}      # accessed by all the threads

#---reports function processing
#TODO discover why function info not displaying
def profile(func):
    def wrapper(*args, **kwargs):
        import time
        start = time.time()
        func(*args, **kwargs)
        end   = time.time()
        print(end - start)
    return wrapper

#---function to discover which ports are open on a device
#@profile
def get_port_list(host, username, pwd, total_ports_open_lock, device_dict_lock):
	count_up = 0
	connect_timeout = 10

	#global resources shared by all threads
	global total_ports_open
	global device_dict

	try:
		# Connect to devices in devices file using username and password provided above
		dev = Device(host=host.strip(), user=username, password=pwd, port_no=22)
		dev.open(auto_probe=connect_timeout)
		dev.timeout = connect_timeout
		eths = EthPortTable(dev).get()

		# for every port on this device
		for port in eths:
			status = port.oper
			descrip = port.description

			# if the port is a wifi port don't add it
			if descrip not in ["WAPS"] and status in ["up"]:
				count_up +=1

        #update our global variables safetly
		with total_ports_open_lock:
			total_ports_open += count_up

		with device_dict_lock:
		    device_dict[host] = count_up

		dev.close()

	except ConnectAuthError:
			print "\nAuthentication error on: ", host
	except ConnectError as err:
            print ("Cannot connect to device: ".format(err))
	except Exception,e:
			print "\nError ", e, "on host: ", host


#---print the header info to the screen
def display_header() :
    now = time.strftime("%c")
    print "Current date & time " + time.strftime("%c")
    print "This script counts the total number of ports up per device list\n "
    print ""

    #write the header to our log file
    log = open('log1.txt', 'a')
    log.write("\n")
    log.write("\nBEGIN-OF-SCRIPT=============================\n")
    log.write(now)
    log.close()


#---display the results and footer ----
def display_results(start, end):
    #TODO log errors with python logging
    later = time.strftime("%c")
    log = open('log1.txt', 'a')
    log.write("\n")
    log.write(later)
    log.write("\nEND-OF-SCRIPT=============================\n")
    log.close()

    #print ""
    #print "Here is the list of devices with errors:"
    #print ""

    print "TOTAL DEVICES WITH OPEN PORTS:", len(device_dict)
    print "TOTAL PORTS OPEN:", total_ports_open
    print "\nDevices paired with number ports open:", device_dict


    print "Total Proessing Time: ", (end - start)

    #log errors
    #str(err_dev_list).strip('[]')
    #print '\n'.join(map(str,err_dev_list))
    #print ""

# --main driver ---------------
def main() :
    display_header()
    device = raw_input("Enter the name of the file, that lists the IP of the devices:")
    threads = []
    err_dev_list = []

    #no. of logical cpus
    #print " no. of CPU's ", multiprocessing.cpu_count()

    if (not os.path.isfile(device)):
        print "No file found"

    else:
        try:
            with open(device) as infile:
                #Grab credentials
                username = raw_input("Enter your username:")
                with warnings.catch_warnings():
                     warnings.simplefilter('ignore', getpass.GetPassWarning)
                     password = getpass.getpass(str('password: '))

                #create  locks for our shared resources
                total_ports_open_lock = threading.Lock()
                device_dict_lock = threading.Lock()

                start = time.time()

                #TODO try doing multi processing instead of threading
                #So for every device we have on file, create a separate thread to find all up ports
                for host in infile:
                        try:
                            # first check the string is a valid IPv4 address
                            socket.inet_aton(host)

                            # spawn a new thread for each device listed in the file if it is a valid IP
                            t = threading.Thread(target=get_port_list, args=(host,username,password,total_ports_open_lock,device_dict_lock))
                            threads.append(t)
                            t.start()
                            t.join()  # this makes the main code wait until all threads are finished before continuing

                        except socket.error:
                            #TODO log error
                            print "Invalid IP: ", host
                end = time.time()
                display_results(start, end)

        except Exception,e:
            print "Error:", e, "\n"
            log.write("\nError on: ")
            log.write(host)
            log.write(str(e))
            log.write("\n")
            err_dev_list.append(host)  #make this a dictionary mapping device to error


#-- main call----
if __name__ == '__main__':
    main()


