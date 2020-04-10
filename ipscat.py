#!/usr/bin/env python3.5
#Prints webservers running in an ip-range
#2020/04/10 OGCyb3r
import socket, http.client, threading, time, sys, os, IP2Location
def clean():
	clear='clear'
	os.system(clear)
clean()
def normalscan(ip, msg):
	ports = [80,443] #Normal scan will use only 2 ports.
	for port in ports:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((ip, port)) #TRY CONN
			s.close()
			IP2LocObj = IP2Location.IP2Location()
			IP2LocObj.open("data/x.BIN") #x.BIN WHERE IP2Location database .
			rec = IP2LocObj.get_all(ip)
			c1=(rec.country_long) #GEET TEHH COUNTRY NAME
			c2=(rec.isp)	#GET TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTHE ISP company
			c3=(rec.domain) #GET THE DOMAIN NAME
			print(("""[\x1b[30;38;5;119m+\x1b[0m]\x1b[1;38;5;47m%s\x1b[0m:\x1b[1;38;5;119m%s\x1b[0m \x1b[30;38;5;105m%s\x1b[0m \x1b[37;38;5;163m%s\x1b[0m, \x1b[37;48;5;235m%s\x1b[0m"""%(ip,str(port),c3,c2,c1)))
			SavePorts = open("t4mp/%s.txt"%(sys.argv[1]), "a+")
			SavePorts.write("%s:[%s],(%s , %s , %s)\n"%(ip,str(port),c3,c2,c1))
			SavePorts.close()
		except:pass
def fullscan(ip, msg):
	ports = [21,22,23,25,53,443,110,135,137,139,138,3308,143,993,465,995,80,8080,445,3389,1433] #FULL SCAN WILL USE THOSE PORTS
	for port in ports:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((ip, port))
			s.close()
			IP2LocObj = IP2Location.IP2Location()
			IP2LocObj.open("data/x.BIN")
			rec = IP2LocObj.get_all(ip)
			c1=(rec.country_long)
			c2=(rec.isp)
			c3=(rec.domain)
			print(("""[\x1b[30;38;5;119m+\x1b[0m]\x1b[1;38;5;47m%s\x1b[0m:\x1b[1;38;5;119m%s\x1b[0m \x1b[30;38;5;105m%s\x1b[0m \x1b[37;38;5;163m%s\x1b[0m,\x1b[37;48;5;235m%s\x1b[0m"""%(ip,str(port),c3,c2,c1)))
			SavePorts = open("t4mp/%s.txt"%(sys.argv[1]), "a+")
			SavePorts.write("%s:[%s],(%s , %s , %s)\n"%(ip,str(port),c3,c2,c1))
			SavePorts.close()
		except:pass
def fullmode(ip_range):
	lst = []
	iplist = []
	ip_range = ip_range.rsplit(".",2)
	if len(ip_range[1].split("-",1)) ==2:
		for i in range(int(ip_range[1].split("-",1)[0]),int(ip_range[1].split("-",1)[1])+1,1):
			lst.append(ip_range[0]+"."+str(i)+".")
		for ip in lst:
			for i in range(int(ip_range[2].split("-",1)[0]),int(ip_range[2].split("-",1)[1])+1,1):
				iplist.append(ip+str(i))
		return iplist
	if len(ip_range[1].split("-",1)) ==1:
		for i in range(int(ip_range[2].split("-",1)[0]),int(ip_range[2].split("-",1)[1])+1,1):
			iplist.append(ip_range[0]+"."+str(ip_range[1].split("-",1)[0])+"."+str(i))
		return iplist
def shortmode(ip_range):
	lst = []
	iplist = []
	ip_range = ip_range.rsplit(".",2)
	if len(ip_range[1].split("-",1)) ==2:
		for i in range(int(ip_range[1].split("-",1)[0]),int(ip_range[1].split("-",1)[1])+1,1):
			lst.append(ip_range[0]+"."+str(i)+".")
		for ip in lst:
			for i in range(int(ip_range[2].split("-",1)[0]),int(ip_range[2].split("-",1)[1])+1,1):
				iplist.append(ip+str(i))
		return iplist
	if len(ip_range[1].split("-",1)) ==1:
		for i in range(int(ip_range[2].split("-",1)[0]),int(ip_range[2].split("-",1)[1])+1,1):
			iplist.append(ip_range[0]+"."+str(ip_range[1].split("-",1)[0])+"."+str(i))
		return iplist
def main():
	path = "t4mp"
	if not os.path.exists(path):
		os.makedirs(path, exist_ok=True)
	if len(sys.argv) == 1:
		print(("""\x1b[1;38;5;105m@@@  @@@@@@@    @@@@@@    @@@@@@@   @@@@@@   @@@@@@@
@@@  @@@@@@@@  @@@@@@@   \x1b[1;38;5;104m@@@@@@@@  @@@@@@@@  @@@@@@@
@@!  @@!  @@@  !@@       !@@       @@!  @@@    @@!
!@!  !@!  @!@  \x1b[1;38;5;103m!@!       !@!       !@!  @!@    !@!
!!@  @!@@!@!   !!@@!!    !@!       @!@!@!@!    @!!
!!!  !!@!!!     !!@!!!   !!!       \x1b[1;38;5;109m!!!@!!!!    !!!
!!:  !!:            !:!  :!!       !!:  !!!    !!:
:!:  :!:           \x1b[1;38;5;110m!:!   :!:       :!:  !:!    :!:
 ::   ::       :::: ::    ::: :::  ::   :::     ::
:     :        :: : :     :: :: :   :   : :     :\x1b[0m
How to use :
	\x1b[1;38;5;252m--full\x1b[0m means scanning :
\x1b[1;38;5;226m[21,22,23,25,53,443,110,135,137,139,138,3308,143,993,465,995,80,8080,445,3389,1433]\x1b[0m

\x1b[1;38;5;119m[ method1 ]\x1b[0m python3.5 ipscat.py 127.0.0.1-255
\x1b[1;38;5;119m[ method2 ]\x1b[0m python3.5 ipscat.py 127.0.0.1-255 \x1b[1;38;5;252m--full\x1b[0m
"""))
		sys.exit(1)
	if len(sys.argv) >= 3:
		in1=sys.argv[2]
		if(in1=="--full"):
			try:
				iplist = fullmode(sys.argv[1])
			except(ValueError):
				print("[-] Incorrect IP-Range\n")
				sys.exit(1)
			print("\x1b[1;38;5;119m[ + ]\x1b[0m [full scan] start scanning ip address {%s} - total ips %s"%(sys.argv[1],len(iplist)))
			socket.setdefaulttimeout(3)
			for ip in iplist:
				time.sleep(1)
				threading.Thread( target=fullscan, args=(ip, 0) ).start()
			else:
				print(("""Timeout..."""))
	else:
		try:
			iplist = shortmode(sys.argv[1])
		except(ValueError):
			print("[-] Incorrect IP-Range\n")
			sys.exit(1)
		print("\x1b[1;38;5;119m[ + ]\x1b[0m [normal scan] start scanning ip address {%s} - total ips %s"%(sys.argv[1],len(iplist)))
		socket.setdefaulttimeout(3)
		for ip in iplist:
			time.sleep(1)
			threading.Thread( target=normalscan, args=(ip, 0) ).start()
if __name__ == '__main__':
    main()
