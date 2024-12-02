# DDOS_DNS_AMPLIFICATION
Shabby and simple DDos via DNS amplification. 


*ONLY TESTED IN LINUX

How it works? 
  Very simple, we create a DNS query with query type A, the source IP will be the target IP, this will overflow his DNS server with requests, resulting in a larger response being sent to the target. This can cause service disruption or denial of service due to the amplified traffic.

Arguments: 

  --t_ip: Target IP address. 
  
  --dns-server: DNS server to use (default: 8.8.8.8).
  
  --qn: Domain name for DNS queries (default: facebook.com).
  
  --packets: Number of packets to send (default: 200).
  
  --max-threads: Number of threads for concurrent attack (default: 2).
  
  --timeout: Time between each packet send in seconds (default: 0).

Example: 

  sudo python main.py --t_ip 192.168.1.1 --dns-server 8.8.8.8 --packets 240 --max-threads 4 --timeout 1 
