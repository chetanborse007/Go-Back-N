# GO-BACK-N PROTOCOL


## DESCRIPTION
This is an implementation of GO-BACK-N reliable transport layer protocol.


## RUNNING SERVER
python ServerApp.py -a [sender_ip] -b [sender_port] -x [receiver_ip] -y [receiver_port] -m [sequence_number_bits]

e.g. python ServerApp.py -a "127.0.0.1" -b 8081 -x "127.0.0.1" -y 8080 -m 2


## RUNNING CLIENT
python ClientApp.py -f [filename] -a [sender_ip] -b [sender_port] -x [receiver_ip] -y [receiver_port] -m [sequence_number_bits] -w [window_size] -s [max_segment_size] -n [total_packets] -t [timeout]

e.g. python ClientApp.py -f "index.html" -a "127.0.0.1" -b 8081 -x "127.0.0.1" -y 8080 -m 2 -w 3 -s 1500 -n "ALL" -t 10


## Maintainer
 - Name:        Chetan Borse
 - EMail ID:    chetanborse2106@gmail.com
 - LinkedIn:    https://www.linkedin.com/in/chetanrborse
