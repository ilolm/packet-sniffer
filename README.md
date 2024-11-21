# Packet-Sniffer

## DEPENDENCIES:
```
python3
python3-pip
```

---

## INSTALLATION:
```
git clone https://github.com/ilolm/packet-sniffer.git
cd packet-sniffer
pip3 install -r requirements.txt
chmod +x packet_sniffer.py
```

---

## USAGE:
```
Usage: sudo ./packet_sniffer.py [options]

Options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface=INTERFACE
                        Enter an interface that you want to sniff data from.
                        DEFAULT - eth0
  -o OUTPUT_PATH, --output=OUTPUT_PATH
                        Enter full path to save output file to. File extension
                        '.pcap'. DEFAULT - NO OUTPUT.
```
