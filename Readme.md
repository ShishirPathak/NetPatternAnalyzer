# This repository was created as a requirement of CIS 542 (Fall 2023); at UMass Dartmouth.

# NetPatternAnalyzer

NetPatternAnalyzer, a packet sniffer tool, allows you to analyze network traffic from PCAP files. 
It is a python utility that takes the network trace (pcap/pcapng) and generates a heatmap which shows the amount of 
data transfer between the endpoints.

## Requirements

- Python 3.9.6
- scapy
- seaborn
- pandas
- matplotlib

## Installation

1. Clone the repository:

   git clone https://github.com/ShishirPathak/NetPatternAnalyzer.git

2. Navigate to the project directory:

   cd NetPatternAnalyzer

3. Install the required dependencies:

   pip install -r requirements.txt

4. Run the Program

   python3 NetPatternAnalyzer.py

