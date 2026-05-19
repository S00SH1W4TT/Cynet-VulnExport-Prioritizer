# Cynet-VulnExport-Prioritizer
Python script that prioritizes and groups findings from Cynet. This compares the findings against current KEV &amp; EPSS database data as well. 

#Pre-requisites (databases): 
You need to download the latest KEV & EPSS database files. This is manual for now. 

Where to get KEV database file: 
https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Where to get EPSS database file: 
https://www.first.org/epss/data_stats

# Usage

In terminal: 
python3 VA_Summary.py "input_file_name" "output_file_name" --kev known_exploited_vulnerabilities.csv --epss-csv epss_scores.csv

Thats it! 
