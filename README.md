# Analyzing DNS Log Files Using Splunk SIEM

## Introduction
DNS (Domain Name System) logs are crucial for understanding network activity and identifying potential security threats. Splunk SIEM (Security Information and Event Management) provides powerful capabilities for analyzing DNS logs and detecting anomalies or malicious activities.

## Prerequisites
Before analyzing DNS logs in Splunk, ensure the following:
- A Splunk instance is installed and configured.
- DNS log data sources are configured to forward logs to Splunk.

## Steps to Upload Sample DNS Log Files to Splunk SIEM

### 1. Prepare Sample DNS Log Files
- Obtain a sample [DNS log file](https://www.secrepo.com/maccdc2012/dns.log.gz) in a suitable format (e.g., text files).
- Ensure the log files contain relevant DNS events, including source IP, destination IP, domain name, query type, response code, etc.
- Save the sample log files in a directory accessible by the Splunk instance.

### 2. Upload Log Files to Splunk
- Log in to the Splunk web interface.
- Navigate to **Settings** > **Add Data**.
- Select **Upload** as the data input method.

### 3. Choose File
- Click on **Select File** and choose the sample DNS log file you prepared earlier.

### 4. Set Source Type
- In the **Set Source Type** section, specify the source type for the uploaded log file.
- Choose the appropriate source type for DNS logs (`dns`).

### 5. Review Settings
- Review other settings such as index, host, and sourcetype.
- Set the **index** to `dns_logs_index` to store the DNS log data in a dedicated index for better organization.
- Ensure the settings are configured correctly to match the sample DNS log file.

### 6. Click Upload
- Once all settings are configured, click on the **Review** button.
- Review the settings one final time to ensure accuracy.
- Click **Submit** to upload the sample DNS log file to Splunk.

### 7. Verify Upload
- After uploading, navigate to the search bar in the Splunk interface.
- Run a search query to verify that the uploaded DNS events are visible.

  ```spl
  index=dns_logs_index sourcetype=dns
## Field Extraction and Renaming

Before proceeding with the analysis, I extracted and renamed the following fields from the raw DNS log data for easier analysis:

- **timestamp**: The timestamp of the DNS log entry.
- **src_ip**: The source IP address making the DNS request.
- **src_port**: The source port used in the request.
- **dst_ip**: The destination IP address of the DNS server.
- **dst_port**: The destination port used by the DNS server (usually 53).
- **protocol**: The protocol used in the DNS query, typically `udp`.
- **request_size**: The size of the DNS request in bytes.
- **fqdn**: The Fully Qualified Domain Name being queried.
- **record**: The DNS record type (e.g., A, PTR, NXDOMAIN).

These field extractions allow for more efficient analysis of DNS log events.

## Steps to Analyze DNS Log Files in Splunk SIEM

### 1. Search for DNS Events
- Open the Splunk interface and navigate to the search bar.
- Enter the following search query to retrieve DNS events:
  ```spl
  index=dns_logs_index sourcetype=dns
### 2. Analyze Top DNS Queries by Frequency
  - Find the most frequently queried domains:
   ```spl
   index=dns_logs_index sourcetype=dns | stats count by fqdn | sort - count | head 10
```
### 3. Analyze Top Source IPs Making DNS Queries
  - Find the most frequently queried domains:
   ```spl
   index=dns_logs_index sourcetype=dns | stats count by src_ip | sort - count | head 10
   ```
### 4. Analyze Top DNS Queries by Frequency
  - Find the most frequently queried domains:
   ```spl
   index=dns_logs_index sourcetype=dns | stats count by fqdn | sort - count | head 10
   ```
### 5. Monitor DNS Traffic by Protocol
  - Find the most frequently queried domains:
   ```spl
   index=dns_logs_index sourcetype=dns | stats count by protocol
   ```
### 6. Identify Large DNS Requests (Potential DNS Tunneling)
- Check for unusually large DNS requests that might indicate data exfiltration via DNS tunneling:
   ```spl
   index=dns_logs_index sourcetype=dns | eval fqdn_length = len(fqdn) | where fqdn_length > 50 | stats count by fqdn, src_ip
  ```
### 7. Tracking DNS Activity from Specific Hosts
- Track DNS requests from specific IP addresses, like critical servers or suspected devices, to monitor abnormal activity:
   ```spl
   index=dns_logs_index sourcetype=dns src_ip="192.168.202.83" | stats count by fqdn, dst_ip
   ```
### 8. DNS Query Size Analysis
- You can analyze the request_size to identify unusually large or small DNS queries, which might indicate data exfiltration (DNS tunneling) or attacks.
   ```spl
   index=dns_logs_index sourcetype=dns | stats avg(request_size), max(request_size), min(request_size) by src_ip
   ```
