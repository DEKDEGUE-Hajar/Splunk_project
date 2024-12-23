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
  ![2](https://github.com/user-attachments/assets/5e19624c-e1f0-4598-a91e-5e0c99a22e1f)

### 3. Choose File
- Click on **Select File** and choose the sample DNS log file you prepared earlier.
![3](https://github.com/user-attachments/assets/294ad308-a092-46f5-98a4-6fe75ae19da5)

### 4. Set Source Type
- In the **Set Source Type** section, specify the source type for the uploaded log file.
- Choose the appropriate source type for DNS logs (`dns`).

  ![5](https://github.com/user-attachments/assets/a671ae98-8822-43f3-8fa2-cace90150483)


### 5. set the index
- Set the **index** to `dns_logs_index` to store the DNS log data in a dedicated index for better organization.
- Ensure the settings are configured correctly to match the sample DNS log file.

  ![6](https://github.com/user-attachments/assets/3d047463-16d6-4fe9-9858-c4af30e0384d)


### 6. Click Upload
- Once all settings are configured, click on the **Review** button.
- Review the settings one final time to ensure accuracy.
- Click **Submit** to upload the sample DNS log file to Splunk.
  
![7](https://github.com/user-attachments/assets/b74267d0-e8ee-4a7e-9b43-4ba4ad0b1bab)

### 7. Verify Upload
- After uploading, navigate to the search bar in the Splunk interface.
- Run a search query to verify that the uploaded DNS events are visible.

  ```spl
  index=dns_logs_index sourcetype=dns

<img width="956" alt="image" src="https://github.com/user-attachments/assets/663de3df-d5d5-469a-937a-3df1d482e558" />

### 8. Field Extraction and Renaming

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

![9](https://github.com/user-attachments/assets/223accec-ff5c-45eb-ab42-75dc2d4921ea)

These field extractions allow for more efficient analysis of DNS log events.

![10](https://github.com/user-attachments/assets/43617ca7-df84-4aa2-a8b1-72a13bd818f7)

## Steps to Analyze DNS Log Files in Splunk SIEM

### 1. Search for DNS Events
- Open the Splunk interface and navigate to the search bar.
- Enter the following search query to retrieve DNS events:
  ```spl
  index=dns_logs_index sourcetype=dns
  ```
  ![1-req](https://github.com/user-attachments/assets/09bddbae-1b8a-462a-91cd-5027f3757be2)

### 2. Analyze Top DNS Queries by Frequency
  - Find the most frequently queried domains:
   ```spl
   index=dns_logs_index sourcetype=dns | stats count by fqdn | sort - count | head 10
   ```
![2-req](https://github.com/user-attachments/assets/8bb0a921-9dd7-43a0-b8f5-acee228bda06)

![2-vis](https://github.com/user-attachments/assets/3797dd42-9ab9-47b8-8fe2-64f0b19aa71a)

### 3. Analyze Top Source IPs Making DNS Queries
  - Find the most frequently queried domains:
   ```spl
   index=dns_logs_index sourcetype=dns | stats count by src_ip | sort - count | head 10
   ```
![3-req](https://github.com/user-attachments/assets/ccef2942-9512-4340-bcc2-99298b6c324d)
![3-vis](https://github.com/user-attachments/assets/5a6969d0-5d4b-4135-a990-b7df695f8b4b)

### 4. Monitor DNS Traffic by Protocol
  - Find the most frequently queried domains:
   ```spl
   index=dns_logs_index sourcetype=dns | stats count by protocol
   ```
![4-req](https://github.com/user-attachments/assets/9ec3c614-7d62-4cfd-8162-74a1855a08b3)
![4-vis](https://github.com/user-attachments/assets/abc5c5f8-856d-4eb5-975f-3c557a7c85b9)

### 5. Identify Large DNS Requests (Potential DNS Tunneling)
- Check for unusually large DNS requests that might indicate data exfiltration via DNS tunneling:
   ```spl
   index=dns_logs_index sourcetype=dns | eval fqdn_length = len(fqdn) | where fqdn_length > 50 | stats count by fqdn, src_ip
  ```
![5-req](https://github.com/user-attachments/assets/5815ef97-daea-4ce9-a9ef-320d4e7cd9c1)

### 6. Tracking DNS Activity from Specific Hosts
- Track DNS requests from specific IP addresses, like critical servers or suspected devices, to monitor abnormal activity:
   ```spl
   index=dns_logs_index sourcetype=dns src_ip="192.168.202.83" | stats count by fqdn, dst_ip
   ```
   ![6-req](https://github.com/user-attachments/assets/8521dd3c-9ba2-4f2a-89bf-c07493e638cb)

### 7. DNS Query Size Analysis
- You can analyze the request_size to identify unusually large or small DNS queries, which might indicate data exfiltration (DNS tunneling) or attacks.
   ```spl
   index=dns_logs_index sourcetype=dns | stats avg(request_size), max(request_size), min(request_size) by src_ip
   ```
   ![7-req](https://github.com/user-attachments/assets/72f9aff8-0422-45b5-b717-c543eca4b877)

## Conclusion
Analyzing DNS log files using Splunk SIEM enables security professionals to detect and respond to potential security incidents effectively. By understanding DNS activity and identifying anomalies, organizations can enhance their overall security posture and protect against various cyber threats.


