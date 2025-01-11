import email
import re
import requests
import base64
import time

VIRUSTOTAL_API_KEY = "ff2c8787e15432aef5a3d1618f13b629807ed63f2aca379b19a4c19ca50109b1"  # Replace with your VirusTotal API key

def parse_email_headers(email_path = "/home/darkrabbai/PhishingAwareness/phishing_email_sample.eml"):
    with open(email_path, 'r') as f:
        msg = email.message_from_file(f)
    headers = dict(msg.items())
    return headers

def extract_links(email_path = "/home/darkrabbai/PhishingAwareness/phishing_email_sample.eml"
):
    with open(email_path, 'r') as f:
        msg = email.message_from_file(f)
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode()
                links = re.findall(r'http[s]?://\S+', body)
                return links
    else:
        body = msg.get_payload(decode=True).decode()
        links = re.findall(r'http[s]?://\S+', body)
        return links

def check_link_virustotal(link = "https://www.virustotal.com/api/v3/urls"):
    """
    Sends a link to VirusTotal for analysis and returns the report.
    """
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
# URL needs to be base64 encoded before sending to VirusTotal
    response = requests.post(url, headers=headers, data={"url": link})
    if response.status_code == 200:
        json_response = response.json()
        analysis_id = json_response.get("data", {}).get("id", "")
        
        # Use the analysis ID to retrieve the report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(3):  # Retry 5 times
                time.sleep(5)  # Wait 10 seconds between retries
        report_response = requests.get(report_url, headers=headers)
        
        if report_response.status_code == 200:
            report_data = report_response.json()
            stats = report_data.get("data", {}).get("attributes", {}).get("stats", {})
            return stats
        else:
            return f"Failed to retrieve report: {report_response.status_code}"
    else:
        return f"Failed to send link: {response.status_code}"

def main():
    email_path = "../phishing_email_sample.eml"
    headers = parse_email_headers(email_path = "/home/darkrabbai/PhishingAwareness/phishing_email_sample.eml"
)
    print("Parsed Headers:")
    for key, value in headers.items():
        print(f"{key}: {value}")
    
    links = extract_links(email_path = "/home/darkrabbai/PhishingAwareness/phishing_email_sample.eml"
)
    print("\nExtracted Links:")
    for link in links:
        print(link)
        print("Checking With virustotal...")
        stats = check_link_virustotal(link)
        print(f"VirusTotal Stats: {stats}")

if __name__ == "__main__":
    main()
