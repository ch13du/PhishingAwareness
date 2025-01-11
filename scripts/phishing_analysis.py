import email
import re

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

if __name__ == "__main__":
    main()
