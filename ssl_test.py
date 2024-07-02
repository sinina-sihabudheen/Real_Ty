import ssl
import certifi
import urllib.request

def verify_ssl_cert():
    context = ssl.create_default_context(cafile=certifi.where())
    url = 'https://www.google.com'  # Replace with any HTTPS URL to test
    try:
        response = urllib.request.urlopen(url, context=context)
        print(f"SSL certificate verified successfully for {url}")
    except Exception as e:
        print(f"SSL certificate verification failed: {e}")

if __name__ == "__main__":
    verify_ssl_cert()
