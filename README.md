# web_vuln_scanner

COMPANY: CODETECH IT SOLUTIONS
NAME:Ahammed Falah F M
Intern ID:CT04DZ2299
DOMAIN: Cyber Security And Ethical Hacking 
DURATION: 4 WEEKS 
MENTOR: NEELA SANTOSH

# Web Application Vulnerability Scanner – Project Overview
In today's digital landscape, the security of web applications is more critical than ever. With the increasing number of cyber-attacks targeting websites, it is essential for developers and security professionals to proactively identify and patch vulnerabilities before malicious actors can exploit them. This project introduces a lightweight, Python-based Web Application Vulnerability Scanner designed to detect two of the most common security issues in web applications: SQL Injection (SQLi) and Cross-Site Scripting (XSS).

# Purpose and Scope
The goal of this tool is to provide a simple, yet effective scanner that can help developers, testers, and ethical hackers identify potential security flaws in web applications. It focuses specifically on SQL Injection and XSS attacks, both of which are consistently listed in the OWASP Top 10 vulnerabilities. This tool is intended for educational use and security testing on applications where the user has proper authorization.

# How It Works
The scanner is built using two popular Python libraries:

requests: For sending HTTP requests to target URLs.

BeautifulSoup (from bs4): For parsing and analyzing HTML content, especially forms.

When a user inputs a target URL, the scanner performs two types of tests:

# SQL Injection Test:
The scanner appends common SQL injection payloads (e.g., ' OR '1'='1) to query parameters and sends requests to the server. If the server response includes the payload or shows behavior indicative of a successful SQLi (such as database errors or unexpected content), the scanner flags the URL as potentially vulnerable.

# XSS Test:
The scanner uses BeautifulSoup to locate all forms on the web page. It then injects simple JavaScript payloads (like <script>alert('XSS')</script>) into each form input and observes the server's response. If the payload is reflected in the response HTML, it's an indicator of a reflected XSS vulnerability.

# Features
Easy-to-use CLI interface.

Lightweight and fast — no external tools or complex setups.

Easily extendable with additional payloads or modules.

Detects potential vulnerabilities without performing destructive actions.

