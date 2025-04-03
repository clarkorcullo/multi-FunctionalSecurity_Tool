# multi-FunctionalSecurity_Tool


User Manual: Multi-Function Security Tool



1. Introduction: What is this Tool?

Welcome to the Multi-Function Security Tool! Think of this tool like a basic check-up kit for computers and websites, helping you perform some simple security-related tests.

Purpose: To run common checks like seeing which "doors" (ports) are open on a computer, testing common passwords, or looking for basic website vulnerabilities.
Who is it for? Anyone interested in learning basic security concepts or performing authorized checks on their own systems or networks.

⚠️ EXTREMELY IMPORTANT WARNING ⚠️

Use Responsibly: This tool performs actions that can be seen as intrusive or even illegal if used on computers or networks you do not own or do not have explicit, written permission to test.
Permission is Key: ALWAYS get permission before running scans (like Port Scan, Brute Force SSH, SQL Injection, Network Scan, Web App Scan) on any system or website that isn't yours. Unauthorized scanning is against the law in many places.
Educational Use: This tool is primarily for educational purposes on your own equipment or in controlled environments where you have permission.
Not a Replacement for Professionals: The checks performed are basic. This tool does not replace a professional security assessment.





2. Getting Started

Launching the tool is usually simple:

If you have an icon, double-click it.
If you have the script file (.py), you might need to run it using Python (instructions would be provided separately if needed).

3. Understanding the Interface

The tool has two main sections:

Left Side (Controls):

Input Box: This is where you type the target information. The label above it tells you what kind of information is needed (like an IP address, website URL, or a password for checking).
Buttons: Below the input box are buttons, arranged in rows of three. Each button performs a specific security check or action.
Toggle Theme Button: At the bottom of the buttons, this lets you switch between a light (Day) and dark (Night) look for the tool.

Right Side (Results):

Results Box: This large area shows the output and results of the actions you perform by clicking the buttons. Text might appear in different colors:
Green: Often indicates success or something found (like an open port or strong password).
Red/Orange: Often indicates failure, a potential problem, or a weak password.
Blue/Gray: Often indicates informational messages or that a scan was stopped.



4. How to Use Each Feature (Buttons)

Here's what each button does and what you need to enter:

Scan Ports:

What it does: Checks a target computer to see if common network "doors" (ports) are open. Open ports can sometimes be used by attackers.
What to enter: An IP address (e.g., 192.168.1.1) or a domain name (e.g., google.com).
Results: Shows a list of common ports that are found to be open.

Brute Force SSH:

What it does: Tries a small list of very common usernames and passwords to see if it can log into a specific service (SSH) on a computer. This shows if very weak, default credentials are being used.
What to enter: An IP address (e.g., 192.168.1.100). Domain names won't work here.
Results: Will show "Success!" if it finds a match, or list "Failed" attempts.

⚠️ Warning: ONLY use this on computers you own and have set up for testing, or with explicit    permission. Trying this on other systems is illegal.

SQL Injection Scan:

What it does: Performs a very basic check on a website URL to see if it might be vulnerable to a common web attack called SQL Injection.
What to enter: A full website URL (e.g., http://example.com/page?id=1 or just http://example.com).
Results: Might show a message if it detects hints of a vulnerability based on common error messages.
Note: This is a very basic check and might miss vulnerabilities or give false alarms.

Privilege Escalation:

What it does: Looks for programs running on your own computer with high privileges (like "root" on Linux/Mac or "SYSTEM" on Windows) that aren't standard system processes. This is a very basic check.
What to enter: Nothing. Just click the button. It checks the computer the tool is running on.
Results: Lists any potentially suspicious processes found.

Network Scanner:

What it does: Tries to find other active computers, phones, printers, etc., that are currently connected to your same local network (like your home Wi-Fi).
What to enter: Nothing. Just click the button.
Results: Shows a list of IP addresses and unique hardware (MAC) addresses for devices it finds.
Note: This scan might require Administrator/Root privileges to run correctly on your computer.

Vuln Scanner:

What it does: (Placeholder) This feature currently only gives general hints about things to check based on which common ports were found open by the "Scan Ports" function.
What to enter: An IP address or domain name (ideally after running "Scan Ports").
Results: Provides suggestions for common security checks related to open ports.
⚠️ Warning: This is NOT a real vulnerability scan. It doesn't confirm any actual weaknesses.





Password Strength:

What it does: Checks if the text you enter in the input box meets common recommendations for a strong password (length, uppercase, lowercase, number, special character).
What to enter: The password you want to check.
Results: Will tell you if the password seems "Strong" or list the reasons why it's considered "Weak".

Web App Scanner:

What it does: (Placeholder) Performs very basic checks on a website, like looking for missing security information in its headers.
What to enter: A full website URL (e.g., http://example.com).
Results: Lists any basic issues found (like missing headers).
⚠️ Warning: This is NOT a comprehensive web security scan.

Export Results:

What it does: Lets you save the text currently shown in the Results Box to a file on your computer.
How to use: Click the button, choose a location and filename, and click "Save". You can usually save as a .txt (text) or .csv (spreadsheet) file.

Stop Scanning:

What it does: Attempts to stop any scans that are currently running (like Port Scan, Network Scan, Brute Force, SQLi).
How to use: Click the button if a scan is taking too long or you want to cancel it. It will ask you to confirm. Note: It might take a moment for the scan to fully stop.


Clear Results:

What it does: Erases all the text from the Results Box.
How to use: Click this button to get a clean slate.

Help:

What it does: Shows this user manual information in a separate window.

5. Important Reminders

Permissions are MANDATORY: Never scan systems you don't have permission for.
Basic Checks Only: This tool performs introductory-level checks. Real security requires more advanced tools and knowledge.
Potential for Errors: Network conditions or target system configurations can sometimes cause errors or incomplete results.
Use Safely: Be mindful of the potential impact of your scans.