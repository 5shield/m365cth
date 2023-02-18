# Microsoft 365 Cyber Threat Hunting Data Collector
This is a relatively simple script intended to rapidly collect USEFUL information that will aid in hunting for cyber threats in an M365 environment.

Data collected is as follows:
* Login data (success and failures) along with IP address information, user-agent, geolocation, operating system, and computer name
  * Note: The default date range is set to the last 90 days, and this script will automatically collect up to 50,000 records
  
* Mailbox rules (sometimes mailbox rules are used to hide Email communication particularly with BEC)

* Mailbox permissions (it's always good to know if someone in the environment has permission to access other mailboxes)

* Forwarding rules (sometimes used by cyber threat actors for espionage or maintaining / regaining mailbox access)

* MFA status (when trying identify a potential security incident, knowing whether or not MFA is enabled is valuable)

Happy Hunting!

c1ph04


  
