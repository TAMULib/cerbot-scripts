#!/usr/bin/python3
import subprocess
import requests
import time
import sys
import os
import datetime
import shutil
import smtplib
from email.message import EmailMessage

# Variables
CERT_DIR = "/etc/certs" # Directory to export cert files to
POST_SCRIPTS_DIR = "/root/cert-scripts" # Directory containing executable .sh files which will be run after its respective cert is renewed. For example, test.com.sh will run after the certificate for test.com has been renewed.
CERT_OWNER = "root" # UNIX user to own the certificate files
CERT_GROUP = "root" # UNIX group to own the certificate files.
DOMAIN_LIST_PATH = "/root/domain_list.txt" # Path to TXT file containing a list of domains to generate a certificate for. 1 line = 1 certificate. To put multiple domains onto one certificate, put all the domains on one line seperated by commas (no spaces).
DOMAIN_SUFFIX = "example.com" # Used for sanity test to make sure the requested DNS record falls under our authority.
REPLACE_AFTER_SECONDS = 86400 * 10 # If the cert is set to expire within this many seconds, run the script. 86,400sec = 24hr
DELAY_SECONDS = 30 # Delay between making change to DNS and signaling certbot to verify the change

CONTACT_EMAIL = "alert_me@example.com" # E-mail address to send alerts to.
FROM_EMAIL = "donotreply@example.com" # "From" address for e-mail alerts.
SMTP_SERVER = "relay.example.com" # SMTP server to contact for email alerts.

CLOUDFLARE_ZONE_ID = ""
CLOUDFLARE_USER_EMAIL = ""
CLOUDFLARE_API_KEY = ""

# Helper Functions

# Uses openssl, subprocess.run line may need tweaking to run on Windows
def check_cert_expiration(filepath, seconds_until_expire):
    if not os.path.isfile(filepath):
        return True

    openssl_process = subprocess.run('openssl x509 -checkend ' + str(seconds_until_expire) + ' -noout -in ' + filepath + ' > /dev/null', shell=True)
    if openssl_process.returncode != 0:
        return True
    else:
        return False

# OS Agnostic. record_data and record_url needs to be tweaked to match the format of your DNS provider's API.
def set_acme_record(record_name, challenge):
    record_data = {
        "name": record_name,
        "content": challenge,
        "type": "TXT",
        "ttl": 300,
        "comment": "DNS Challenge Token for certbot",
        "proxied": False
    }
    record_headers = {
        "Content-Type": "application/json",
        "X-Auth-Email": CLOUDFLARE_USER_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API_KEY
    }
    record_url = "https://api.cloudflare.com/client/v4/zones/" + CLOUDFLARE_ZONE_ID + "/dns_records"
    print('POSTing challenge data to ' + record_name + ', data: ' + challenge)
    return requests.post(record_url, headers=record_headers, json=record_data)

def delete_acme_record(record_id):
    record_url = "https://api.cloudflare.com/client/v4/zones/" + CLOUDFLARE_ZONE_ID + "/dns_records/" + record_id
    record_headers = {
        "Content-Type": "application/json",
        "X-Auth-Email": CLOUDFLARE_USER_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API_KEY
    }
    return requests.delete(record_url, headers=record_headers)

# Script Start
list_file = open(DOMAIN_LIST_PATH, "r")
domain_list = list_file.readlines()
list_file.close()

success_list = []
failed_list = []

# Each line in the Domain List File gets its own certbot process.
# DNS-Provider Agnostic. The subprocess.Popen and subprocess.run lines may need tweaking to run on Windows. Lines using 'shutil' will likely need replacing to a Windows-equivalent library for managing files.
for domains_raw in domain_list:
    failed_flag = False
    record_list = []
    domains = domains_raw.strip()
    cert_id = domains.split(",")[0].replace("*.", "_.")
    CERT_PATH = CERT_DIR + "/" + cert_id + ".cer"
    KEY_PATH = CERT_DIR + "/" + cert_id + ".key"

    print('Checking if certificate located at ' + CERT_PATH + ' will expire in under ' + str(REPLACE_AFTER_SECONDS) + ' seconds...')
    if check_cert_expiration(CERT_PATH, REPLACE_AFTER_SECONDS):
        print('Certificate expiration detected, attempting renewal...')
        certbot_process = subprocess.Popen('certbot certonly --manual --force-renewal --preferred-challenges dns --agree-tos -d ' + domains + ' -m ' + CONTACT_EMAIL + ' --cert-name ' + cert_id, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, encoding='utf8', bufsize=1)

        last_line = ""
        record_name = ""
        while certbot_process.poll() is None:
            current_line = certbot_process.stdout.readline()
            if len(current_line.strip()) == 0:
                continue
            if '_acme-challenge' in current_line:
                record_name = current_line.strip().replace("Admin Toolbox: https://toolbox.googleapps.com/apps/dig/#TXT/", "")
                if record_name.endswith("."):
                    record_name = record_name[:-1]
            if 'with the following value:' in last_line:
                if not record_name.endswith(DOMAIN_SUFFIX):
                    print("ERROR: Record " + record_name + " does not fall under our " + DOMAIN_SUFFIX + " DNS authority!", file=sys.stderr)
                    failed_entry = [domains, record_name + " does not fall under our " + DOMAIN_SUFFIX + " DNS authority. Cannot create DNS record for ACME."]
                    failed_list.append(failed_entry)
                    failed_flag = True
                    certbot_process.terminate()
                    break
                status_code = set_acme_record(record_name, current_line.strip())
                if status_code < 200 or status_code > 299:
                    print('Cloudflare GET or PUT request returned with status code ' + str(status_code) + '!', file=sys.stderr)
                    failed_entry = [domains, "The GET or PUT request to Cloudflare returned with status code " + str(status_code)]
                    failed_list.append(failed_entry)
                    failed_flag = True
                    certbot_process.terminate()
                    break
                record_list.append(post_response.json()["result"]["id"])
                print('Cloudflare entry for _acme-challenge successfully updated. Waiting ' + str(DELAY_SECONDS) + ' to continue.')
                time.sleep(DELAY_SECONDS)
                certbot_process.stdin.write('\n')
            last_line = current_line

        if certbot_process.poll() == 0:
            print('Certificate renewal successful.')
            if os.path.isfile(CERT_PATH):
                print('Renaming previous certificate files.')
                TODAY = datetime.date.today()
                os.rename(CERT_PATH, CERT_PATH + '.old-' + str(TODAY))
                if os.path.isfile(KEY_PATH):
                    os.rename(KEY_PATH, KEY_PATH + '.old-' + str(TODAY))
        
            print('Copying certificate file to ' + CERT_PATH + '.')
            shutil.copyfile("/etc/letsencrypt/live/" + cert_id + "/fullchain.pem", CERT_PATH)
            shutil.copyfile("/etc/letsencrypt/live/" + cert_id + "/privkey.pem", KEY_PATH)
            shutil.chown(CERT_PATH, user=CERT_OWNER, group=CERT_GROUP)
            shutil.chown(KEY_PATH, user=CERT_OWNER, group=CERT_GROUP)
            print('Files copied successfully.')
            
            success_list.append(domains)
        else:
            if not failed_flag:
                print('Certbot process failed with exit code ' + str(certbot_process.poll()) + '!', file=sys.stderr)
                failed_entry = [domains, "Certbot process failed with exit code " + str(certbot_process.poll()) + ", check /var/log/letsencrypt"]
                failed_list.append(failed_entry)

        for rec in list(set(record_list)):
            del_ret = delete_acme_record(rec)
            if not bool(del_ret.json()["success"]) or del_ret < 200 or del_ret > 299:
                msg = EmailMessage()
                msg['Subject'] = "Error on Certbot Cleanup"
                msg['To'] = CONTACT_EMAIL
                msg['From'] = FROM_EMAIL
                msg.set_content("Unable to delete the leftover ACME records for " + rec + ", this will need to be deleted manually in Cloudflare. Status Code: " + str(del_ret))
                smtp_session = smtplib.SMTP(SMTP_SERVER)
                smtp_session.send_message(msg)
                smtp_session.quit()
    else:
        print('Certificate is NOT expiring within set time frame (' + str(REPLACE_AFTER_SECONDS) + ' sec), skipping entry.')

# Call Post-Scripts Based on Renewed Certs
# Should work on Windows, just replace ".sh" at the end of script_path with ".bat", ".py", ".ps1", etc
for entry in success_list:
    script_path = POST_SCRIPTS_DIR + "/" + entry.split(",")[0].replace("*.", "_.") + ".sh"
    if os.path.exists(script_path):
        subprocess.call(script_path)

# Send Alert Emails
# Should be completely OS and DNS Provider Agnostic.
msg = EmailMessage()
msg['From'] = FROM_EMAIL
msg['To'] = CONTACT_EMAIL
if len(success_list) > 0 and len(failed_list) == 0:
    msg['Subject'] = "Certbot Renewals Successful"
    content = """\
    <html>
      The following domains were successfully renewed:
      <ul>\n"""
    for entry in success_list:
        content = content + "        <li>" + entry + "</li>\n"
    content = content + "      </ul>\n\n        Alert Generated: " + str(datetime.datetime.now()) + "\n    </html>"
    msg.add_alternative(content, subtype='html')
    smtp_session = smtplib.SMTP(SMTP_SERVER)
    smtp_session.send_message(msg)
    smtp_session.quit()
elif len(success_list) > 0 and len(failed_list) > 0:
    msg['Subject'] = "Certbot Renewals With Errors"
    content = """\
    <html>
      The following domains were successfully renewed:
      <ul>\n"""
    for entry in success_list:
        content = content + "        <li>" + entry + "</li>\n"
    content = content + "      </ul>\n      The following domains failed to renew:\n      <ul>\n"
    for entry in failed_list:
        content = content + "        <li>" + entry[0] + "\n          <ul>\n            <li>" + entry[1] + "</li>\n          </ul>\n        </li>\n"
    content = content + "      </ul>\n\n        Alert Generated: " + str(datetime.datetime.now()) + "\n    </html>"
    msg.add_alternative(content, subtype='html')
    smtp_session = smtplib.SMTP(SMTP_SERVER)
    smtp_session.send_message(msg)
    smtp_session.quit()
elif len(success_list) == 0 and len(failed_list) > 0:
    msg['Subject'] = "Certbot Renewals Failed"
    content = """\
    <html>
      The following domains failed to renew:
      <ul>\n"""
    for entry in failed_list:
        content = content + "        <li>" + entry[0] + "\n          <ul>\n            <li>" + entry[1] + "</li>\n          </ul>\n        </li>\n"
    content = content + "      </ul>\n\n        Alert Generated: " + str(datetime.datetime.now()) + "\n    </html>"
    msg.add_alternative(content, subtype='html')
    smtp_session = smtplib.SMTP(SMTP_SERVER)
    smtp_session.send_message(msg)
    smtp_session.quit()
