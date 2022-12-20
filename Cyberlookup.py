import webbrowser
import re


def is_valid_ip(ip):
    # Regex to check if the input is a valid public IP address
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return bool(re.match(pattern, ip))


def is_valid_url(url):
    # Regex to check if the input is a valid URL
    pattern = r"^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w.-]+)+[\w\-._~:/?#[\]@!$&'()*+,;=.]+$"
    return bool(re.match(pattern, url))


def is_valid_mac(mac):
    # Regex to check if the input is a valid MAC address
    pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    return bool(re.match(pattern, mac))


counter = 0
while True:
    print("Please choose one of the following options:")
    print("1." + " IP address lookup tools")
    print("2." + " Threat attribution tools")
    print("3." + " Website scanners")
    print("4." + " IP Fraud Search and Blacklist Checkers")
    print("5." + " Threat and Vulnerability Research")
    print("6." + " User agent parsers - Sources used to parse HTTP user agent string")
    print("7." + " MAC Address lookup tools")
    print("8." + " Commonly used IP sites used to make Reports ")
    print("0." + " to exit ")
    print(" " + ">>> ", end="")

    choice = input()

    if choice == "1":
        ip = input("Please enter a valid public IP address: ")
        if is_valid_ip(ip):
            # Open the websites in separate tabs
            webbrowser.open_new_tab("https://ip2location.com/demo?ip=" + ip)
            webbrowser.open_new_tab("https://search.censys.io/hosts/" + ip)
            webbrowser.open_new_tab("https://www.shodan.io/host/" + ip)
        else:
            print("Invalid IP address try again")

    elif choice == "2":
        ip = input("Please enter a valid public IP address: ")
        if is_valid_ip(ip):
            # Open the websites in separate tabs
            webbrowser.open_new_tab("https://otx.alienvault.com/indicator/ip/" + ip)
            webbrowser.open_new_tab("https://www.virustotal.com/gui/ip-address/" + ip)
            webbrowser.open_new_tab("https://metadefender.opswat.com/search?search=")
            print("Manually enter IP")
            webbrowser.open_new_tab("https://www.abuseipdb.com/check/" + ip)
            webbrowser.open_new_tab("https://exchange.xforce.ibmcloud.com/ip/" + ip)
            webbrowser.open_new_tab("https://community.riskiq.com/research")
            print("Singh in and Manually enter IP")
            webbrowser.open_new_tab("https://pulsedive.com/search?q=" + ip)
        else:
            print("Invalid IP address")

    elif choice == "3":
        url = input("Please enter a valid URL: ")
        if is_valid_url(url):
            # Open the websites in separate tabs
            webbrowser.open_new_tab("https://urlscan.io/search/#" + url)
        else:
            print("Invalid URL")

    elif choice == "4":
        ip = input("Please enter a valid public IP address: ")
        if is_valid_ip(ip):
            # Open the websites in separate tabs
            webbrowser.open_new_tab("https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a" + ip + "&run=toolpage")
            webbrowser.open_new_tab("https://scamalytics.com/ip/" + ip)
            webbrowser.open_new_tab("https://whatismyipaddress.com/blacklist-check?ip=" + ip)
            webbrowser.open_new_tab("https://threatfox.abuse.ch/browse.php?search=" + ip)

        else:
            print("Invalid IP address")

    elif choice == "5":
        ip = input("Please enter a valid public IP address: ")
        if is_valid_ip(ip):
            # Open the websites in separate tabs
            webbrowser.open_new_tab("https://www.onyphe.io/search/?query=" + ip)
            webbrowser.open_new_tab("https://vulners.com/search?query=" + ip)
            webbrowser.open_new_tab("https://packetstormsecurity.com/")

        else:
            print("Invalid IP address try again")

    elif choice == "6":
        print("Opening websites...")
        # Open the website in tab
        webbrowser.open_new_tab("https://developers.whatismybrowser.com/useragents/parse/#parse-useragent")

    elif choice == "7":
        mac_address = input("Enter a valid MAC address: ")
        if is_valid_mac(mac_address):

            # Open the specified websites in new tabs
            webbrowser.open_new_tab("https://dnschecker.org/mac-lookup.php?query=" + mac_address)
            webbrowser.open_new_tab("https://macvendors.com/search/")
        else:
            print("Invalid MAC address, try again")

    elif choice == "8":
        ip = input("Please enter a valid public IP address: ")
        if is_valid_ip(ip):
            # Open the websites in separate tabs
            webbrowser.open_new_tab("https://ip2location.com/demo?ip=" + ip)
            webbrowser.open_new_tab("https://scamalytics.com/ip/" + ip)
            webbrowser.open_new_tab("https://www.virustotal.com/gui/ip-address/" + ip)
            webbrowser.open_new_tab("https://metadefender.opswat.com/")
            webbrowser.open_new_tab("https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a" + ip + "&run=toolpage")
            webbrowser.open_new_tab("https://otx.alienvault.com/indicator/ip/" + ip)

        else:
            print('Invalid IP address try again ')
    elif choice == "0":
        break
    else:
        counter += 1
