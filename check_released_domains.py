import re
import requests
import time
import sys

print ("[*] Checking <WiederFrei> Domain Names")
html_file="C:\\tmp\\(6) Wieder Frei (@wiederfrei) _ Twitter.html"

f = open(html_file, 'r', encoding="utf8")

html_string = ""

print("[*] Getting HTML")
for x in f:
  x.replace("\n","")
  html_string = html_string + x

ergebnis = []


print("[*] Checking Status")
for finding in re.findall(r'data-expanded-url="((http|https)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3})"', html_string):
    url = "www." + finding[0].replace("http://","")
    res = requests.get("http://urlmetriken.ch/" + url)
    print ("[*] Please Wait ¦", end="")
    for i in range(0, 10):
        print(".", end="")
        sys.stdout.flush()
        time.sleep(0.5)

    print("¦")
    print("bla")
    l = url + ";"
    if res.status_code == 200:
        print("[+] " + finding[0] + " - ", end="")
        pos = re.findall(r'\"para_sent_top\">.+rangiert auf Platz ([\d.\'\\]+) in Schweiz',
                         res.content.decode(res.encoding))
        views = re.findall(r'<td class=.wh_two.>([\d\'\\]+)<\/td>', res.content.decode(res.encoding))
        if pos:
            print(str(pos[0]), end="")
            l = l+ str(pos[0]) + ";"
        else:
            print ("Not Found")
            l = l + "--" + ";"


        if views:
            print(str(views[0]))
            l = l + str(views[0])
        else:

            l = l + "--"
    else:
        print("[X] " + finding[0] + " - ", end="")
        l = l + "--;--"
        print ("Not in URL Metrik " + res.url)
        if re.findall("removed",res.url):
            print("[!] WARNING - Removed in URL")

    ergebnis.append(l)

w = open("result.txt", "a")

for e in ergebnis:
    w.write(e)
    print(".", end="")

w.close()

# res = requests.get("http://urlmetriken.ch/www.google.com")
# print ("Status Google: " + str(res.status_code))
# pos = re.findall(r'\"para_sent_top\">.+rangiert auf Platz ([\d.\'\\]+) in Schweiz',res.content.decode(res.encoding))
# if pos:
#     print ("Position: " + str(pos[0]))
# views = re.findall(r'<td class=.wh_two.>([\d\'\\]+)<\/td>',res.content.decode(res.encoding))
# if views:
#     print ("Views: " + str(views[0]))
# else:
#     print ("View Error")
# res2 = requests.get("http://urlmetriken.ch/www.noroot.ch")
# print ("Status No Root: " + str(res2.status_code))


