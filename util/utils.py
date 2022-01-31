import requests
from lxml import html
import xml.etree.ElementTree as treant
from termcolor import colored
import warnings

warnings.simplefilter("ignore")

def prepare_cpe(cpe):
 if containsNumber(cpe) == True:
   word=cpe.split(':')
   name=word[2]
   types=word[3]
   if len(word) >= 5:
    version=word[4]
    ret=name+" "+types+" "+version
    return ret
   return 0 
 return 0

def containsNumber(value):
 for character in value:
  if character.isdigit():
   return True
 return False

def risk_color(risk):
  if "LOW" in risk:
    return colored(risk,"green")
  if "MEDIUM" in risk:
    return colored(risk,"yellow")
  if "HIGH" in risk:
    return colored(risk,"red")
  if "CRITICAL" in risk:
    return colored(risk,"red",attrs=['blink'])

def banner():
    print (open('banner.txt','r').read())



def parser_response_csv(content,limit,csv_str):
    tree = html.fromstring(content)
    desc = tree.xpath("//*[contains(@data-testid, 'vuln-summary')]")
    cve = tree.xpath("//*[contains(@data-testid, 'vuln-detail-link')]")
    score = tree.xpath("//*[contains(@data-testid, 'vuln-cvss2-link')]")
    if len(desc) > 0:
        maxLimit = limit  if limit <= len(desc) else len(desc) - 1
        if limit > len(desc):
            maxLimit = len(desc)
        for i in range(0,maxLimit):
            url =("https://nvd.nist.gov/vuln/detail/"+cve[i].text)
            print(csv_str+str(cve[i].text)+"|"+url+"|"+str(score[i].text)+"|"+str(desc[i].text) )
    


def parser_response(content,limit):
    tree = html.fromstring(content)
    desc = tree.xpath("//*[contains(@data-testid, 'vuln-summary')]")
    cve = tree.xpath("//*[contains(@data-testid, 'vuln-detail-link')]")
    score = tree.xpath("//*[contains(@data-testid, 'vuln-cvss2-link')]")
    if len(desc) > 0:
        maxLimit = limit  if limit <= len(desc) else len(desc) - 1
        if limit > len(desc):
            maxLimit = len(desc)
        for i in range(0,maxLimit):
            print ("\t\t" + colored(desc[i].text,"magenta") )
            url =("https://nvd.nist.gov/vuln/detail/"+cve[i].text)
            print ("\t\t" + colored(url,"green") )
            print ("\t\t" + risk_color(score[i].text +"\n") )
    print

def getCPE(cpe):
    cpe = prepare_cpe(cpe)
    if cpe != 0:
        url = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query="+cpe+"&search_type=all&isCpeNameSearch=false"
        r = requests.get(url)
        if r.status_code == 200:
            return r.content
        else:
            return False
    return False

def fix_cpe_str(str):
    return str.replace('-',':')

def parser(filenmap,limit,type_output):
    print (colored("\n::::: Vision v0.3 - nmap NVD's cpe correlation to CVE \n","yellow"))
    tree = treant.parse(filenmap)
    root = tree.getroot()
    for child in root.findall('host'):
        for k in child.findall('address'):
            host = k.attrib['addr']
            for y in child.findall('ports/port'):
                current_port = y.attrib['portid']
                for z in y.findall('service/cpe'):
                    if len(z.text) > 4:
                        cpe = fix_cpe_str(z.text)
                        result = getCPE(cpe)
                        if result:
                            if("csv" in type_output):
                                string_csv=str(host)+"|"+str(current_port)+"|"+str(cpe)+"|"
                                parser_response_csv(result,limit,string_csv)
                            else:
                                print (colored("Host: " + host,"cyan"))
                                print (colored("Port: " + current_port,"cyan"))
                                print (colored("cpe: " + cpe,"cyan"))
                                parser_response(result,limit)

