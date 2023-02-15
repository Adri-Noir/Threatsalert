from lxml import etree

for event, element in etree.iterparse('C:\Users\goranc\Desktop\NVD_CVEs\mitre-cve-2017.xml', events=("start", "end")):
  if element.tag == 'Vulnerability' and event == 'end':
    for child in list(element):
        print child.text
  element.clear()
