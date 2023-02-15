import xml.etree.cElementTree as ET
import urllib2
import time
from datetime import datetime
import md5
import pysolr
import re
log_solr = pysolr.Solr('http://192.168.123.183:8983/solr/ExploitLog', timeout=60)
solr = pysolr.Solr('http://192.168.123.183:8983/solr/ExploitDB', timeout=60)
SIZE=500
NUM_ROWS=1000000
"""
url='https://cve.mitre.org/data/downloads/allitems-cvrf-year-'+str(2017)+'.xml'
r=urllib2.urlopen(url)
file_name='C:\Users\goranc\Desktop\NVD_CVEs\mitre-cve-'+url[56:60]+'.xml'
with open(file_name, 'wb') as fd:
    fd.write(r.read())
json={}
refjson={}
sve=[]
refs=[]

log_solr = pysolr.Solr('http://192.168.123.183:8983/solr/ExploitLog', timeout=60)
solr = pysolr.Solr('http://192.168.123.183:8983/solr/ExploitDB', timeout=60)
results = solr.search('*:*', **{"fl": "id, mitre_hash", 'rows': NUM_ROWS})
solrdic = {}
for i in results:
    solrdic[i['id']] = i['mitre_hash']
solr_list=[]
log_list=[{'type': 'info', 'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]
def fast_iter(context, func, *args, **kwargs):

    for event, elem in context:
        func(elem, event, *args, **kwargs)
        elem.clear()

    if len(solr_list)>0:
        solr.add(solr_list)
        log_solr.add(log_list)
    del context

def process_element(elem, event):
    global json, refjson, refs, solr, log_solr, solrdic, solr_list, log_list
    if(event=='start'):
        if elem.tag == '{http://www.icasi.org/CVRF/schema/vuln/1.1}Title':
            json['cve']=elem.text
            if json['cve']!=None:
                json['id']=int(json['cve'].split('-')[1]+json['cve'].split('-')[2])
        
        if (elem.tag=='{http://www.icasi.org/CVRF/schema/vuln/1.1}Note' and elem.attrib['Type']=='Description'):
            json['desc']=elem.text
        
        if (elem.tag=='{http://www.icasi.org/CVRF/schema/vuln/1.1}Note' and elem.attrib['Type']=='Other'):
            if(elem.attrib['Title']=='Published'):
                json['upload']=elem.text
            elif(elem.attrib['Title']=='Modified'):
                json['edited']=elem.text

        if (elem.tag=='{http://www.icasi.org/CVRF/schema/vuln/1.1}URL'):
            refjson['url']=elem.text
        
        if (elem.tag=='{http://www.icasi.org/CVRF/schema/vuln/1.1}Description'):
            refjson['refdesc']=elem.text
            
    if(event=='end'):
        if elem.tag == '{http://www.icasi.org/CVRF/schema/vuln/1.1}Title' and json['cve']==None:
            json['cve']=elem.text
            json['id']=int(json['cve'].split('-')[1]+json['cve'].split('-')[2])

        if (elem.tag=='{http://www.icasi.org/CVRF/schema/vuln/1.1}Note' and json['desc']==None):
            json['desc']=elem.text

        if (elem.tag=='{http://www.icasi.org/CVRF/schema/vuln/1.1}Note' and 'edited' in json):
            if(json['edited']==None):
                json['edited']=elem.text
                
        if (elem.tag=='{http://www.icasi.org/CVRF/schema/vuln/1.1}Note' and 'upload' in json):
            if(json['upload']==None):
                json['upload']=elem.text

        if (elem.tag=='{http://www.icasi.org/CVRF/schema/vuln/1.1}URL' and 'url' in refjson):
            if(refjson['url']==None):
                refjson['url']=elem.text
        
        if (elem.tag=='{http://www.icasi.org/CVRF/schema/vuln/1.1}Description' and 'refdesc' in refjson):
            if(refjson['refdesc']==None):
                refjson['refdesc']=elem.text
            
        
        if(elem.tag=='{http://www.icasi.org/CVRF/schema/vuln/1.1}Reference'):
            refs.append(refjson)
            refjson={}
            
        if(elem.tag=='{http://www.icasi.org/CVRF/schema/vuln/1.1}References'):
            json['refs']=refs
            refs=[]
            
        if(elem.tag=='{http://www.icasi.org/CVRF/schema/vuln/1.1}Vulnerability'):
            json['mitre_hash']=unicode(md5.new(str(json)).hexdigest(), 'utf-8')
            if(str(json['id']) in solrdic):
                if(json['mitre_hash']!=solrdic[str(json['id'])]):
                    solr_list.append(json)
                    log={}
                    log['id'] = json['id']
                    log['type'] = 'updated'
                    if('upload' in json):
                        log['upload'] = json['upload']
                    if('edited' in json):
                        log['edited'] = json['edited']
                    log_list.append(log)
            else:
                solr_list.append(json)
                log={}
                log['id'] = json['id']
                log['type'] = 'added'
                if('upload' in json):
                    log['upload'] = json['upload']
                if('edited' in json):
                    log['edited'] = json['edited']
                log_list.append(log)

            if(len(solr_list)>=SIZE):
                solr.add(solr_list)
                log_solr.add(log_list)
                solr_list=[]
                log_list=[{'type': 'info', 'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]
            json={}

start=time.time()
context = ET.iterparse('mitre-cve-2017.xml', events = ('start', 'end'))
fast_iter(context, process_element)
end=time.time()
print end-start
"""
def parse_XML(mitre_year):
    tree = ET.parse('mitre-cve-'+str(mitre_year)+'.xml')
    results = solr.search('*:*', **{"fl": "id, mitre_hash", 'rows': NUM_ROWS})
    solrdic = {}
    for i in results:
        solrdic[i['id']] = i['mitre_hash']
    solr_list=[]
    log_list=[{'type': 'info', 'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]
    for elem in tree.iter():
        if elem.tag=='{http://www.icasi.org/CVRF/schema/vuln/1.1}Vulnerability':
            dic = handle_vulnerabilities(elem)
            if(str(dic['id']) in solrdic):
                if(dic['mitre_hash']!=solrdic[str(dic['id'])]):
                    solr_list.append(dic)
                    log={}
                    log['id'] = dic['id']
                    log['type'] = 'updated'
                    if('upload' in dic):
                        log['upload'] = dic['upload']
                    if('edited' in dic):
                        log['edited'] = dic['edited']
                    log_list.append(log)
            else:
                solr_list.append(dic)
                log={}
                log['id'] = dic['id']
                log['type'] = 'added'
                if('upload' in dic):
                    log['upload'] = dic['upload']
                if('edited' in dic):
                    log['edited'] = dic['edited']
                log_list.append(log)

            if(len(solr_list)>=SIZE):
                solr.add(solr_list)
                log_solr.add(log_list)
                solr_list=[]
                log_list=[]
    if len(solr_list)>0:
        solr.add(solr_list)
        log_solr.add(log_list)

    del elem, results, solrdic, solr_list, log_list

def handle_vulnerabilities(elem):
    NAMESPACE='{http://www.icasi.org/CVRF/schema/vuln/1.1}'
    json={}
    refjson={}
    refs=[]
    for child in elem:
        if child.tag==NAMESPACE+'Title':
            json['cve']=child.text
            json['id']=child.text[4:8]+child.text[9:]
        if child.tag==NAMESPACE+'Notes':
            for note in child:
                if(note.attrib['Type']=='Description'):
                    json['desc']=note.text
                elif(note.attrib['Type']=='Other'):
                    if(note.attrib['Title']=='Published'):
                        json['upload']=note.text
                    elif(note.attrib['Title']=='Modified'):
                        json['edited']=note.text

        if child.tag==NAMESPACE+'References':
            for reference in child:
                for detail_reference in reference:
                    if detail_reference.tag==NAMESPACE+'URL':
                        refjson['url']=detail_reference.text

                    if detail_reference.tag==NAMESPACE+'Description':
                        refjson['refdesc']=detail_reference.text
                        refs.append(refjson)
                        refjson={}

    del child, note
    json['refs']=refs
    json['mitre_hash']=unicode(md5.new(str(json)).hexdigest(), 'utf-8')
    return json
    
def download_XML(mitre_year):
    url='https://cve.mitre.org/data/downloads/allitems-cvrf-year-'+str(mitre_year)+'.xml'
    r=urllib2.urlopen(url)
    file_name='C:\Users\goranc\Desktop\NVD_CVEs\mitre-cve-'+url[56:60]+'.xml'
    with open(file_name, 'wb') as fd:
        fd.write(r.read())

for i in range(1999, 2018):
    print i
    download_XML(i)
    parse_XML(i)
    
