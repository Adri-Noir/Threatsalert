import concurrent.futures
import urllib2
import time
import gzip
import StringIO
start=time.time()
urls = []


    
for i in range(2002,2018):
    #urls.append('https://cve.mitre.org/data/downloads/allitems-cvrf-year-'+str(i)+'.xml')
    urls.append('https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-'+str(i)+'.json.gz')

def download_mitre(url):
    r=urllib2.urlopen(url)
    file_name='C:\Users\goranc\Desktop\NVD_CVEs\mitre-cve-'+url[56:60]+'.xml'
    with open(file_name, 'wb') as f:
        f.write(r.read())

def download_nvd(url):
    request = urllib2.Request(url)
    request.add_header('Accept-encoding', 'gzip')
    opener = urllib2.build_opener()
    f = opener.open(request)
    compresseddata = f.read()
    compressedstream = StringIO.StringIO(compresseddata)
    gzipper = gzip.GzipFile(fileobj=compressedstream)
    data = gzipper.read()
    file_name='nvd-cve-'+url[58:62]+'.json'
    
    print url
    with open(file_name, 'wb') as f:
        f.write(data)

with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
    executor.map(download_nvd, urls)

end=time.time()
print end-start
