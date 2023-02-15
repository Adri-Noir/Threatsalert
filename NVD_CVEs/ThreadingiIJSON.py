import ijson
import time
import concurrent.futures
from xml.sax.handler import ContentHandler
from xml.sax import make_parser
start=time.time()
godine=[]
for i in range(1999, 2018):
    godine.append(i)

def parse_JSON(nvd_year):
    print 'parsing JSON'
    all_cves={}
    dic={'software_names': []}
    app_name=''
    name='nvd-cve-'+str(nvd_year)+'.json'
    json = ijson.parse(open(name, 'r'))
    for prefix, event, value in json:
        if(prefix=='CVE_Items.item.CVE_data_meta.CVE_ID' and event=='string'):
            dic['cve']=str(value)

        if(prefix=='CVE_Items.item.CVE_affects.CVE_vendor.CVE_vendor_data.item.CVE_vendor_name' and event=='string'):
            vendor_name=str(value)

        if(prefix=='CVE_Items.item.CVE_affects.CVE_vendor.CVE_vendor_data.item.CVE_product.CVE_product_data.item.CVE_product_name' and event=='string'):
            app_name=str(value)

        if(prefix=='CVE_Items.item.CVE_affects.CVE_vendor.CVE_vendor_data.item.CVE_product.CVE_product_data.item.CVE_version.CVE_version_data.item.CVE_version_value' and event=='string'):
            if(value=='-' or value=='*'):
                dic['software_names'].append(vendor_name+'_'+app_name)
            else:
                dic['software_names'].append(vendor_name+'_'+app_name+'_'+value)

        if(prefix=='CVE_Items.item.CVE_impact.CVE_impact_cvssv2.bm.score' and event=='string'):
            dic['cvssv2_score']=value

        if(prefix=='CVE_Items.item.CVE_impact.CVE_impact_cvssv3.bm.score' and event=='string'):
            dic['cvssv3_score']=value
            
        if(prefix=='CVE_Items.item' and event=='end_map'):
            all_cves[dic['cve']]=dic
            dic={'software_names': []}

class ParseXML(ContentHandler):

    def __init__(self):
        self.json = {'cve':'','desc':'', 'upload':'','edited':''}
        self.all_cves=[]
        self.refs=[]
        self.refsjson={'url':'', 'refdesc':''}
        self.is_title=False
        self.is_desc = False
        self.is_published = False
        self.is_modified = False
        self.is_url = False
        self.is_description=False

    def startElement(self, name, attrs):
        if name == 'Title':
            self.is_title=True
            
        if (name=='Note' and attrs.get('Type')=='Description'):
            self.is_desc = True
        
        if (name=='Note' and attrs.get('Type')=='Other'):
            if(attrs.get('Title')=='Published'):
                self.is_published = True
            elif(attrs.get('Title')=='Modified'):
                self.is_modified = True

        if (name=='URL'):
            self.is_url=True
        
        if (name=='Description'):
            self.is_description=True

    def endElement(self, name):
        if(name=='Title'):
            self.is_title=False

        if(name=='Note'):
            self.is_desc=False
            self.is_published=False
            self.is_modified=False

        if(name=='URL'):
            self.is_url=False

        if(name=='Description'):
            self.is_description=False
        
        if(name=='Reference'):
            self.refs.append(self.refsjson)
            self.refsjson={'url':'', 'refdesc':''}

        if(name=='Vulnerability'):
            self.json['id']=int(self.json['cve'].split('-')[1]+self.json['cve'].split('-')[2])
            if(self.json['upload']==''):
                del self.json['upload']
            if(self.json['edited']==''):
                del self.json['edited']
            if(len(self.refs)>0):
                self.json['refs']=self.refs
            self.refs=[]
            self.json['mitre_hash']=unicode(md5.new(str(self.json)).hexdigest(), 'utf-8')
            self.all_cves.append(self.json)
            self.json={'cve':'','desc':'', 'upload':'','edited':''}

    def characters(self, content):
        if self.is_title:
            self.json['cve']+=content
        
        if self.is_desc:
            self.json['desc']+=content

        if self.is_published:
            self.json['upload']+=content

        if self.is_modified:
            self.json['edited']+=content

        if self.is_url:
            self.refsjson['url']+=content
            
        if self.is_description:
            self.refsjson['refdesc']+=content



def parse_XML_from_mitre(mitre_year):
    print 'Parsira se XML'
    get_xml_from_mitre(mitre_year)
    grabber=ParseXML()
    saxparser = make_parser()
    saxparser.setContentHandler(grabber)
    saxparser.parse('mitre-cve-'+str(mitre_year)+'.xml')

with concurrent.futures.ThreadPoolExecutor(max_workers=19) as executor:
    executor.map(parse_XML_from_mitre, godine)

end=time.time()
print end-start
