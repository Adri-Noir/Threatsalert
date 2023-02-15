import cjson
import dicttoxml
obj=cjson.decode(open('nvd-cve-2016.json').read())
xml=dicttoxml.dicttoxml(obj)
print type(xml)
