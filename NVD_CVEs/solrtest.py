import pysolr
solr=pysolr.Solr('http://192.168.10.136:8983/solr/ExploitDB')
result=solr.suggest_terms('software_names', 'db')
similar = solr.more_like_this(q='software_names:*db*', mltfl='text')
print result