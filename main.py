from flask import Flask, request, render_template, jsonify, session, abort, redirect, flash, url_for
import pysolr
import os
import hashlib
import time
import random, string
import smtplib
import uuid
from threading import Thread
import subprocess
from wappalyzer import Wappalyzer
import json
import builtwith
import nmap

app = Flask(__name__, template_folder='static')
app.secret_key = os.urandom(12)
"""
fromaddr = ''
username = ''
password = ''
server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
server.ehlo()
server.login(username,password)
"""
solrip="http://172.17.0.3:8983/solr/"
solr = pysolr.Solr(solrip+'ExploitDB', timeout=30)
auth_solr = pysolr.Solr(solrip+'AuthDB', timeout=30)
inv_solr = pysolr.Solr(solrip+'InventoryDB', timeout=30)
rows=1000

def check_login():
	if 'logged_in' in session:
		if session['logged_in']:
			return True
	return False

@app.route('/api/name/<string:name>', methods=['GET'])
def api_get_by_name(name):
        results=solr.search('software_names:*'+name.lower()+'*', **{'rows': str(rows)})
        return jsonify({'by_name': results.docs})

@app.route('/api/cve/<string:cve>', methods=['GET'])
def api_get_by_cve(cve):
        results=solr.search('cve:'+cve.upper(), **{'rows': str(rows)})
        return jsonify({'cves': results.docs})

@app.route('/', methods = ['GET'])
def index():
	newest=solr.search('*:* AND NOT desc:*RESERVED* AND NOT desc:*REJECT*', **{'sort': 'upload desc', 'rows': 5})
	return render_template('index.html', newest=newest)

@app.route('/result', methods = ['POST', 'GET'])
def result():
	if request.method == 'POST':
		raw_cve = request.form["cve"]
		cve_br = request.form["cve"]
		select = request.form['search_type']
		if select=='cve':
			cve_br='*'+cve_br+'*'
			results=solr.search('cve:'+cve_br, **{'sort': 'id asc'})
		elif select=='software':
			if '*' in cve_br:
				cve_br='*'+cve_br+'*'
				results=solr.search('software_names:'+cve_br, **{'sort': 'id asc'})
			else:
				cve_br='*'+cve_br+'*'
				cve_br=cve_br.replace(" ", "*")
				results=solr.search('software_names:'+cve_br, **{'sort': 'id asc'})
		if results.hits%50!=0:
			return render_template("result.html", page_count=(results.hits//50)+1, search_string=cve_br, search_type=select, raw_str=raw_cve)
		else:
			return render_template("result.html", page_count=results.hits//50, search_string=cve_br, search_type=select, raw_str=raw_cve)
	elif request.method == 'GET':
		return render_template("result.html", page_count=1, search_string='', search_type='', raw_str='')

@app.route("/create_results")
def create_results():
	page=request.args.get('page', type=int)
	search_query=request.args.get('search_query', type=str)
	search_type=request.args.get('search_type', type=str)
	print page, search_query, search_type
	if search_type=="cve":
		query=solr.search('cve:'+search_query, **{'start': 50*(page-1), 'rows': 50, 'sort': 'id asc'})
	elif search_type=="software":
		query=solr.search('software_names:'+search_query, **{'start': 50*(page-1), 'rows': 50, 'sort': 'cvssv2_score desc, upload desc, id asc'})
	ratings={'low': 'badge badge-primary', 'medium': 'badge badge-warning', 'high': 'badge badge-danger', 'critical': 'badge badge-default'}
	return_query=''
	if len(query)==0:
		return '<div class="container slideInUp animated">No records found</div>'
	else:
		return_query+="""
		<div class="container slideInUp animated">
			Records Found:""" + str(query.hits)+ """
		</div>

		<div class="ui divided items container animated bounceInUp">

		"""
		for item in query:
			return_query+="""
				<div class="item" style="word-wrap:break-word; min-width: 70%;">
					<div class="content">
						<p class="header">""" + item['cve'] + '''<a href="'''+url_for('cve_details', cve_id=item['id'])+'''"><i class="right Info Circle icon"></i></a></p>
				
			'''
			if 'cvssv2_score' in item:
				return_query+='''
					<div class="meta">
						<span>CVSSV2 score: <span class="'''+ratings[item['cvssv2_severity'].lower()]+'''">'''+str(item['cvssv2_score'])+""" """+item['cvssv2_severity']+"""</span></span>
				
				"""
									
				if 'cvssv3_score' in item:
					return_query+='''
						<span>CVSSV3 score: <span class="'''+ratings[item['cvssv3_severity'].lower()]+'''">'''+str(item['cvssv3_score'])+""" """+item['cvssv3_severity']+"""</span></span>
					</div>
					"""
				else:
					return_query+="""</div>"""
    				
			return_query+="""
				<div class="description">
					<p>"""+item['desc']+"""</p>
				</div>
			"""

			if 'upload' in item:
				return_query+="""
					<div class="extra">
						<div class="ui label">Original release date: """+item['upload']+"""</div>
				
				"""
				if 'edited' in item:
					return_query+="""
						<div class="ui label">Last Modified: """+item['edited']+"""</div>
					"""
				return_query+="""</div>"""
			return_query+="""</div></div>"""
		return_query+="""</div>"""
		return jsonify(lol=return_query)

@app.route('/cve_info/<string:cve_id>')
def cve_details(cve_id):
	result=solr.search('id:'+cve_id)
	for i in result:
		return render_template("more_cve.html", cve_dict = i)

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'GET':
		return render_template("login_form.html")
	elif request.method == 'POST':
		if request.form['password'] != '' and request.form['email'] != '':
			exists=auth_solr.search('email:'+request.form['email']+' AND password:'+hashlib.sha256(request.form['password']).hexdigest())
			if (len(exists)==1):
				for user in exists:
					session['logged_in'] = True
					session['username'] = user['username']
					session['user_id'] = user['id']
					flash('Welcome '+user['username']+'!', 'success')
					return redirect(url_for('index'))
			elif(len(exists)==0):
				flash('Wrong username or password', 'warning')
				return redirect(url_for('login'))
		else:
			flash('Some of the fields are empty', 'danger')
			return redirect(url_for('login'))

@app.route("/logout")
def logout():
	session['logged_in'] = False
	flash('Goodbye '+session['username']+'!', 'info')
	session.pop('username', None)
	session.pop('user_id', None)
	return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'GET':
		return render_template("register_form.html")
	elif request.method == 'POST':
		if request.form['password'] != '' and request.form['password']==request.form['confirm_password'] and request.form['username'] != '' and request.form['email'] != '':
			exists=auth_solr.search('username:'+request.form['username'])
			if(len(exists)==0):
				super_secret_key=''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(25))
				user_dic={'username':request.form['username'], 'email': request.form['email'], 'password': hashlib.sha256(request.form['password']).hexdigest(), 'active': 'false', 'authhash': hashlib.sha256(request.form['email']+request.form['password']+super_secret_key).hexdigest(), 'senttimestamp': time.time()}
				msg = 'Subject: {}\n\n{}'.format('Validate Registration', 'http://localhost/verify_registration/'+user_dic['authhash'])
				server.sendmail(fromaddr, request.form['email'], msg)
				auth_solr.add([user_dic])
				flash('Verify your account on your email!', 'info')
				return redirect(url_for('index'))
			else:
				flash('Email or Username is taken', 'info')
				return redirect(url_for('register'))
		else:
			flash('Some fields are empty', 'danger')
			return redirect(url_for('register'))

@app.route('/verify_registration/<string:reg_hash>', methods=['GET'])
def verify_registration(reg_hash):
	search_results=auth_solr.search('authhash:'+reg_hash)
	if(len(search_results)==1):
		new_user_dict={}
		for user in search_results:
			if(user['senttimestamp']>time.time()-86400):
				new_user_dict['id']=user['id']
				new_user_dict['username']=user['username']
				new_user_dict['email']=user['email']
				new_user_dict['password']=user['password']
				new_user_dict['active']='true'
				auth_solr.add([new_user_dict])
				session['logged_in'] = True
				session['username'] = user['username']
				session['user_id'] = user['id']
				flash('Welcome '+user['username']+'!', 'success')
				return redirect(url_for('index'))
			else:
				flash('Key Expired', 'danger')
				return redirect(url_for('index'))
	else:
		flash('Wrong key', 'danger')
		return redirect(url_for('index'))

@app.route('/recover_password', methods=['GET','POST'])
def recover_password():
	if request.method=='GET':
		return render_template("recover_email_part.html")
	elif request.method=='POST':
		if request.form['email'] != '':
			exists=auth_solr.search('email:'+ request.form['email'])
			if(len(exists)==1):
				for user in exists:
					super_secret_key=''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(25))
					user_dic={'id':user['id'], 'username':user['username'], 'email': user['email'], 'password': user['password'], 'active': 'true', 'authhash': hashlib.sha256(user['email']+user['password']+super_secret_key).hexdigest(), 'senttimestamp': time.time()}
					auth_solr.add([user_dic])
					msg = 'Subject: {}\n\n{}'.format('Validate your Email', 'http://localhost/confirm_from_email/'+user_dic['authhash'])
					server.sendmail(fromaddr, request.form['email'], msg)
					flash('To change your password you need to go to your email and get the key', 'info')
					return redirect(url_for('index'))					
			else:
				flash('Invalid Email', 'danger')
				return redirect(url_for('recover_password'))
		else:
			flash('Email field empty!', 'warning')
			return redirect(url_for('recover_password'))

@app.route('/confirm_from_email/<string:passwordhash>', methods=['GET', 'POST'])
def finish_recovery(passwordhash):
	if request.method=='GET':
		search_results=auth_solr.search('authhash:'+passwordhash)
		if(len(search_results)==1):
			new_user_dict={}
			for user in search_results:
				if(user['senttimestamp']>time.time()-86400):
					flash('Enter your new password', 'info')
					return render_template("recover_password.html", secret_hash = user['authhash'])
				else:
					flash('Key Expired', 'danger')
					return redirect(url_for('index'))
		else:
			flash('Wrong key', 'danger')
			return redirect(url_for('index'))

	elif request.method=='POST':
		if request.form['password'] != '' and request.form['password']==request.form['confirm_password']:
			exists=auth_solr.search('authhash:'+passwordhash)
			if(len(exists)==1):
				for user in exists:
					user_dic={'id':user['id'], 'username':user['username'], 'email': user['email'], 'password': hashlib.sha256(request.form['password']).hexdigest(), 'active': 'true'}
					auth_solr.add([user_dic])
					session['logged_in'] = True
					session['username'] = user['username']
					session['user_id'] = user['id']
					flash('Password changed', 'success')
					flash('Welcome '+session['username']+'!', 'success')
					return redirect(url_for('index'))					
			else:
				flash('KARLO JOSIP DOSTA!', 'danger')
				return redirect(url_for('confirm_from_email/'+passwordhash))
		else:
			flash('Password field is empty or passwords do not match', 'warning')
			return redirect(url_for('confirm_from_email/'+passwordhash))

@app.route('/change_username', methods=['POST', 'GET'])
def change_profile():
	if check_login():
		if request.method=='GET':
			exists=auth_solr.search('username:'+session['username'])
			for user in exists:
				return render_template("change_profile.html", profile=user)
		elif request.method=='POST':
			if request.form['username']!='':
				exists=auth_solr.search('username:'+request.form['username'])
				if len(exists)==0:
					old_user=auth_solr.search('username:'+session['username'])
					for user in old_user:
						auth_solr.add([{'id':user['id'], 'username':request.form['username'], 'email': user['email'], 'password': user['password']}])
						session['username'] = request.form['username']
					flash('Username updated', 'success')
					flash('Welcome '+session['username']+'!', 'success')
					return redirect(url_for('index'))
				else:
					flash('Username already taken!', 'warning')
					return redirect(url_for('change_profile'))
			else:
				flash('Username field is empty', 'danger')
				return redirect(url_for('change_profile'))
	else:
		flash('You are not logged in', 'danger')
		return redirect(url_for('index'))
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
	if check_login():
		if request.method=='GET':
			return render_template("change_password.html")
		elif request.method=='POST':
			if request.form['old_password']!='' and request.form['password']!='' and request.form['confirm_password']!='' and request.form['password']==request.form['confirm_password']:
				exists=auth_solr.search('username:'+session['username'])
				for user in exists:
					if user['password']==hashlib.sha256(request.form['old_password']).hexdigest():
						auth_solr.add([{'id':user['id'], 'username':user['username'], 'email': user['email'], 'password': hashlib.sha256(request.form['password']).hexdigest()}])
						flash('Password changed!', 'success')
						return redirect(url_for('index'))
					else:
						flash("Old password doesn't match", 'danger')
						return redirect(url_for('change_password'))
			else:
				flash('Some fields are empty', 'danger')
				return redirect(url_for('change_password'))
	else:
		flash('You are not logged in', 'danger')
		return redirect(url_for('index'))

def get_software_from_site(site, id, collection):
	print 'pocetak'
	process = subprocess.Popen(['wad', '-u', site], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	response=json.loads(process.stdout.read())
	for dic in response[response.keys()[0]]:
		if dic["app"].lower() in collection:
			continue
		collection[dic["app"].lower()]=''
		if dic["ver"]!=None:
			collection[dic["app"].lower()]=dic["ver"]
	print 'prvo'
	website=builtwith.parse(site)
	print website
	for key in website.keys():
		for item in website[key]:
			if item.lower() not in collection:
				collection[item.lower()]=""
	print 'drugo'
	nm = nmap.PortScanner()
	if (site[0:5]=="https"):
		nm.scan(site[8:], arguments='-sV -A -T4')
	elif (site[0:5]=="http:"):
		nm.scan(site[7:], arguments='-sV -A -T4')
	for ip in nm.all_hosts():
		for key in nm[ip]['tcp'].keys():
			name = nm[ip]['tcp'][key]['product']
			if name.lower() in collection:
				if collection[name.lower()] != '':
					collection[name.lower()]=nm[ip]['tcp'][key]['version'].lower()
			else:
				collection[name.lower()]=nm[ip]['tcp'][key]['version'].lower()
	print "gotovo"
	site_dict=inv_solr.search("id:"+id).docs[0]
	if 'software' not in site_dict:
		site_dict["software"]=[]
	for soft_name in collection.keys():
		if collection[soft_name]!='':
			site_dict["software"].append(soft_name+' '+collection[soft_name])
		else:
			site_dict["software"].append(soft_name)
	inv_solr.add([site_dict])


@app.route('/inventory', methods=['POST'])
def inventory():
	if check_login():
		if request.method=="POST":
			if request.form['name']!='' and request.form['description']!='':
				exists=inv_solr.search('site:"'+str(request.form['name'])+'"'+' AND user:'+session['user_id'])
				if len(exists)==0:
					uuid_id=uuid.uuid1().hex
					inv_solr.add([{ 'id': uuid_id, 'site': request.form['name'], 'site_description': request.form['description'], 'user': session['user_id']}])
					w=Wappalyzer()
					data=w.analyze(request.form['name'])
					collection={}
					for key in data.keys():
						if key.lower() in collection:
							if collection[key.lower()]=='' and data[key]["version"]!='':
								collection[key.lower()]=data[key]["version"]
						else:
							collection[key.lower()] = data[key]["version"]
					background_thread = Thread(target=get_software_from_site, args=(request.form["name"],uuid_id,collection,))
					background_thread.start()
					return redirect(url_for('site_details', site_id=uuid_id))
				else:
					flash('You already have that site', 'warning')
					sites=inv_solr.search('user:'+session['user_id'])
					for site in sites:
						return redirect(url_for('site_details', site_id=site['id']))
			else:
				flash('Some field are empty', 'warning')
				sites=inv_solr.search('user:'+session['user_id'])
				for site in sites:
					return redirect(url_for('site_details', site_id=site['id']))
	else:
		flash('You are not logged in', 'danger')
		return redirect(url_for('index'))

@app.route('/delete_inventory/<string:by_id>', methods=['GET'])
def delete_inventory(by_id):
	if check_login():
		inv_solr.delete(q='id:'+by_id+' AND user:'+session['user_id'])
		flash('Site successfully deleted', 'success')
		return redirect(url_for('site_details'))
	else:
		flash('You are not logged in', 'danger')
		return redirect(url_for('index'))

@app.route('/edit_inventory/<string:by_id>', methods=['POST'])
def edit_inventory(by_id):
	if check_login():
		if request.form['newname']!='' and request.form['newdescription']!='':
			exists=inv_solr.search('site:'+request.form['newname']+' AND user:'+session['user_id']+' AND NOT id:'+by_id)
			if len(exists)==0:
				sites=inv_solr.search('id:'+by_id+' AND user:'+session['user_id'])
				dic={'id': by_id, 'user':session['user_id'], 'site': request.form['newname'], 'site_description':request.form['newdescription']}
				for site in sites:
					if 'software' in site:
						dic['software']=site['software']
					inv_solr.add([dic])
					flash('Site updated', 'success')
					return redirect(url_for('site_details', site_id=by_id))
			else:
				flash('Site already exists! Use some other name.', 'warning')
				return redirect(url_for('site_details', site_id=by_id))
		else:
			flash('Some fields are empty', 'warning')
			return redirect(url_for('site_details', site_id=by_id))
	else:
		flash('You are not logged in', 'danger')
		return redirect(url_for('index'))

@app.route('/site_details', methods=['GET'])
@app.route('/site_details/<string:site_id>', methods=['GET'])
def site_details(site_id=None):
	if check_login():
		if request.method=='GET':
			if site_id==None:
				sites=inv_solr.search('user:'+session['user_id'], **{'rows': rows})
				if len(sites)>0:
					for site in sites:
						return redirect(url_for('site_details', site_id=site['id']))
				else:
					return render_template("site_details.html", sites=[], soft_list=[], one_site_id='', software_query=[])
			else:
				sites=inv_solr.search('user:'+session['user_id'], **{'rows': rows})
				softwares=inv_solr.search('id:'+site_id)
				soft_list=[]
				software_query='('
				for soft in softwares:
					one_site_id=soft['id']
					if 'software' in soft:
						for one in soft['software']:
							soft_list.append(one)
							software_query+='*'+one.replace(' ','*')+'*'+' OR '
				software_query=software_query[:len(software_query)-4]+')'
				print software_query, 'OVDJE JE PRINT'
				if software_query!=')':
					hits=solr.search('software_names:'+software_query).hits
				else:
					hits=0
				return render_template("site_details.html", sites=sites, soft_list=soft_list, one_site_id=one_site_id, pagenm=hits//50+int(bool(hits%50)), software_query=software_query)
	else:
		flash('You are not logged in', 'danger')
		return redirect(url_for('index'))	

@app.route('/add_software/<string:site_id>', methods=['POST'])
def add_software(site_id):
	if check_login():
		if request.form['software']!='':
			site=inv_solr.search('id:'+site_id+' AND user:'+session['user_id'])
			if len(site)==0:
				flash('KARLO JOSIP DOSTA', 'danger')
				return redirect(url_for('site_details', site_id=site_id))
			else:
				for one in site:
					software_search=request.form['software']
					if ('software' in one):
						if software_search not in one['software']:
							old_site={'user':one['user'], 'site': one['site'], 'site_description': one['site_description'], 'id': one['id'], 'software': one['software']}
						else:
							flash('That software already exists in '+one['site'], 'warning')
							return redirect(url_for('site_details', site_id=site_id))
					else:
						old_site={'user':one['user'], 'site': one['site'], 'site_description': one['site_description'], 'id': one['id'], 'software': []}
					old_site['software'].append(software_search)
					inv_solr.add([old_site])
					flash('Software added', 'success')
					return redirect(url_for('site_details', site_id=site_id))
		elif request.form['software']=='':
			flash('Field is empty', 'warning')
			return redirect(url_for('site_details', site_id=site_id))
		else:
			flash('An error ocurred', 'danger')
			return redirect(url_for('site_details', site_id=site_id))
	else:
		flash('You are not logged in', 'danger')
		return redirect(url_for('index'))		

@app.route('/delete_software/<string:site_id>/<string:software>', methods=['GET'])
def delete_software(site_id, software):
	if check_login():
		results=inv_solr.search('id:'+site_id+' AND user:'+session['user_id'])
		if len(results)==1:
			for result in results:
				result['software'].remove(software)
				inv_solr.add([result])
				flash('Software deleted', 'success')
				return redirect(url_for('site_details', site_id=site_id))
	else:
		flash('You are not logged in', 'danger')
		return redirect(url_for('index'))		

@app.route('/edit_software/<string:site_id>/<string:software>', methods=['POST'])
def edit_software(site_id, software):
	if check_login():
		if request.form['newsoftname']!='':
			results=inv_solr.search('id:'+site_id+' AND user:'+session['user_id'])
			if len(results)==1:
				for result in results:
					if request.form['newsoftname'] not in result['software']:
						result['software'].remove(software)
						result['software'].append(request.form['newsoftname'])
						inv_solr.add([result])
						flash('Software succesfully edited', 'success')
						return redirect(url_for('site_details', site_id=site_id))
					else:
						flash('Software already exists', 'warning')
						return redirect(url_for('site_details', site_id=site_id))
			else:
				flash('KARLO JOSIP DOSTA', 'danger')
				return redirect(url_for('site_details', site_id=site_id))
		else:
			flash('Field is empty', 'warning')
			return redirect(url_for('site_details', site_id=site_id))
	else:
		flash('You are not logged in', 'danger')
		return redirect(url_for('index'))	
if __name__ == "__main__":
	app.run(host='0.0.0.0', port=80, threaded=True)
