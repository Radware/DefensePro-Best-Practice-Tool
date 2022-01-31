import urllib3
import getpass
urllib3.disable_warnings()
from os import error
from Excel_Handler import Excel_Handler
from Config_Convertor_Handler import Config_Convertor_Handler
from requests import Session
from requests.sessions import session
from error_handling import Error_handler, VISION_LOGIN_ERROR
import json
import time
import timeit


class Vision:

	def __init__(self, ip, username, password):
		self.ip = ip
		self.login_data = {"username": username, "password": password}
		self.base_url = "https://" + ip
		self.session = Session()
		self.session.headers.update({"Content-Type": "application/json"})
		self.config_file = Config_Convertor_Handler()
		self.login()
		
	def login(self):
		login_url = self.base_url + '/mgmt/system/user/login'

		r = self.session.post(url=login_url, json=self.login_data, verify=False)
		response = r.json()

		if response['status'] == 'ok':
			self.session.headers.update({"JSESSIONID": response['jsessionid']})
			#print("Auth Cookie is:  " + response['jsessionid'])
			#print(r.status_code)
			print("Login to Vision was successful")
			return str(r.status_code)
		else:
			# Error handling to be completed
			raise Error_handler(VISION_LOGIN_ERROR)

	def lock_device(self,dp_ip):
		url = f"https://{self.ip}/mgmt/system/config/tree/device/byip/{dp_ip}/lock"
		response = self.session.post(url, verify=False)
		print(f"Lock Device {dp_ip} --> {response.status_code}")
		print("\n"+"*"*30+"\n")

	def update_policy(self,dp_ip):
		self.lock_device(dp_ip)
		update_url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/updatepolicies?"
		response = self.session.post(update_url, verify=False)
		print(f"Policy Update --> {response.status_code}")

	def BDoS_profile_config(self, dp_ip):
		BDoS_config_file = self.config_file.create_BDoS_Profile_dic()
		print("BDoS Profile Configurations\n")
		for index in range(len(BDoS_config_file)):
			url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsNetFloodProfileTable/{BDoS_config_file[index]['rsNetFloodProfileName']}/"
			bdos_profile_body = json.dumps(BDoS_config_file[index])
			response = self.session.post(url, data=bdos_profile_body, verify=False)
			print(f"{BDoS_config_file[index]['rsNetFloodProfileName']} --> {response.status_code}")
		print("\n"+"*"*30+"\n")

	def DNS_SIG_config(self, dp_ip, custom_dns_config_file):
		#custom_dns_config_file = self.config_file.create_Custom_DNS_Singature_Profile_dic()
		profile_name = custom_dns_config_file[0][0]['rsIDSSignaturesProfileName']
		print("DNS Custom Profile Configurations\n")

		url_dns_service = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Services/Network%20Services-DNS/"
		url_dns_complex = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Complexity/Low/"

		dns_service_body = json.dumps(custom_dns_config_file[0][0])
		dns_complex_body = json.dumps(custom_dns_config_file[0][1])

		response_service = self.session.post(
				url_dns_service, data=dns_service_body, verify=False)
		response_com = self.session.post(
				url_dns_complex, data=dns_complex_body, verify=False)
		print(f"DNS-Service : {profile_name} --> {response_service.status_code}")
		print(f"DNS-Complex : {profile_name} --> {response_com.status_code}")
		
		# Adding DOS fields to custom siganture:
		url_threat_floods = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Floods/"
		url_threat_slow = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Slow%20Rate/"
		url_threat_vulen = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Vulnerability//"
		url_threat_floods_body = json.dumps(custom_dns_config_file[0][2])
		url_threat_slow_body = json.dumps(custom_dns_config_file[0][3])
		url_threat_vulen_body = json.dumps(custom_dns_config_file[0][4])
		response_flood = self.session.post(url_threat_floods, data=url_threat_floods_body, verify=False)
		response_slow = self.session.post(url_threat_slow, data=url_threat_slow_body, verify=False)
		response_vulen  = self.session.post(url_threat_vulen, data=url_threat_vulen_body, verify=False)
		print(f"Threat-Flood : {profile_name} --> {response_flood.status_code}")
		print(f"Threat-Slow : {profile_name} --> {response_slow.status_code}")
		print(f"Threat-Vulen: {profile_name} --> {response_vulen.status_code}")

		print("\n"+"*"*30+"\n")

	def HTTP_SIG_config(self, dp_ip, custom_http_config_file):
		#custom_http_config_file = self.config_file.create_Custom_HTTP_Singature_Profile_dic()
		profile_name = custom_http_config_file[0][0]['rsIDSSignaturesProfileName']
		print("HTTP Custom Profile Configurations\n")

		url_http_service = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Services/Web-HTTP/"
		url_http_complex = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Complexity/Low/"
		url_http_confidance = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Confidence/High/"
		url_http_risk = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Risk/High/"

		http_service_body = json.dumps(custom_http_config_file[0][0])
		http_complex_body = json.dumps(custom_http_config_file[0][1])
		http_confidance_body = json.dumps(custom_http_config_file[0][2])
		http_risk_body = json.dumps(custom_http_config_file[0][3])

		response_service = self.session.post(url_http_service, data=http_service_body, verify=False)
		response_com = self.session.post(url_http_complex, data=http_complex_body, verify=False)
		response_conf = self.session.post(url_http_confidance, data=http_confidance_body, verify=False)
		response_risk = self.session.post(url_http_risk, data=http_risk_body, verify=False)

		print(f"HTTP-Service : {profile_name} --> {response_service.status_code}")
		print(f"HTTP-Complex : {profile_name} --> {response_com.status_code}")
		print(f"HTTP-Confidance : {profile_name} --> {response_conf.status_code}")
		print(f"HTTP-Risk : {profile_name} --> {response_risk.status_code}")
		
		# Adding DOS fields to custom siganture:
		url_threat_floods = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Floods/"
		url_threat_slow = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Slow%20Rate/"
		url_threat_vulen = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Vulnerability//"
		url_threat_floods_body = json.dumps(custom_http_config_file[0][4])
		url_threat_slow_body = json.dumps(custom_http_config_file[0][5])
		url_threat_vulen_body = json.dumps(custom_http_config_file[0][6])
		response_flood = self.session.post(
			url_threat_floods, data=url_threat_floods_body, verify=False)
		response_slow = self.session.post(
			url_threat_slow, data=url_threat_slow_body, verify=False)
		response_vulen = self.session.post(
			url_threat_vulen, data=url_threat_vulen_body, verify=False)
		print(f"Threat-Flood : {profile_name} --> {response_flood.status_code}")
		print(f"Threat-Slow : {profile_name} --> {response_slow.status_code}")
		print(f"Threat-Vulen: {profile_name} --> {response_vulen.status_code}")

		print("\n"+"*"*30+"\n")

	def HTTPS_SIG_config(self, dp_ip, custom_https_config_file):
		# custom_https_config_file = self.config_file.create_Custom_HTTPS_Singature_Profile_dic()
		profile_name = custom_https_config_file[0][0]['rsIDSSignaturesProfileName']
		print("HTTPS Custom Profile Configurations\n")
		url_https_service = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Services/Web-HTTPS/"
		url_https_complex = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Complexity/Low/"
		url_https_confidance = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Confidence/High/"
		url_https_risk = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Risk/High/"

		https_service_body = json.dumps(custom_https_config_file[0][0])
		https_complex_body = json.dumps(custom_https_config_file[0][1])
		https_confidance_body = json.dumps(custom_https_config_file[0][2])
		https_risk_body = json.dumps(custom_https_config_file[0][3])

		response_service = self.session.post(url_https_service, data=https_service_body, verify=False)
		response_com = self.session.post(url_https_complex, data=https_complex_body, verify=False)
		response_conf = self.session.post(url_https_confidance, data=https_confidance_body, verify=False)
		response_risk = self.session.post(url_https_risk, data=https_risk_body, verify=False)

		print(f"HTTPS-Service : {profile_name} --> {response_service.status_code}")
		print(f"HTTPS-Complex : {profile_name} --> {response_com.status_code}")
		print(f"HTTPS-Confidance : {profile_name} --> {response_conf.status_code}")
		print(f"HTTPS-Risk : {profile_name} --> {response_risk.status_code}")
		
		# Adding DOS fields to custom siganture:
		url_threat_floods = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Floods/"
		url_threat_slow = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Slow%20Rate/"
		url_threat_vulen = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Vulnerability//"
		url_threat_floods_body = json.dumps(custom_https_config_file[0][4])
		url_threat_slow_body = json.dumps(custom_https_config_file[0][5])
		url_threat_vulen_body = json.dumps(custom_https_config_file[0][6])
		response_flood = self.session.post(
			url_threat_floods, data=url_threat_floods_body, verify=False)
		response_slow = self.session.post(
			url_threat_slow, data=url_threat_slow_body, verify=False)
		response_vulen = self.session.post(
			url_threat_vulen, data=url_threat_vulen_body, verify=False)
		print(f"Threat-Flood : {custom_https_config_file[0][0]['rsIDSSignaturesProfileName']} --> {response_flood.status_code}")
		print(f"Threat-Slow : {custom_https_config_file[0][0]['rsIDSSignaturesProfileName']} --> {response_slow.status_code}")
		print(f"Threat-Vulen: {custom_https_config_file[0][0]['rsIDSSignaturesProfileName']} --> {response_vulen.status_code}")

		print("\n"+"*"*30+"\n")

	def Mail_SIG_config(self, dp_ip, custom_mail_config_file):
		# custom_mail_config_file = self.config_file.create_Custom_Mail_Singature_Profile_dic()
		profile_name = custom_mail_config_file[0][0]['rsIDSSignaturesProfileName']
		print("Mail Custom Profile Configurations\n")

		url_mail_imap_service = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Services/Mail-IMAP/"
		url_mail_pop3_service = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Services/Mail-POP3/"
		url_mail_smtp_service = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Services/Mail-SMTP/"
		url_mail_complex = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Complexity/Low/"
		url_mail_confidance = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Confidence/High/"
		url_mail_risk = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Risk/High/"

		mail_service_imap_body = json.dumps(custom_mail_config_file[0][0])
		mail_service_pop3_body = json.dumps(custom_mail_config_file[0][1])
		mail_service_smtp_body = json.dumps(custom_mail_config_file[0][2])
		mail_complex_body = json.dumps(custom_mail_config_file[0][3])
		mail_confidance_body = json.dumps(custom_mail_config_file[0][4])
		mail_risk_body = json.dumps(custom_mail_config_file[0][5])

		response_service_imap = self.session.post(url_mail_imap_service, data=mail_service_imap_body, verify=False)
		response_service_pop3 = self.session.post(url_mail_pop3_service, data=mail_service_pop3_body, verify=False)
		response_service_smtp = self.session.post(url_mail_smtp_service, data=mail_service_smtp_body, verify=False)
		response_complex = self.session.post(url_mail_complex, data=mail_complex_body, verify=False)
		response_conf = self.session.post(url_mail_confidance, data=mail_confidance_body, verify=False)
		response_risk = self.session.post(url_mail_risk, data=mail_risk_body, verify=False)


		print(f"Mail-Service IMAP: {profile_name} --> {response_service_imap.status_code}")
		print(f"Mail-Service POP3: {profile_name} --> {response_service_pop3.status_code}")
		print(f"Mail-Service SMTP: {profile_name} --> {response_service_smtp.status_code}")
		print(f"Mail-Complex : {profile_name} --> {response_complex.status_code}")
		print(f"Mail-Confidance : {profile_name} --> {response_conf.status_code}")
		print(f"Mail-Risk : {profile_name} --> {response_risk.status_code}")

		# Adding DOS fields to custom siganture:
		url_threat_floods = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Floods/"
		url_threat_slow = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Slow%20Rate/"
		url_threat_vulen = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Vulnerability//"
		url_threat_floods_body = json.dumps(custom_mail_config_file[0][4])
		url_threat_slow_body = json.dumps(custom_mail_config_file[0][5])
		url_threat_vulen_body = json.dumps(custom_mail_config_file[0][6])
		response_flood = self.session.post(
			url_threat_floods, data=url_threat_floods_body, verify=False)
		response_slow = self.session.post(
			url_threat_slow, data=url_threat_slow_body, verify=False)
		response_vulen = self.session.post(
			url_threat_vulen, data=url_threat_vulen_body, verify=False)
		print(
			f"Threat-Flood : {custom_mail_config_file[0][0]['rsIDSSignaturesProfileName']} --> {response_flood.status_code}")
		print(
			f"Threat-Slow : {custom_mail_config_file[0][0]['rsIDSSignaturesProfileName']} --> {response_slow.status_code}")
		print(
			f"Threat-Vulen: {custom_mail_config_file[0][0]['rsIDSSignaturesProfileName']} --> {response_vulen.status_code}")

		print("\n"+"*"*30+"\n")

	def FTP_SIG_config(self, dp_ip, custom_ftp_config_file):
		# custom_ftp_config_file = self.config_file.create_Custom_FTP_Singature_Profile_dic()
		profile_name = custom_ftp_config_file[0][0]['rsIDSSignaturesProfileName']
		print("FTP Custom Profile Configurations\n")
		url_ftp_service = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Services/File%20Transfer-FTP/"
		url_ftp_complex = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/1/Complexity/Low/"
		ftp_service_body = json.dumps(custom_ftp_config_file[0][0])
		ftp_complex_body = json.dumps(custom_ftp_config_file[0][1])
		response_service = self.session.post(
			url_ftp_service, data=ftp_service_body, verify=False)
		response_comp = self.session.post(
			url_ftp_complex, data=ftp_complex_body, verify=False)
		print(f"FTP-Service : {profile_name} --> {response_service.status_code}")
		print(f"FTP-Complex : {custom_ftp_config_file[0][1]['rsIDSSignaturesProfileName']} --> {response_comp.status_code}")

		#Adding DOS fields to custom siganture:
		url_threat_floods = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Floods/"
		url_threat_slow = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Slow%20Rate/"
		url_threat_vulen = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSignaturesProfilesTable/{profile_name}/2/Threat%20Type/DoS%20-%20Vulnerability//"
		url_threat_floods_body = json.dumps(custom_ftp_config_file[0][2])
		url_threat_slow_body = json.dumps(custom_ftp_config_file[0][3])
		url_threat_vulen_body = json.dumps(custom_ftp_config_file[0][4])
		response_flood = self.session.post(url_threat_floods, data=url_threat_floods_body, verify=False)
		response_slow = self.session.post(url_threat_slow, data=url_threat_slow_body, verify=False)
		response_vulen = self.session.post(url_threat_vulen, data=url_threat_vulen_body, verify=False)
		print(f"Threat-Flood : {profile_name} --> {response_flood.status_code}")
		print(f"Threat-Slow : {profile_name} --> {response_slow.status_code}")
		print(f"Threat-Vulen: {profile_name} --> {response_vulen.status_code}")
			

		print("\n"+"*"*30+"\n")

	def OOS_profile_config(self, dp_ip):
		OOS_config_file = self.config_file.create_OOS_Profile_dic()
		print("OOS Profile Configurations\n")
		for index in range(len(OOS_config_file)):
			url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsStatefulProfileTable/{OOS_config_file[index]['rsSTATFULProfileName']}/"
			oos_profile_body = json.dumps(OOS_config_file[index])
			response = self.session.post(url, data=oos_profile_body, verify=False)
			print(f"{OOS_config_file[index]['rsSTATFULProfileName']} --> {response.status_code}")
		print("\n"+"*"*30+"\n")

	def EAAF_profile_config(self, dp_ip, EAAF_config_file):
		#EAAF_config_file = self.config_file.create_ERT_Profile_dic()
		profile_name = EAAF_config_file[0]['rsErtAttackersFeedProfileName']
		print("EAAF Profile Configurations\n")
		url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsErtAttackersFeedProfileTable/{profile_name}/"
		eaaf_profile_body = json.dumps(EAAF_config_file[0])
		response = self.session.post(url, data=eaaf_profile_body, verify=False)
		if response.status_code == 200:
			print(f"{profile_name} --> {response.status_code}")
		elif response.status_code == 500:
			print(json.loads(response.text)['message'])
			#if "not found" in json.loads(response.text)['message'].split(':')[1]:
		print("\n"+"*"*30+"\n")

	def NTP_server_config(self, dp_ip, NTP_config_file):
		# NTP_config_file = self.config_file.create_ntp_config()
		print("NTP Server Configurations\n")
		ntp_srv_url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config"
		ntp_ip_body = json.dumps(NTP_config_file[0][0])
		ntp_enable = json.dumps(NTP_config_file[0][1])
		ntp_ip_res = self.session.put(
			ntp_srv_url, data=ntp_ip_body, verify=False)
		ntp_enable_res = self.session.put(
			ntp_srv_url, data=ntp_enable, verify=False)

		print(f" NTP IP Configuration Response --> {ntp_ip_res.status_code}")
		print(f" NTP Enable Response --> {ntp_enable_res.status_code}")
		print("\n"+"*"*30+"\n")

	def Syslog_server_config(self, dp_ip, Syslog_config_file):
		# Syslog_config_file = self.config_file.create_syslog_config()
		print("Syslog Server Configurations\n")
		for index in range(len(Syslog_config_file)):
			sys_srv_url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rdwrSyslogServerTable/{Syslog_config_file[index]['rdwrSyslogServerAddress']}"
			syslog_body = json.dumps(Syslog_config_file[index])	
			syslog_res = self.session.post(sys_srv_url, data=syslog_body, verify=False)
			print(f" Syslog Configuration Response --> {syslog_res.status_code}")
		print("\n"+"*"*30+"\n")

	def SYN_profile_config(self, dp_ip):
		SYN_config_file = self.config_file.create_Syn_Profile_dic()
		print("SYN Profile Configurations\n")
		for index in range(len(SYN_config_file)):
				profile_params_url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSynProfilesParamsTable/{SYN_config_file[index][0]['rsIDSSynProfilesParamsName']}/"
				profile_create_url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSynProfilesTable/{SYN_config_file[index][0]['rsIDSSynProfilesParamsName']}/{SYN_config_file[index][1]['rsIDSSynProfileServiceName']}/"
				syn_profile_body = json.dumps(SYN_config_file[index][0]) 
				profile_paramters = json.dumps(SYN_config_file[index][1])

				profile_create_res = self.session.post(
					profile_create_url, data=profile_paramters, verify=False)

				response_params_update = self.session.put(
					profile_params_url, data=syn_profile_body, verify=False)

				print(f"{SYN_config_file[index][0]['rsIDSSynProfilesParamsName']}, Profile_Creation_Response --> {profile_create_res.status_code}")
				print(f"{SYN_config_file[index][0]['rsIDSSynProfilesParamsName']}, Profile_Params_Update_Response --> {response_params_update.status_code}")
		
				#Checks if its the Global Policy, need to configure HTTPS, and HTTP 
				# Adding HTTP Application to Syn Profile
				if SYN_config_file[index][0]['rsIDSSynProfilesParamsName'] == "Global_auto_syn":
					profile_create_url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSynProfilesTable/{SYN_config_file[index][0]['rsIDSSynProfilesParamsName']}/{SYN_config_file[index][2]['rsIDSSynProfileServiceName']}/"
					profile_paramters_HTTP = json.dumps(SYN_config_file[index][1])
					rofile_create_res = self.session.post(
                                            profile_create_url, data=profile_paramters_HTTP, verify=False)
					print(f"{SYN_config_file[index][0]['rsIDSSynProfilesParamsName']}, Adding HTTP To global Syn Profile --> {profile_create_res.status_code}")

		print("\n"+"*"*30+"\n")
                    
	def DNS_Flood_profile_config(self, dp_ip, DNS_config_file):
		# DNS_config_file = self.config_file.create_DNS_Profile_dic()
		print("DNS Profile Configurations\n")
		for index in range(len(DNS_config_file)):
			url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsDnsProtProfileTable/{DNS_config_file[index]['rsDnsProtProfileName']}/"
			DNS_profile_body = json.dumps(DNS_config_file[index])
			response = self.session.post(url, data=DNS_profile_body, verify=False)
			print(f"{DNS_config_file[index]['rsDnsProtProfileName']} --> {response.status_code}")
		print("\n"+"*"*30+"\n")

	def AS_profile_config(self, dp_ip):

		as_profile_flag = self.config_file.get_as_profile_status()
		if as_profile_flag == "Yes":
			# Enable AS Global:
			url_eanble_as = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config"
			body_enable = {"rsIDSScanningMechanismStatus": "1"}
			AS_enable_body = json.dumps(body_enable)
			response = self.session.put(url_eanble_as, data=AS_enable_body, verify=False)
			print(f"Enable AS Globally --> {response.status_code}")
						
			AS_config_file = self.config_file.create_AS_Profile_dic()
			print("Anti-Scan Profile Configurations\n")
			for index in range(len(AS_config_file)):
				url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSScanningProfilesTable/{AS_config_file[index]['rsIDSScanningProfilesName']}/"
				AS_profile_body = json.dumps(AS_config_file[index])
				response = self.session.post(url, data=AS_profile_body, verify=False)
				print(f"{AS_config_file[index]['rsIDSScanningProfilesName']} --> {response.status_code}")
			print("\n"+"*"*30+"\n")
		else:
			print("AS Profile --> Disabled")

	def ERT_profile_config(self, dp_ip):
		ERT_config_file = self.config_file.create_ERT_Profile_dic()
		for index in range(len(ERT_config_file)):
			url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsErtAttackersFeedProfileTable/{ERT_config_file[index]['rsErtAttackersFeedProfileName']}/"
			ERT_profile_body = json.dumps(ERT_config_file[index])
			response = self.session.post(url, data=ERT_profile_body, verify=False)
			print(response)

	def GEO_profile_config(self, dp_ip):
		GEO_config_file = self.config_file.create_GEO_Profile_dic()
		for index in range(len(GEO_config_file)):
			url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsGeoProfileTable/{GEO_config_file[index]['rsGeoProfileName']}/"
			GEO_profile_body = json.dumps(GEO_config_file[index])
			response = self.session.post(url, data=GEO_profile_body, verify=False)
			print(response)

	def HTTPS_profile_config(self, dp_ip):
		HTTPS_config_file = self.config_file.create_HTTPS_Profile_dic()
		for index in range(len(HTTPS_config_file)):
			url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsHttpsFloodProfileTable/{HTTPS_config_file[index]['rsHttpsFloodProfileName']}/"
			HTTPS_profile_body = json.dumps(HTTPS_config_file[index])
			response = self.session.post(url, data=HTTPS_profile_body, verify=False)
			print(response)

	def net_class_config(self, dp_ip):
		networks_config = self.config_file.create_net_class_list()
		print("Network Class Configurations\n")
		for index in range (len(networks_config)):
				url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsBWMNetworkTable/{networks_config[index]['rsBWMNetworkName']}/{networks_config[index]['rsBWMNetworkSubIndex']}/"
				net_class_body = json.dumps(networks_config[index])
				response = self.session.post(url, data=net_class_body, verify=False)
				print(f" Creating Network Class: {networks_config[index]['rsBWMNetworkName']} --> {response.status_code}")
		time.sleep(2.0)
		print("\n"+"*"*30+"\n")

	def Protection_config(self, dp_ip):
	 
	  delay_time = 2.5
	  self.lock_device(dp_ip)
	  time.sleep(delay_time)
	  self.BDoS_profile_config(dp_ip)
	  time.sleep(delay_time)
	  self.OOS_profile_config(dp_ip)
	  time.sleep(delay_time)
	  self.AS_profile_config(dp_ip)
	  time.sleep(delay_time)
	  self.SYN_profile_config(dp_ip)
	  time.sleep(delay_time)
	  self.update_policy(dp_ip)
	  time.sleep(delay_time)

	def Policy_config(self, dp_ip):

		Policy_config_file = self.config_file.create_Protections_Per_Policy_dic()
		DNS_Singature_Profiles_Dict = self.config_file.create_Custom_DNS_Singature_Profile_dic()
		FTP_Singature_Profiles_Dict = self.config_file.create_Custom_FTP_Singature_Profile_dic()
		HTTP_Singature_Profiles_Dict = self.config_file.create_Custom_HTTP_Singature_Profile_dic()
		HTTPS_Singature_Profiles_Dict = self.config_file.create_Custom_HTTPS_Singature_Profile_dic()
		Mail_Singature_Profiles_Dict = self.config_file.create_Custom_Mail_Singature_Profile_dic()
		DNS_Flood_Profiles_Dict = self.config_file.create_DNS_Profile_dic()
		NTP_Flag = self.config_file.create_ntp_config()
		EAAF_Profile = self.config_file.create_ERT_Profile_dic()
		Syslog_Flag = self.config_file.create_syslog_config()

		#Checks if Custom FTP Singature profile is requierd 
		if FTP_Singature_Profiles_Dict:
			self.FTP_SIG_config(dp_ip, FTP_Singature_Profiles_Dict)
			time.sleep(1.5)
		#Checks if Custom HTTP Singature profile is requierd 
		if HTTP_Singature_Profiles_Dict:
			self.HTTP_SIG_config(dp_ip, HTTP_Singature_Profiles_Dict)
			time.sleep(1.5)
		#Checks if Custom HTTPS Singature profile is requierd 
		if HTTPS_Singature_Profiles_Dict:
			self.HTTPS_SIG_config(dp_ip, HTTPS_Singature_Profiles_Dict)
			time.sleep(1.5)
		#Checks if Custom Mail Singature profile is requierd 
		if Mail_Singature_Profiles_Dict:
			self.Mail_SIG_config(dp_ip, Mail_Singature_Profiles_Dict)
			time.sleep(1.5)
		#Checks if Custom DNS Singature profile is requierd 
		if DNS_Singature_Profiles_Dict:
			self.DNS_SIG_config(dp_ip, DNS_Singature_Profiles_Dict)
			time.sleep(1.5)
		#Checks if DNS Flood profile is requierd 
		if DNS_Flood_Profiles_Dict:
			self.DNS_Flood_profile_config(dp_ip, DNS_Flood_Profiles_Dict)
			time.sleep(1.5)
		#Checks if NTP Server is requierd 
		if NTP_Flag:
			self.NTP_server_config(dp_ip, NTP_Flag)
			time.sleep(1.5)
		#Checks if Syslog Server is requierd 
		if Syslog_Flag:
			self.Syslog_server_config(dp_ip, Syslog_Flag)
			time.sleep(1.5)
		#Checks if EAAF Protection is requierd 
		if EAAF_Profile:
			self.EAAF_profile_config(dp_ip, EAAF_Profile)
			time.sleep(1.5)
		else:
			print("EAAF Protection --> Disabled")

		print("Policy Configurations Summary:\n")
		print(f"Configure DP: {dp_ip}:\n")
		for index in range(len(Policy_config_file)):
			url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSNewRulesTable/{Policy_config_file[index]['rsIDSNewRulesName']}/"
			Policy_profile_body = json.dumps(Policy_config_file[index])
			response = self.session.post(url, data=Policy_profile_body, verify=False)
			if response.status_code == 200:
				print(f"Creating Policy: {Policy_config_file[index]['rsIDSNewRulesName']} --> {response.status_code}")
			elif response.status_code == 500:
				if "not found" in json.loads(response.text)['message'].split(':')[1]:
					print(f"Error in Creating Policy: {Policy_config_file[index]['rsIDSNewRulesName']} --> {json.loads(response.text)['message'].split(':')[1]}")
				elif "valid" in json.loads(response.text)['message'].split(':')[1]:
					print(f"Error in Creating Policy: {Policy_config_file[index]['rsIDSNewRulesName']} --> {json.loads(response.text)['message'].split(':')[1]}")
		print("\n"+"*"*30+"\n")

	def Del_Policy_config(self, dp_ip):
		Policy_list = self.config_file.get_Policies_list()
		print("Policy Configurations\n")
		for index in range(len(Policy_list)):
			policy_name = Policy_list[index]
			url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSNewRulesTable/{policy_name}/"
			response = self.session.delete(url, verify=False)
			print(f"Delete Policy: {Policy_list[index]} --> {response.status_code}")
		print("\n"+"*"*30+"\n")

	def Del_BdoS_config(self, dp_ip):
		Policy_config_file = self.config_file.create_Protections_Per_Policy_dic()
		#print(Policy_config_file)
		print("Delete BDoS Configurations\n")
		for index in range(len(Policy_config_file)):
			policy_name = f"{Policy_config_file[index]['rsIDSNewRulesName']}_auto_BDoS".split("_B")
			bdos_profile_name = f"{policy_name[0]}_auto_BDoS"
			url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsNetFloodProfileTable/{bdos_profile_name}/"
			response = self.session.delete(url, verify=False)
			print(f"Delete BDoS: {Policy_config_file[index]['rsIDSNewRulesName']} --> {response.status_code}")
		print("\n"+"*"*30+"\n")

	def Del_OOS_config(self, dp_ip):
		Policy_config_file = self.config_file.create_Protections_Per_Policy_dic()
		#print(Policy_config_file)
		print("Delete OOS Configurations\n")
		for index in range(len(Policy_config_file)):
			policy_name = f"{Policy_config_file[index]['rsIDSNewRulesName']}_auto_oos".split("_B")
			oos_profile_name = f"{policy_name[0]}_auto_oos"
			url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsStatefulProfileTable/{oos_profile_name}/"
			response = self.session.delete(url, verify=False)
			print(f"Delete OOS: {oos_profile_name} --> {response.status_code}")
		print("\n"+"*"*30+"\n")

	def Del_AS_config(self, dp_ip):
		Policy_config_file = self.config_file.create_Protections_Per_Policy_dic()
		print("Delete OOS Configurations\n")
		for index in range(len(Policy_config_file)):
			policy_name = f"{Policy_config_file[index]['rsIDSNewRulesName']}_auto_as".split("_B")
			as_profile_name = f"{policy_name[0]}_auto_as"
			url = f"https://{self.ip}/mgmt/device/byip/{dp_ip}/config/rsIDSScanningProfilesTable/{as_profile_name}/"
			response = self.session.delete(url, verify=False)
			print(f"Delete AS: {as_profile_name} --> {response.status_code}")
		print("\n"+"*"*30+"\n")
	
	def Delete_configuration(self, dp_ip):
	   delay_time = 2.5
	   self.lock_device(dp_ip)
	   time.sleep(delay_time)
	   self.Del_Policy_config(dp_ip)
	   time.sleep(delay_time)
	   self.Del_BdoS_config(dp_ip)
	   time.sleep(delay_time)
	   self.Del_OOS_config(dp_ip)
	   time.sleep(delay_time)
	   self.Del_AS_config(dp_ip)
	   time.sleep(delay_time)
	   self.update_policy(dp_ip)

def DP_config(vision_obj,dp_ip):

	vision_obj.lock_device(dp_ip)
	time.sleep(1.5)
	vision_obj.net_class_config(dp_ip)
	vision_obj.Protection_config(dp_ip)
	vision_obj.Policy_config(dp_ip)
	vision_obj.update_policy(dp_ip)
	time.sleep(3.0)

def BP_Tool_run(vision_obj,DP_list):
	start_runtime = timeit.default_timer()
	for index in range(len(DP_list)):
	 DP_config(vision_obj,DP_list[index])
	stop_runtime = timeit.default_timer()
	print('Running Time: ', stop_runtime - start_runtime)


