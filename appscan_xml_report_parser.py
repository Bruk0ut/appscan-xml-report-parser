#!/usr/bin/python
"""
Title: IBM AppScan XML Report Parser

Author: Mike Arnold (bruk0ut.sec :@: gmail.com)

Purpose: Parse IBM AppScan generated XML reports and create spreadsheet, tabs split per vulnerability severity

Required Packages: xlsxwriter, lxml

Notes: Tested against AppScan version 9.0.3.7 - non credentialed scans and 1 SITE PER XML REPORT!

Notes: To generate an AppScan XML report from fresh scan -> AppScanCMD.exe e /su http://host/ /rf path_to_output_xml_file.xml /rtm DetailedReport /rt xml /v
Notes: To generate an AppScan XML report from existing .scan file -> AppScanCMD.exe report /base_scan path_to_.scan_file.scan -report_file path_to_output_xml_file.xml /report_type xml
"""
from lxml import etree as ET
import sys, pprint, os, xlsxwriter, datetime

def usage():
	print "Usage: Place all AppScan XML report files which are to be parsed, into the same directory as " + sys.argv[0] + " then run."
	
def get_xml_files():
	xml_file_array = []
	files_in_dir = os.listdir(".")
	found_xml_count = 0
	for file in files_in_dir:
		if file.lower().find(".xml") > -1:
			found_xml_count +=1
			xml_file_array.append(file)
	if found_xml_count == 0:
		print "[-] Error - no .xml files found in current directory! Quiting..."
		usage()
		sys.exit()
	else:
		print "[+] Found " + str(found_xml_count) + " xml files to parse"
		return xml_file_array


def open_xml_file(xml_file):
	fcontents = open(xml_file,'r')
	contents = fcontents.read()
	fcontents.close()
	
	return (ET.XML(contents))

def get_main_scan_summary_info(xml_root,xml_file,debug_log):
	try:
		hostname = ""
		total_low_sev_count = ""
		total_med_sev_count = ""
		total_high_sev_count = ""
		
		summaryinfo = xml_root.find('Summary/Hosts')
		if summaryinfo is not None:
			for child in summaryinfo.iter():
				if child.tag=="Host":
					hostname = child.attrib['Name']
				elif child.tag=="TotalLowSeverityIssues" and child.text:
					total_low_sev_count = child.text
				elif child.tag=="TotalMediumSeverityIssues" and child.text:
					total_med_sev_count = child.text
				elif child.tag=="TotalHighSeverityIssues" and child.text:
					total_high_sev_count = child.text
			
			#check we have all props, if so break out the loop by returning the props in a dict
			if (hostname != "" and total_low_sev_count != "" and total_med_sev_count != "" and total_high_sev_count != ""):
				return debug_log,{"hostname": hostname,"total_low_sev_count": total_low_sev_count,"total_med_sev_count": total_med_sev_count,"total_high_sev_count": total_high_sev_count}

		#error as we should never reach here
		print "[-] Error - could not parse summary stats from xml report?"
		debug_log += "[-] Error - could not parse summary stats from xml report? in " + xml_file + "\r\n\r\n\r\n"
		return debug_log,{"hostname": "N/A - Bad Report File","total_low_sev_count": 0,"total_med_sev_count": 0,"total_high_sev_count": 0}
	except Exception, e:
		print "[-] Error - could not parse summary stats from xml report?"
		debug_log += "[-] Error - could not parse summary stats from xml report? in " + xml_file + "\n"
		debug_log += "[-] Error exception details" + str(e) + "\n\n\n"
		return debug_log,{"hostname": "N/A - Bad Report File","total_low_sev_count": 0,"total_med_sev_count": 0,"total_high_sev_count": 0}

def get_remediation_info(xml_root,xml_file,debug_log):
	try:
		remediationinfo = xml_root.find('Results/RemediationTypes')
		remediation_name_and_additional_info = ""
		fix_id = ""
		remediation_info_array = []
		if remediationinfo is not None:
			for child in remediationinfo.iter():
				if child.tag=="RemediationType":
					#check if this fix_id has already been added to the array
					this_remediation_is_in_array = False
					for remediation_element in remediation_info_array:
						if fix_id == remediation_element["remediation_fix_id"]:
							this_remediation_is_in_array = True

					if fix_id!="" and not this_remediation_is_in_array:
						#we have come to end of this section, so add remediation info and fix_id to array then reset the vars for the next one
						#print "adding " + fix_id  
						remediation_info_array.append({'remediation_fix_id':fix_id,'remediation_name_and_additional_info':remediation_name_and_additional_info})
						#remediation_name_and_additional_info = ""					

					#grab the fix_id
					fix_id = child.attrib['ID']
					
				elif child.tag=="Name" and child.text:
					#grab the remediation name
					remediation_name_and_additional_info = child.text.replace('\n'," | ")

				elif child.tag =="text" and child.text:
					#grab the remediation additional info
					remediation_name_and_additional_info +=  " | " + child.text.replace('\n'," | ")
					if child.getnext() is None:
						this_remediation_is_in_array = False
						for remediation_element in remediation_info_array:
							if fix_id == remediation_element["remediation_fix_id"]:
								this_remediation_is_in_array = True
						if not this_remediation_is_in_array:
							#we are on the last recommendation and it's not already been submitted, so submit it to the array
							remediation_info_array.append({'remediation_fix_id':fix_id,'remediation_name_and_additional_info':remediation_name_and_additional_info})
											
				elif child.tag =="indentText" and child.text:
					#grab the remediation additional info
					remediation_name_and_additional_info +=  " | " + child.text.replace('\n'," | ")
					if child.getnext() is None:
						this_remediation_is_in_array = False
						for remediation_element in remediation_info_array:
							if fix_id == remediation_element["remediation_fix_id"]:
								this_remediation_is_in_array = True
						if not this_remediation_is_in_array:
							#we are on the last recommendation and it's not already been submitted, so submit it to the array
							remediation_info_array.append({'remediation_fix_id':fix_id,'remediation_name_and_additional_info':remediation_name_and_additional_info})

				elif child.tag =="link" and child.text:
					#grab the remediation additional info
					remediation_name_and_additional_info +=  " | " + child.text.replace('\n'," | ")
					if child.getnext() is None:
						this_remediation_is_in_array = False
						for remediation_element in remediation_info_array:
							if fix_id == remediation_element["remediation_fix_id"]:
								this_remediation_is_in_array = True
						if not this_remediation_is_in_array:
							#we are on the last recommendation and it's not already been submitted, so submit it to the array
							remediation_info_array.append({'remediation_fix_id':fix_id,'remediation_name_and_additional_info':remediation_name_and_additional_info})


			print "[+] Parsed " + str(len(remediation_info_array)) + " remediation entries..."
			return debug_log,remediation_info_array
		else:
			print "[-] Error - could not find remediation info in xml file " + xml_file
			debug_log +="[-] Error - could not find remediation info in xml file " + xml_file + "\n\n\n"
			return debug_log,[]
	
	except Exception, e:
		print "[-] Error - could not find remediation info in xml file " + xml_file
		debug_log +="[-] Error - could not find remediation info in xml file " + xml_file + "\n"	
		debug_log += "[-] Error exception details" + str(e) + "\n\n\n"
		return debug_log,[]
		
		
def get_advisory_info(xml_root,xml_file,remediation_info_array,debug_log):
	try:
		advisoryinfo = xml_root.find('Results/IssueTypes')
		advisory_remediation_fix_id_ref = ""
		advisory_issuetype_id =""
		advisory_name = ""
		advisory_threatclassification_and_additional_info = ""
		advisory_cause = ""
		advisory_risk = ""
		advisory_info_array = []

		if advisoryinfo is not None:
			for child in advisoryinfo.iter():
				if child.tag=="RemediationID" and child.text:
					#reset section_completed flag to prevent additional text and indentText fields being appended
					section_completed = False
					for fix_id in remediation_info_array:
						#get the advisory_issuetype_id for this remedation fix_id. this is just a precationary binding check
						if child.text == fix_id["remediation_fix_id"]:
							advisory_remediation_fix_id_ref = fix_id["remediation_fix_id"]
							advisory_issuetype_id = child.getparent().attrib["ID"]

				elif child.tag=="name" and child.getparent().tag=="advisory" and child.text:
					advisory_name = child.text.replace('\n'," | ")
					
				elif child.tag=="name" and child.getparent().tag=="threatClassification" and child.text:
					advisory_threatclassification_and_additional_info = child.text.replace('\n'," | ")

				elif child.tag=="text" and child.text and not section_completed:
					advisory_threatclassification_and_additional_info += " | " + child.text.replace('\n'," | ")			

				elif child.tag=="indentText" and child.text and not section_completed:
					advisory_threatclassification_and_additional_info += " | " + child.text.replace('\n'," | ")	

				elif child.tag=="cause" and child.text:
					advisory_cause = child.text.replace('\n'," | ")

				elif child.tag=="securityRisk" and child.text:
					advisory_risk = child.text.replace('\n'," | ")

				elif child.tag=="affectedProduct":
					#end of section has been reached as far as advisory details is concerned. set flag
					section_completed = True
					advisory_info_array.append({'advisory_remediation_fix_id_ref':advisory_remediation_fix_id_ref,'advisory_issuetype_id':advisory_issuetype_id,'advisory_name':advisory_name,'advisory_threatclassification_and_additional_info':advisory_threatclassification_and_additional_info,'advisory_cause':advisory_cause,'advisory_risk':advisory_risk})
					
					
			print "[+] Parsed " + str(len(advisory_info_array)) + " advisory entries..."
			return debug_log,advisory_info_array
		else:
			print "[-] Error - could not find advisory info in xml file " + xml_file
			debug_log +="[-] Error - could not find advisory info in xml file " + xml_file + "\n\n\n"		
			return debug_log,[]
	
	except Exception, e:
		print "[-] Error - could not find advisory info in xml file " + xml_file
		debug_log +="[-] Error - could not find advisory info in xml file " + xml_file + "\n"	
		debug_log += "[-] Error exception details" + str(e) + "\n\n\n"
		return debug_log,[]

def get_issue_info_and_write_excel_data_in_memory(xml_root,xml_file,summary_info_dict,remediation_info_array,advisory_info_array,high_sev_count,med_sev_count,low_sev_count,debug_log):
	try:
		issuesinfo = xml_root.find('Results/Issues')
		issue_issuetype_id =""
		issue_url =""
		issue_severity =""
		issue_cvss =""
		issue_entity =""
		issue_reasoning =""
		issue_original_http_traffic =""
		issue_test_http_traffic =""
		issue_count = 0
		
		#add to total issue counts for final summary of all docs
		high_sev_count += int(summary_info_dict["total_high_sev_count"])
		med_sev_count += int(summary_info_dict["total_med_sev_count"])
		low_sev_count += int(summary_info_dict["total_low_sev_count"])
				
		if issuesinfo is not None:
			for child in issuesinfo.iter():
				if child.tag=="Issue":
					for issuetype_id in advisory_info_array:
						#find the matching advisory_issue_type_id for the issue_IssueTypeID so the advisory and issues can be binded correctly.
						if child.attrib["IssueTypeID"] == issuetype_id["advisory_issuetype_id"]:
							issue_issuetype_id = child.attrib["IssueTypeID"]
							#reset the issues variables for this new issue
							issue_url =""
							issue_severity =""
							issue_cvss =""
							issue_entity =""
							issue_reasoning =""
							issue_original_http_traffic =""
							issue_test_http_traffic =""
				
				elif child.tag=="Url" and child.getparent().tag=="Issue" and child.text:
					issue_url = child.text
				

				elif child.tag=="Severity" and child.getparent().tag=="Issue" and child.text:
					issue_severity = child.text
					
				elif child.tag=="Score" and child.getparent().tag=="CVSS" and child.text:
					issue_cvss = child.text
									
				#watch this, might not be safe to use. if so just remove it
				elif child.tag=="Entity" and child.getparent().tag=="Issue":
					issue_entity = pprint.pformat(child.attrib.items()).replace('\n'," | ")
					
				#we only want to extract one instance of test variant data, so check if reasoning is already populated			
				elif child.tag=="Reasoning" and issue_reasoning == "" and child.text:
					issue_reasoning = child.text.replace('\n'," | ")

				#we only want to extract one instance of test variant data, so check if OG HTTP traffic is already populated			
				elif child.tag=="OriginalHttpTraffic" and issue_original_http_traffic == "" and child.text:
					issue_original_http_traffic = child.text.encode('utf-8')
					
				#we only want to extract one instance of test variant data, so check if test HTTP traffic is already populated			
				if child.tag=="TestHttpTraffic" and child.text is not None and child.text.replace('\n'," | "):
					#this is our last check before commiting an entry to excel in memory and flushing for the next xml report file
					if issue_test_http_traffic != "":
						#do nothing, we've already committed this issue to excel memory
						sys.stdout.write(".")
					else:
						#we've not submitted this issue to excel memory yet and this is the last element of the this issue. now commit all if severity is not just "informational".
						issue_test_http_traffic = child.text.encode('utf-8')
						if issue_severity != "Informational":
							#build excel array row accordingly, based on severity
							issue_count +=1
							
							for advisory in advisory_info_array:						
								if issue_issuetype_id == advisory["advisory_issuetype_id"]:
									#found matching advisory for this issue
									#now find matching remediation:
									for remediation in remediation_info_array:
										if advisory["advisory_remediation_fix_id_ref"] == remediation["remediation_fix_id"]:
											#found matching remediation fix id, now we can commit the row to excel memory

											if issue_severity == "High":
												
												high_severity_excel_row_array.append({'hostname':summary_info_dict["hostname"],'issue_severity':issue_severity,'issue_cvss':issue_cvss,'issue_reasoning':issue_reasoning,'advisory_name':advisory["advisory_name"],'advisory_risk':advisory["advisory_risk"],'advisory_cause':advisory["advisory_cause"],'advisory_threatclassification_and_additional_info':advisory["advisory_threatclassification_and_additional_info"],'issue_url':issue_url,'issue_entity':issue_entity,'remediation_name_and_additional_info':remediation["remediation_name_and_additional_info"],'issue_original_http_traffic':issue_original_http_traffic,'issue_test_http_traffic':issue_test_http_traffic,'xml_file':xml_file})
												issue_issuetype_id =""#(extracted from remediation_fix_id)
																						
											elif issue_severity == "Medium":
												
												medium_severity_excel_row_array.append({'hostname':summary_info_dict["hostname"],'issue_severity':issue_severity,'issue_cvss':issue_cvss,'issue_reasoning':issue_reasoning,'advisory_name':advisory["advisory_name"],'advisory_risk':advisory["advisory_risk"],'advisory_cause':advisory["advisory_cause"],'advisory_threatclassification_and_additional_info':advisory["advisory_threatclassification_and_additional_info"],'issue_url':issue_url,'issue_entity':issue_entity,'remediation_name_and_additional_info':remediation["remediation_name_and_additional_info"],'issue_original_http_traffic':issue_original_http_traffic,'issue_test_http_traffic':issue_test_http_traffic,'xml_file':xml_file})
												issue_issuetype_id =""#(extracted from remediation_fix_id)
												
											elif issue_severity == "Low":
												
												low_severity_excel_row_array.append({'hostname':summary_info_dict["hostname"],'issue_severity':issue_severity,'issue_cvss':issue_cvss,'issue_reasoning':issue_reasoning,'advisory_name':advisory["advisory_name"],'advisory_risk':advisory["advisory_risk"],'advisory_cause':advisory["advisory_cause"],'advisory_threatclassification_and_additional_info':advisory["advisory_threatclassification_and_additional_info"],'issue_url':issue_url,'issue_entity':issue_entity,'remediation_name_and_additional_info':remediation["remediation_name_and_additional_info"],'issue_original_http_traffic':issue_original_http_traffic,'issue_test_http_traffic':issue_test_http_traffic,'xml_file':xml_file})
												issue_issuetype_id =""#(extracted from remediation_fix_id)
																
			print ""
			print "[+] XML doc has " + summary_info_dict["total_high_sev_count"] + " high severity issues"
			print "[+] XML doc has " + summary_info_dict["total_med_sev_count"] + " medium severity issues"
			print "[+] XML doc has " + summary_info_dict["total_low_sev_count"] + " low severity issues"
			print "[+] Will add " + str(issue_count) + " non informational issues to master Excel spreadsheet..."
				
			#check if any and all issues were parsed as expected
			if issue_count == 0:
				debug_log += "[-] Error - did not add any issues for xml file " + xml_file + "\n\n\n"
				return debug_log,high_severity_excel_row_array,medium_severity_excel_row_array,low_severity_excel_row_array,high_sev_count,med_sev_count,low_sev_count
				
			elif issue_count < (int(summary_info_dict["total_high_sev_count"]) + int(summary_info_dict["total_med_sev_count"]) + int(summary_info_dict["total_low_sev_count"])):
				debug_log += "[-] Warning - possible parsing issue. Could not parse all issues:\n"
				debug_log += "[-] " + xml_file + " had " +  summary_info_dict["total_high_sev_count"] + " high severity issues\n"
				debug_log += "[-] " + xml_file + " had " +  summary_info_dict["total_med_sev_count"] + " medium severity issues\n"
				debug_log += "[-] " + xml_file + " had " +  summary_info_dict["total_low_sev_count"] + " low severity issues\n"				
				debug_log += "[-] But only " + str(issue_count) + " issues were parsed and added to report\n\n\n"
				return debug_log,high_severity_excel_row_array,medium_severity_excel_row_array,low_severity_excel_row_array,high_sev_count,med_sev_count,low_sev_count				
	
			else:
				return debug_log,high_severity_excel_row_array,medium_severity_excel_row_array,low_severity_excel_row_array,high_sev_count,med_sev_count,low_sev_count
			
	except Exception, e:
		debug_log += "[-] Error processing issue details in " + xml_file + "\n"
		debug_log += "[-] Error exception details" + str(e) + "\n\n\n"
		return debug_log,[]

def create_excel_master_file(high_severity_excel_row_array,medium_severity_excel_row_array,low_severity_excel_row_array,high_sev_count,med_sev_count,low_sev_count,report_count,debug_log):
	try:
		filename = "AppScan_Results_" + datetime.datetime.now().strftime("%m_%d_%y_%H%M") + ".xlsx"
		print "[+] Generating XLSX file"
		#set props
		workbook = xlsxwriter.Workbook(filename)
		bold = workbook.add_format({'bold': True})
		uline = workbook.add_format({'underline': True})

		#add worksheets
		summary_worksheet = workbook.add_worksheet('Summary')
		high_sev_worksheet = workbook.add_worksheet('High_Severity')
		medium_sev_worksheet = workbook.add_worksheet('Medium_Severity')
		low_sev_worksheet = workbook.add_worksheet('Low_Severity')

		summary_worksheet.set_tab_color('black')
		high_sev_worksheet.set_tab_color('red')
		medium_sev_worksheet.set_tab_color('orange')
		low_sev_worksheet.set_tab_color('green')

		#write summary sheet
		summary_worksheet.write(0,0,"Summary_Count_of_Issues",bold)
		summary_worksheet.write(0,1,"Count",bold)
		summary_worksheet.write(1,0,"Total_High_Severity_Issues",uline)
		summary_worksheet.write(1,1,high_sev_count)
		summary_worksheet.write(2,0,"Total_Medium_Severity_Issues",uline)
		summary_worksheet.write(2,1,med_sev_count)
		summary_worksheet.write(3,0,"Total_Low_Severity_Issues",uline)
		summary_worksheet.write(3,1,low_sev_count)
		summary_worksheet.write(4,0,"Total_Number_Of_Sites_Scanned_With_AppScan",uline)
		summary_worksheet.write(4,1,report_count)
		summary_worksheet.set_column(0,0,len("Total_Number_Of_Sites_Scanned_With_AppScan"))

		#write high severity sheet
		high_sev_worksheet.write(0,0,"Hostname",bold)
		high_sev_worksheet.set_column(0,0,len("Hostname"))
		high_sev_worksheet.write(0,1,"Issue_Severity",bold)
		high_sev_worksheet.set_column(1,0,len("Issue_Severity"))
		high_sev_worksheet.write(0,2,"Issue_CVSS_Score",bold)
		high_sev_worksheet.set_column(2,0,len("Issue_CVSS_Score"))
		high_sev_worksheet.write(0,3,"Reason_for_Suspicion",bold)
		high_sev_worksheet.set_column(3,0,len("Reason_for_Suspicion"))
		high_sev_worksheet.write(0,4,"Advisory_Name",bold)
		high_sev_worksheet.set_column(4,0,len("Advisory_Name"))
		high_sev_worksheet.write(0,5,"Advisory_Risk",bold)
		high_sev_worksheet.set_column(5,0,len("Advisory_Risk"))
		high_sev_worksheet.write(0,6,"Advisory_Cause",bold)
		high_sev_worksheet.set_column(6,0,len("Advisory_Cause"))
		high_sev_worksheet.write(0,7,"Advisory_Info",bold)
		high_sev_worksheet.set_column(7,0,len("Advisory_Info"))
		high_sev_worksheet.write(0,8,"Affected_URL",bold)
		high_sev_worksheet.set_column(8,0,len("Affected_URL"))
		high_sev_worksheet.write(0,9,"Affected_HTML_Entity",bold)
		high_sev_worksheet.set_column(9,0,len("Affected_HTML_Entity"))
		high_sev_worksheet.write(0,10,"Remediation_Info",bold)
		high_sev_worksheet.set_column(10,0,len("Remediation_Info"))
		high_sev_worksheet.write(0,11,"XML_Report_Filename",bold)
		high_sev_worksheet.set_column(11,0,len("XML_Report_Filename"))
		high_sev_worksheet.write(0,12,"Original_HTTP_Traffic",bold)
		high_sev_worksheet.set_column(12,0,len("Original_HTTP_Traffic"))
		high_sev_worksheet.write(0,13,"Test_HTTP_Traffic",bold)
		high_sev_worksheet.set_column(13,0,len("Test_HTTP_Traffic"))
		

		row = 1
		for issue in high_severity_excel_row_array:
			high_sev_worksheet.write(row,0,issue["hostname"])
			high_sev_worksheet.write(row,1,issue["issue_severity"])
			high_sev_worksheet.write(row,2,issue["issue_cvss"])
			high_sev_worksheet.write(row,3,issue["issue_reasoning"])
			high_sev_worksheet.write(row,4,issue["advisory_name"])
			high_sev_worksheet.write(row,5,issue["advisory_risk"])
			high_sev_worksheet.write(row,6,issue["advisory_cause"])
			high_sev_worksheet.write(row,7,issue["advisory_threatclassification_and_additional_info"])
			high_sev_worksheet.write(row,8,issue["issue_url"])
			high_sev_worksheet.write(row,9,issue["issue_entity"])
			high_sev_worksheet.write(row,10,issue["remediation_name_and_additional_info"])
			high_sev_worksheet.write(row,11,issue["xml_file"])
			high_sev_worksheet.write(row,12,issue["issue_original_http_traffic"].decode('utf-8'))
			high_sev_worksheet.write(row,13,issue["issue_test_http_traffic"].decode('utf-8'))
			row +=1
		
		#apply auto filter
		high_sev_worksheet.autofilter(0,0,row,13)	
			
		#write medium severity sheet
		medium_sev_worksheet.write(0,0,"Hostname",bold)
		medium_sev_worksheet.set_column(0,0,len("Hostname"))
		medium_sev_worksheet.write(0,1,"Issue_Severity",bold)
		medium_sev_worksheet.set_column(1,0,len("Issue_Severity"))
		medium_sev_worksheet.write(0,2,"Issue_CVSS_Score",bold)
		medium_sev_worksheet.set_column(2,0,len("Issue_CVSS_Score"))
		medium_sev_worksheet.write(0,3,"Reason_for_Suspicion",bold)
		medium_sev_worksheet.set_column(3,0,len("Reason_for_Suspicion"))
		medium_sev_worksheet.write(0,4,"Advisory_Name",bold)
		medium_sev_worksheet.set_column(4,0,len("Advisory_Name"))
		medium_sev_worksheet.write(0,5,"Advisory_Risk",bold)
		medium_sev_worksheet.set_column(5,0,len("Advisory_Risk"))
		medium_sev_worksheet.write(0,6,"Advisory_Cause",bold)
		medium_sev_worksheet.set_column(6,0,len("Advisory_Cause"))
		medium_sev_worksheet.write(0,7,"Advisory_Info",bold)
		medium_sev_worksheet.set_column(7,0,len("Advisory_Info"))
		medium_sev_worksheet.write(0,8,"Affected_URL",bold)
		medium_sev_worksheet.set_column(8,0,len("Affected_URL"))
		medium_sev_worksheet.write(0,9,"Affected_HTML_Entity",bold)
		medium_sev_worksheet.set_column(9,0,len("Affected_HTML_Entity"))
		medium_sev_worksheet.write(0,10,"Remediation_Info",bold)
		medium_sev_worksheet.set_column(10,0,len("Remediation_Info"))
		medium_sev_worksheet.write(0,11,"XML_Report_Filename",bold)
		medium_sev_worksheet.set_column(11,0,len("XML_Report_Filename"))
		medium_sev_worksheet.write(0,12,"Original_HTTP_Traffic",bold)
		medium_sev_worksheet.set_column(12,0,len("Original_HTTP_Traffic"))
		medium_sev_worksheet.write(0,13,"Test_HTTP_Traffic",bold)
		medium_sev_worksheet.set_column(13,0,len("Test_HTTP_Traffic"))
		
		row = 1
		for issue in medium_severity_excel_row_array:
			medium_sev_worksheet.write(row,0,issue["hostname"])
			medium_sev_worksheet.write(row,1,issue["issue_severity"])
			medium_sev_worksheet.write(row,2,issue["issue_cvss"])
			medium_sev_worksheet.write(row,3,issue["issue_reasoning"])
			medium_sev_worksheet.write(row,4,issue["advisory_name"])
			medium_sev_worksheet.write(row,5,issue["advisory_risk"])
			medium_sev_worksheet.write(row,6,issue["advisory_cause"])
			medium_sev_worksheet.write(row,7,issue["advisory_threatclassification_and_additional_info"])
			medium_sev_worksheet.write(row,8,issue["issue_url"])
			medium_sev_worksheet.write(row,9,issue["issue_entity"])
			medium_sev_worksheet.write(row,10,issue["remediation_name_and_additional_info"])
			medium_sev_worksheet.write(row,11,issue["xml_file"])
			medium_sev_worksheet.write(row,12,issue["issue_original_http_traffic"].decode('utf-8'))
			medium_sev_worksheet.write(row,13,issue["issue_test_http_traffic"].decode('utf-8'))
			row +=1

		#apply auto filter
		medium_sev_worksheet.autofilter(0,0,row,13)

		#write low severity sheet
		low_sev_worksheet.write(0,0,"Hostname",bold)
		low_sev_worksheet.set_column(0,0,len("Hostname"))
		low_sev_worksheet.write(0,1,"Issue_Severity",bold)
		low_sev_worksheet.set_column(1,0,len("Issue_Severity"))
		low_sev_worksheet.write(0,2,"Issue_CVSS_Score",bold)
		low_sev_worksheet.set_column(2,0,len("Issue_CVSS_Score"))
		low_sev_worksheet.write(0,3,"Reason_for_Suspicion",bold)
		low_sev_worksheet.set_column(3,0,len("Reason_for_Suspicion"))
		low_sev_worksheet.write(0,4,"Advisory_Name",bold)
		low_sev_worksheet.set_column(4,0,len("Advisory_Name"))
		low_sev_worksheet.write(0,5,"Advisory_Risk",bold)
		low_sev_worksheet.set_column(5,0,len("Advisory_Risk"))
		low_sev_worksheet.write(0,6,"Advisory_Cause",bold)
		low_sev_worksheet.set_column(6,0,len("Advisory_Cause"))
		low_sev_worksheet.write(0,7,"Advisory_Info",bold)
		low_sev_worksheet.set_column(7,0,len("Advisory_Info"))
		low_sev_worksheet.write(0,8,"Affected_URL",bold)
		low_sev_worksheet.set_column(8,0,len("Affected_URL"))
		low_sev_worksheet.write(0,9,"Affected_HTML_Entity",bold)
		low_sev_worksheet.set_column(9,0,len("Affected_HTML_Entity"))
		low_sev_worksheet.write(0,10,"Remediation_Info",bold)
		low_sev_worksheet.set_column(10,0,len("Remediation_Info"))
		low_sev_worksheet.write(0,11,"XML_Report_Filename",bold)
		low_sev_worksheet.set_column(11,0,len("XML_Report_Filename"))
		low_sev_worksheet.write(0,12,"Original_HTTP_Traffic",bold)
		low_sev_worksheet.set_column(12,0,len("Original_HTTP_Traffic"))
		low_sev_worksheet.write(0,13,"Test_HTTP_Traffic",bold)
		low_sev_worksheet.set_column(13,0,len("Test_HTTP_Traffic"))		
		
		row = 1
		for issue in low_severity_excel_row_array:
			low_sev_worksheet.write(row,0,issue["hostname"])
			low_sev_worksheet.write(row,1,issue["issue_severity"])
			low_sev_worksheet.write(row,2,issue["issue_cvss"])
			low_sev_worksheet.write(row,3,issue["issue_reasoning"])
			low_sev_worksheet.write(row,4,issue["advisory_name"])
			low_sev_worksheet.write(row,5,issue["advisory_risk"])
			low_sev_worksheet.write(row,6,issue["advisory_cause"])
			low_sev_worksheet.write(row,7,issue["advisory_threatclassification_and_additional_info"])
			low_sev_worksheet.write(row,8,issue["issue_url"])
			low_sev_worksheet.write(row,9,issue["issue_entity"])
			low_sev_worksheet.write(row,10,issue["remediation_name_and_additional_info"])
			low_sev_worksheet.write(row,11,issue["xml_file"])
			low_sev_worksheet.write(row,12,issue["issue_original_http_traffic"].decode('utf-8'))
			low_sev_worksheet.write(row,13,issue["issue_test_http_traffic"].decode('utf-8'))
			row +=1

		#apply auto filter
		low_sev_worksheet.autofilter(0,0,row,13)
			
		workbook.close()
		print "[+] XLSX Created - " + filename
		return debug_log

	except Exception, e:
		debug_log += "[-] Error creating spreadsheet...\n"
		debug_log += "[-] Error exception details" + str(e) + "\n"
		return debug_log
				
if __name__=="__main__":
	os.system("clear")
	if len(sys.argv) >1:
		usage()
		sys.exit()
	xml_file_list = get_xml_files()
	debug_log = ""
	low_severity_excel_row_array = []
	medium_severity_excel_row_array = []
	high_severity_excel_row_array = []
	high_sev_count = 0
	med_sev_count = 0
	low_sev_count = 0
	report_count = 0
	for xml_file in xml_file_list:		
		print "[+] Working on " + xml_file + "..."
		xml_root = open_xml_file(xml_file)
		
		#get main scan summary info
		debug_log,summary_info_dict = get_main_scan_summary_info(xml_root,xml_file,debug_log)
		#only proceed with parsing if there are actual issues and not a dud XML report
		if (int(summary_info_dict["total_high_sev_count"]) + int(summary_info_dict["total_med_sev_count"]) + int(summary_info_dict["total_low_sev_count"]) == 0):
			print "[-] Skipping this XML file. No issues were found"
			continue
		
		#get remediation info
		debug_log,remediation_info_array = get_remediation_info(xml_root,xml_file,debug_log)
		
		#get advisory info
		debug_log,advisory_info_array = get_advisory_info(xml_root,xml_file,remediation_info_array,debug_log)
		
		#get issue info then write excel data in memory for this xml report
		debug_log,high_severity_excel_row_array,medium_severity_excel_row_array,low_severity_excel_row_array,high_sev_count,med_sev_count,low_sev_count = get_issue_info_and_write_excel_data_in_memory(xml_root,xml_file,summary_info_dict,remediation_info_array,advisory_info_array,high_sev_count,med_sev_count,low_sev_count,debug_log)
		
		report_count+=1
	
	#write the excel file to disk
	debug_log = create_excel_master_file(high_severity_excel_row_array,medium_severity_excel_row_array,low_severity_excel_row_array,high_sev_count,med_sev_count,low_sev_count,report_count,debug_log)

	#check debug_log for any content:
	if debug_log != "":
		tmpfile = open("debug_log.txt","w")
		tmpfile.write(debug_log)
		tmpfile.close()
		print "[-] Warning: debug log has entries, check debug_log.txt for parsing problems"
