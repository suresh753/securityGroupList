#!/usr/local/bin/python3
from __future__ import print_function

import json
import boto3

def lambda_handler(event, context):
	#Explicitly declaring variables here grants them global scope
	cidr_block = ""
	ip_protpcol = ""
	from_port = ""
	to_port = ""
	from_source = ""

	#print("%s,%s,%s,%s,%s,%s" % ("Group-Name","Group-ID","In/Out","Protocol","Port","Source/Destination"))

	for region in ["us-east-1"]:
		ec2=boto3.client('ec2', region )
		sgs = ec2.describe_security_groups(Filters=[{'Name':'vpc-id','Values':['vpc-4c8b3737']},],)["SecurityGroups"]
		for sg in sgs:
			group_name = sg['GroupName']
			group_id = sg['GroupId']
			#print("%s,%s" % (group_name,group_id))
			inbound = sg['IpPermissions']
			#print (inbound)
			#print("%s,%s,%s" % ("","","Inbound"))
			for rule in inbound:
				if rule['IpProtocol'] == "-1":
					traffic_type="All Trafic"
					ip_protpcol="All"
					to_port="All"
				else:
					ip_protpcol = rule['IpProtocol']
					from_port=rule['FromPort']
					to_port=rule['ToPort']
					#If ICMP, report "N/A" for port #
					if to_port == -1:
						to_port = "N/A"

				#Is source/target an IP v4?
				if len(rule['IpRanges']) > 0:
					for ip_range in rule['IpRanges']:
						cidr_block = ip_range['CidrIp']
						print("%s,%s,%s,%s,%s" % (sg['GroupName'],sg['GroupId'],ip_protpcol, to_port, cidr_block))

				#Is source/target an IP v6?
				if len(rule['Ipv6Ranges']) > 0:
					for ip_range in rule['Ipv6Ranges']:
						cidr_block = ip_range['CidrIpv6']
						print("%s,%s,%s,%s,%s" % (sg['GroupName'],sg['GroupId'],ip_protpcol, to_port, cidr_block))

				#Is source/target a security group?
				if len(rule['UserIdGroupPairs']) > 0:
					for source in rule['UserIdGroupPairs']:
						from_source = source['GroupId']
						print("%s,%s,%s,%s,%s" % (sg['GroupName'],sg['GroupId'],ip_protpcol, to_port, from_source))
	return True
