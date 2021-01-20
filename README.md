# Palo Alto Networks Firewall Log Integration

## Overview

Datadog's Palo Alto Networks Firewall Log integration allows customers to ingest, parse and analyse Palo Alto Networks Firewall Logs. This log integration relies upon HTTPs log templating and forwarding capability provided by PAN OS, the operating system that runs in Palo Alto fireewalls. PAN OS allows customers to forward  threat, traffic, authentication and many other important log events.

### Key Use Cases
#### Respond to high severity threat events
Firewall threat logs provide rich context on threats deteected by the firewall which can be filtered and analysed by severity, type, origin IPs/countries and more. 

#### Make informed decisions on Firewall deployment
Firewall traffic logs can be used to measure the traffic and sessions passing through the firewalls and also gives you the ability to monitor for anomolous throughput across firewall deployment.

#### Monitor authentication anomalies
Firewall authentication logs provide detailed information on users as they authenticate with Palo Alto Networks Firewall. These logs can be used to monitor anomalous spikes in authetication traffic from specifc protocols, users, locations and more.

## Setup

### Set up Palo Alto Networks Firewall log collection 

 1. Login to Palo Alto Networks Firewall System
 2. Select Device >> Server Profiles >> HTTP, add a name for the server profile and select the location to create a server profile.
 3. Click Add and provide the following details of the server:
	* Name of the server
	* IP address of the server 
	* Select HTTPS protocol
	* Select HTTP method as POST
	* Provide username and password for authentication
 4. Select Test Server Connection to verify the server connection.
 5. Select the Payload format tab and select the Log Type you want to configure.
 6. Provide the Name and Payload based on the logtype you selected as per the table below.

    | Name     	                   | Format                                                |
    | -------------------------------| ---------------------------------------------------------- |
    | Traffic Log | <details> <summary><i> View Payload </i> </summary> <p>  timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype, time_generated=$time_generated, network.client.ip=$src, network.destination.ip=$dst, natsrc=$natsrc, natdst=$natdst, rule=$rule, usr.id=$srcuser, dstuser=$dstuser,	app=$app,	vsys=$vsys,	from=$from,	to=$to,	inbound_if=$inbound_if,	outbound_if=$outbound_if,	logset=$logset,	sessionid=$sessionid,	repeatcnt=$repeatcnt,	network.client.port=$sport,	network.destination.port=$dport, natsport=$natsport	natdport=$natdport,	flags=$flags,	proto=$proto,	 evt.name=$action,	bytes=$bytes,	network.bytes_read=$bytes_sent,	network.bytes_written=$bytes_received, start=$start, elapsed=$elapsed, category=$category,	seqno=$seqno,	actionflags=$actionflags,	network.client.geoip.country.name=$srcloc,	dstloc=$dstloc,	pkts_sent=$pkts_sent, pkts_received=$pkts_received, session_end_reason=$session_end_reason,	device_name=$device_name,	action_source=$action_source,	src_uuid=$src_uuid,	dst_uuid=$dst_uuid,	tunnelid=$tunnelid,  imsi= $imsi, monitortag=$monitortag, imei=$imei,	parent_session_id=$parent_session_id,	parent_start_time=$parent_start_time,	tunnel=$tunnel,	assoc_id=$assoc_id,	chunks=$chunks	chunks_sent=$chunks_sent	chunks_received=$chunks_received </p> </details> |
    | Threat Log | <details> <summary><i> View Payload </i></summary> <p> timestamp=$receive_time, serial=$serial, type=$type, subtype=$subtype, time_generated=$time_generated, network.client.ip=$src, network.destination.ip=$dst, natsrc=$natsrc, natdst=$natdst, rule=$rule, usr.id=$srcuser, dstuser=$dstuser,	app=$app,	vsys=$vsys,	from=$from,	to=$to,	inbound_if=$inbound_if,	outbound_if=$outbound_if,	logset=$logset,	sessionid=$sessionid,	repeatcnt=$repeatcnt,	network.client.port=$sport,	network.destination.port=$dport,	natsport=$natsport,	natdport=$natdport,	flags=$flags,	proto=$proto,	 evt.name=$action,	misc=$misc,	threatid=$threatid,	category=$category,	severity=$severity,	direction=$direction,	seqno=$seqno,	actionflags=$actionflags,	network.client.geoip.country.name=$srcloc,	dstloc=$dstloc,	contenttype=$contenttype,	pcap_id=$pcap_id,	filedigest=$filedigest,	cloud=$cloud,	url_idx=$url_idx,	http.useragent=$user_agent,	filetype=$filetype,	xff=$xff	referer=$referer,	sender=$sender,	subject=$subject,	recipient=$recipient,	reportid=$reportid,	vsys_name=$vsys_name,	device_name=$device_name,	src_uuid=$src_uuid,	dst_uuid=$dst_uuid,	http_method=$http_method,	tunnel_id=$tunnel_id, imsi=$imsi, monitortag=$monitortag, imei=$imei,	parent_session_id=$parent_session_id,	parent_start_time=$parent_start_time,	tunnel=$tunnel,	thr_category=$thr_category,	contentver=$contentver,	assoc_id=$assoc_id,	ppid=$ppid,	http_headers=$http_headers  </p> </details> |
    | Authentication Log | <details> <summary><i> View Payload </i></summary> <p>  timestamp=$time_generated, serial=$serial,	type=$type,	subtype=$subtype,	vsys=$vsys,	network.client.ip=$ip,	usr.id=$user,	normalize_user=$normalize_user,	object=$object,	authpolicy=$authpolicy,	repeatcnt=$repeatcnt,	authid=$authid,	vendor=$vendor	, logset=$logset, serverprofile=$serverprofile,	message=$message	,clienttype=$clienttype,	evt.outcome=$event,	factorno=$factorno,	seqno=$seqno,	actionflags=$actionflags, vsys_name=$vsys_name,	device_name=$device_name,	vsys_id=$vsys_id,	evt.name=$authproto  </p> </details> |
    | HIP Match Log | <details> <summary><i> View Payload </i></summary> <p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype, time_generated=$time_generated,	usr.id=$srcuser, vsys=$vsys, machinename=$machinename, os=$os, network.client.ip=$src, matchname=$matchname, repeatcnt=$repeatcnt,	matchtype=$matchtype,	seqno=$seqno,	actionflags=$actionflags, vsys_name=$vsys_name,	device_name=$device_name,	vsys_id=$vsys_id,	srcipv6=$srcipv6,	hostid=$hostid  </p> </details> |
    | User-ID Log | <details> <summary><i> View Payload </i></summary> <p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype, vsys=$vsys,	network.client.ip=$ip,	usr.id=$user, datasourcename=$datasourcename,	evt.name=$eventid,	repeatcnt=$repeatcnt, timeout=$timeout,	network.client.port=$beginport,	network.destination.port=$endport,	datasource=$datasource,	datasourcetype=$datasourcetype,	seqno=$seqno,	actionflags=$actionflags, vsys_name=$vsys_name,	device_name=$device_name,	vsys_id=$vsys_id,	factortype=$factortype,	factorcompletiontime=$factorcompletiontime,,	factorno=$factorno,	ugflags=$ugflags,	userbysource=$userbysource  </p> </details> |
    | Tunnel Inspection Log | <details> <summary><i> View Payload </i></summary> <p> timestamp=$time_generated,	serial=$serial,	type=$type,	subtype=$subtype,	 network.client.ip=$src,	network.destination.ip=$dst,	natsrc=$natsrc,	natdst=$natdst,	rule=$rule,	usr.id=$srcuser,	dstuser=$dstuser,	app=$app,	vsys=$vsys,	from=$from,	to=$to,	inbound_if=$inbound_if,	outbound_if=$outbound_if,	logset=$logset,	sessionid=$sessionid,	repeatcnt=$repeatcnt,	network.client.port=$sport,	network.destination.port=$dport,	natsport=$natsport,	natdport=$natdport,	flags=$flags,	proto=$proto,	evt.outcome=$action,	severity=$severity,	seqno=$seqno,	actionflags=$actionflags,	srcloc=$srcloc,	dstloc=$dstloc,	vsys_name=$vsys_name,	device_name=$device_name,	tunnelid=$tunnelid,	monitortag=$monitortag,	parent_session_id=$parent_session_id,	parent_start_time=$parent_start_time,	tunnel=$tunnel,	bytes=$bytes,	network.bytes_read=$bytes_sent,	network.bytes_written=$bytes_received,	packets=$packets,	pkts_sent=$pkts_sent,	pkts_received=$pkts_received,	max_encap=$max_encap,	unknown_proto=$unknown_proto,	strict_check=$strict_check,	tunnel_fragment=$tunnel_fragment,	sessions_created=$sessions_created,	sessions_closed=$sessions_closed,	session_end_reason=$session_end_reason,	evt.name=$action_source,	start=$start,	elapsed=$elapsed,	tunnel_insp_rule=$tunnel_insp_rule  </p> </details> |
    | SCTP Log | <details> <summary><i> View Payload  </i></summary> <p> timestamp=$time_generated, serial=$serial, type=$type, network.client.ip=$src,	network.destination.ip=$dst, rule=$rule, vsys=$vsys, from=$from, to=$to, inbound_if=$inbound_if, outbound_if=$outbound_if, logset=$logset, sessionid=$sessionid,	repeatcnt=$repeatcnt,	network.client.port=$sport,	network.destination.port=$dport,	proto=$proto,	action=$action, vsys_name=$vsys_name,	device_name=$device_name,	seqno=$seqno,	assoc_id=$assoc_id,	ppid=$ppid,	severity=$severity,	sctp_chunk_type=$sctp_chunk_type,	sctp_event_type=$sctp_event_type,	verif_tag_1=$verif_tag_1,	verif_tag_2=$verif_tag_2,	sctp_cause_code=$sctp_cause_code,	diam_app_id=$diam_app_id,	diam_cmd_code=$diam_cmd_code,	diam_avp_code=$diam_avp_code,	stream_id=$stream_id,	assoc_end_reason=$assoc_end_reason,	op_code=$op_code,	sccp_calling_ssn=$sccp_calling_ssn,	sccp_calling_gt=$sccp_calling_gt,	sctp_filter=$sctp_filter,	chunks=$chunks,	chunks_sent=$chunks_sent,	chunks_received=$chunks_received,	packets=$packets,	pkts_sent=$pkts_sent,	pkts_received=$pkts_received  </p> </details> |
    | Config Log | <details> <summary><i> View Payload  </i></summary> <p> timestamp=$time_generated,	serial=$serial,	type=$type,	subtype=$subtype,	 network.client.ip=$host,	vsys=$vsys,	evt.name=$cmd,	usr.id=$admin,	client=$client,	evt.outcome=$result,	path=$path, before_change_detail=$before_change_detail,	after_change_detail=$after_change_detail,	seqno=$seqno,	actionflags=$actionflags, vsys_name=$vsys_name, device_name=$device_name  </p> </details> |
    | System Log | <details> <summary><i> View Payload </i></summary> <p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype,	vsys=$vsys,	evt.name=$eventid,	object=$object,	module=$module,	severity=$severity,	opaque=$opaque,	seqno=$seqno, actionflags=$actionflags, vsys_name=$vsys_name, device_name=$device_name  </p> </details> |
    | Correlated Events Log | <details> <summary><i> View Payload </i></summary> <p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype,	vsys=$vsys,	evt.name=$eventid,	object=$object,	module=$module,	severity=$severity,	opaque=$opaque,	seqno=$seqno, actionflags=$actionflags, vsys_name=$vsys_name,	device_name=$device_name  </p> </details> |
    | GTP Log  | <details> <summary><i> View Payload </i></summary> <p> timestamp=$start, serial=$serial, type=$type, subtype=$subtype,	network.client.ip=$src,	network.destination.ip=$dst, rule=$rule, app=$app, vsys=$vsys,	from=$from,	to=$to,	inbound_if=$inbound_if,	outbound_if=$outbound_if, logset=$logset,	sessionid=$sessionid,	network.client.port=$sport,	network.destination.port=$dport, proto=$proto,	evt.name=$action,	event_type=$event_type,	msisdn=$msisdn,	apn=$apn,	rat=$rat,	msg_type=$msg_type,	end_ip_adr=$end_ip_adr,	teid1=$teid1,	teid2=$teid2,	gtp_interface=$gtp_interface,	cause_code=$cause_code,	severity=$severity,	mcc=$mcc,	mnc=$mnc,	area_code=$area_code,	cell_id=$cell_id,	event_code=$event_code,	srcloc=$srcloc,	dstloc=$dstloc,	imsi=$imsi,	imei=$imei,	start=$start,	elapsed=$elapsed,	tunnel_insp_rule=$tunnel_insp_rule  </p> </details> |

 7. Provide the URI format as mentioned below.

     | Setting     	                   | Description                                                |
     | -------------------------------| ---------------------------------------------------------- |
     | `URI Format`                  | If you are in the Datadog EU site (https://http-intake.logs.datadoghq.eu/v1/input?ddsource=pan.firewall&ddtags=optional), otherwise it should be `GLOBAL`  (https://http-intake.logs.datadoghq.com/v1/input?ddsource=pan.firewall&ddtags=optional)   |

 8. In HTTP Header's click on add button and then add DD-API-KEY and content-type and click ok.
 
     | Setting     	                   | Description                                                |
     | -------------------------------| ---------------------------------------------------------- |
     | `DD-API-KEY`                  | [Create your Datadog API Key  ](https://app.datadoghq.com/account/settings#api) 							|
     |  `Content-Type`               |  text/plain   |    

 9. Click ok and Send Test Log to verify that the HTTP server receives the request
  
For more information, consult the  [Forward Logs to an HTTP(S) Destination](https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-admin/monitoring/forward-logs-to-an-https-destination).

For more information on log types and fields check below links
 
 - https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions
 
For more information, consult the [Logs Collection documentation](https://docs.datadoghq.com/logs/log_collection/?tab=tailexistingfiles#getting-started-with-the-agent).

For more information, refer to the [Datadog API documentation for creating a dashboard](https://docs.datadoghq.com/api/?lang=bash#create-a-dashboard).

## Data Collected

### Metrics

The PANOS integration does not include any metrics.

### Events

The PANOS integration does not send any events.

### Service Checks

The PANOS integration does not include any service checks.
