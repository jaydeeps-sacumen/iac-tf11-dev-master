# PANOS Integration

## Overview

The Datadog-PANOS integration allows you to get your PANOS log events into Datadog.

## Setup

### Set up PANOS log collection

To enable logs collection for Datadog Agent, we need to below information. 

 - API-KEY from Datadog 
 - PANOS System
 - PANOS Server Profile

### API-KEY from Datadog
API-Key is required to send the logs to Datadog over REST API calls. You can login to datadog 
and select integrations option on left side menu. After selecting integrations options you need to select API sub option and generate the API-Key 

### PANOS System

You need PANOS system access to configure the server profile which will allows you to forward the logs to http destination (Datadog). You can configure any of below logs which is required to configure, it's not mandatory to configure all of these logs. Please copy log payload by clicking on each log type below.

<details>
<summary><i>Traffic Log </i> </summary>
<p>  timestamp=$start, serial=$serial, type=$type, subtype=$subtype, time_generated=$time_generated, network.client.ip=$src, network.destination.ip=$dst, natsrc=$natsrc, natdst=$natdst, rule=$rule, usr.id=$srcuser, dstuser=$dstuser,	app=$app,	vsys=$vsys,	from=$from,	to=$to,	inbound_if=$inbound_if,	outbound_if=$outbound_if,	logset=$logset,	sessionid=$sessionid,	repeatcnt=$repeatcnt,	network.client.port=$sport,	network.destination.port=$dport, natsport=$natsport	natdport=$natdport,	flags=$flags,	proto=$proto,	 evt.name=$action,	bytes=$bytes,	network.bytes_read=$bytes_sent,	network.bytes_written=$bytes_received, start=$start, elapsed=$elapsed, category=$category,	seqno=$seqno,	actionflags=$actionflags,	network.client.geoip.country.name=$srcloc,	dstloc=$dstloc,	pkts_sent=$pkts_sent, pkts_received=$pkts_received, session_end_reason=$session_end_reason,	device_name=$device_name,	action_source=$action_source,	src_uuid=$src_uuid,	dst_uuid=$dst_uuid,	tunnelid=$tunnelid,  imsi= $imsi, monitortag=$monitortag, imei=$imei,	parent_session_id=$parent_session_id,	parent_start_time=$parent_start_time,	tunnel=$tunnel,	assoc_id=$assoc_id,	chunks=$chunks	chunks_sent=$chunks_sent	chunks_received=$chunks_received </p>
</details>

<details>
<summary><i>Threat Log </i></summary>
<p> timestamp=$receive_time, serial=$serial, type=$type, subtype=$subtype, time_generated=$time_generated, network.client.ip=$src, network.destination.ip=$dst, natsrc=$natsrc, natdst=$natdst, rule=$rule, usr.id=$srcuser, dstuser=$dstuser,	app=$app,	vsys=$vsys,	from=$from,	to=$to,	inbound_if=$inbound_if,	outbound_if=$outbound_if,	logset=$logset,	sessionid=$sessionid,	repeatcnt=$repeatcnt,	network.client.port=$sport,	network.destination.port=$dport,	natsport=$natsport,	natdport=$natdport,	flags=$flags,	proto=$proto,	 evt.name=$action,	misc=$misc,	threatid=$threatid,	category=$category,	severity=$severity,	direction=$direction,	seqno=$seqno,	actionflags=$actionflags,	network.client.geoip.country.name=$srcloc,	dstloc=$dstloc,	contenttype=$contenttype,	pcap_id=$pcap_id,	filedigest=$filedigest,	cloud=$cloud,	url_idx=$url_idx,	http.useragent=$user_agent,	filetype=$filetype,	xff=$xff	referer=$referer,	sender=$sender,	subject=$subject,	recipient=$recipient,	reportid=$reportid,	vsys_name=$vsys_name,	device_name=$device_name,	src_uuid=$src_uuid,	dst_uuid=$dst_uuid,	http_method=$http_method,	tunnel_id=$tunnel_id, imsi=$imsi, monitortag=$monitortag, imei=$imei,	parent_session_id=$parent_session_id,	parent_start_time=$parent_start_time,	tunnel=$tunnel,	thr_category=$thr_category,	contentver=$contentver,	assoc_id=$assoc_id,	ppid=$ppid,	http_headers=$http_headers  </p>
</details>

<details>
<summary><i>Authentication Log </i></summary>
<p>  timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype, vsys=$vsys,	network.client.ip=$ip, usr.id=$user, normalize_user=$normalize_user, object=$object, authpolicy=$authpolicy, repeatcnt=$repeatcnt,	authid=$authid,	vendor=$vendor	, logset=$logset, serverprofile=$serverprofile,	message=$message	,clienttype=$clienttype,	evt.name=$event,	factorno=$factorno,	seqno=$seqno,	actionflags=$actionflags, vsys_name=$vsys_name,	device_name=$device_name,	vsys_id=$vsys_id,	authproto=$authproto  </p>
</details>

<details>
<summary><i>HIP Match Log </i></summary>
<p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype, time_generated=$time_generated,	usr.id=$srcuser, vsys=$vsys, machinename=$machinename, os=$os, network.client.ip=$src, matchname=$matchname, repeatcnt=$repeatcnt,	matchtype=$matchtype,	seqno=$seqno,	actionflags=$actionflags, vsys_name=$vsys_name,	device_name=$device_name,	vsys_id=$vsys_id,	srcipv6=$srcipv6,	hostid=$hostid  </p>
</details>

<details>
<summary><i>User-ID Log </i></summary>
<p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype, vsys=$vsys,	network.client.ip=$ip,	usr.id=$user, datasourcename=$datasourcename,	evt.name=$eventid,	repeatcnt=$repeatcnt, timeout=$timeout,	network.client.port=$beginport,	network.destination.port=$endport,	datasource=$datasource,	datasourcetype=$datasourcetype,	seqno=$seqno,	actionflags=$actionflags, vsys_name=$vsys_name,	device_name=$device_name,	vsys_id=$vsys_id,	factortype=$factortype,	factorcompletiontime=$factorcompletiontime,,	factorno=$factorno,	ugflags=$ugflags,	userbysource=$userbysource  </p>
</details>

<details>
<summary><i>Tunnel Inspection Log </i></summary>
<p> timestamp=$parent_start_time,	serial=$serial,	type=$type,	subtype=$subtype, network.client.ip=$src, network.destination.ip=$dst,	natsrc=$natsrc,	natdst=$natdst,	rule=$rule,	usr.id=$srcuser, dstuser=$dstuser,	app=$app, vsys=$vsys, from=$from,	to=$to,	inbound_if=$inbound_if,	outbound_if=$outbound_if,	logset=$logset,	sessionid=$sessionid,	repeatcnt=$repeatcnt,	network.client.port=$sport,	network.destination.port=$dport,	natsport=$natsport,	natdport=$natdport,	flags=$flags,	proto=$proto,	evt.name=$action,	severity=$severity,	seqno=$seqno,	actionflags=$actionflags,	srcloc=$srcloc,	dstloc=$dstloc,	vsys_name=$vsys_name,	device_name=$device_name,	tunnelid=$tunnelid,	monitortag=$monitortag,	parent_session_id=$parent_session_id,	parent_start_time=$parent_start_time,	tunnel=$tunnel,	bytes=$bytes,	network.bytes_read=$bytes_sent,	network.bytes_written=$bytes_received,	packets=$packets,	pkts_sent=$pkts_sent,	pkts_received=$pkts_received,	max_encap=$max_encap,	unknown_proto=$unknown_proto,	strict_check=$strict_check,	tunnel_fragment=$tunnel_fragment,	sessions_created=$sessions_created,	sessions_closed=$sessions_closed,	session_end_reason=$session_end_reason,	action_source=$action_source,	start=$start,	elapsed=$elapsed,	tunnel_insp_rule=$tunnel_insp_rule  </p>
</details>

<details>
<summary><i>SCTP Log </i></summary>
<p> timestamp=$time_generated, serial=$serial, type=$type, network.client.ip=$src,	network.destination.ip=$dst, rule=$rule, vsys=$vsys, from=$from, to=$to, inbound_if=$inbound_if, outbound_if=$outbound_if, logset=$logset, sessionid=$sessionid,	repeatcnt=$repeatcnt,	network.client.port=$sport,	network.destination.port=$dport,	proto=$proto,	action=$action, vsys_name=$vsys_name,	device_name=$device_name,	seqno=$seqno,	assoc_id=$assoc_id,	ppid=$ppid,	severity=$severity,	sctp_chunk_type=$sctp_chunk_type,	sctp_event_type=$sctp_event_type,	verif_tag_1=$verif_tag_1,	verif_tag_2=$verif_tag_2,	sctp_cause_code=$sctp_cause_code,	diam_app_id=$diam_app_id,	diam_cmd_code=$diam_cmd_code,	diam_avp_code=$diam_avp_code,	stream_id=$stream_id,	assoc_end_reason=$assoc_end_reason,	op_code=$op_code,	sccp_calling_ssn=$sccp_calling_ssn,	sccp_calling_gt=$sccp_calling_gt,	sctp_filter=$sctp_filter,	chunks=$chunks,	chunks_sent=$chunks_sent,	chunks_received=$chunks_received,	packets=$packets,	pkts_sent=$pkts_sent,	pkts_received=$pkts_received  </p>
</details>

<details>
<summary><i>Config Log  </i></summary>
<p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype,	 network.client.ip=$host,	vsys=$vsys,	cmd=$cmd, usr.id=$admin, client=$client, evt.name=$result,	path=$path, before_change_detail=$before_change_detail,	after_change_detail=$after_change_detail,	seqno=$seqno,	actionflags=$actionflags, vsys_name=$vsys_name, device_name=$device_name  </p>
</details>

<details>
<summary><i>System Log </i></summary>
<p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype,	vsys=$vsys,	evt.name=$eventid,	object=$object,	module=$module,	severity=$severity,	opaque=$opaque,	seqno=$seqno, actionflags=$actionflags, vsys_name=$vsys_name, device_name=$device_name  </p>
</details>

<details>
<summary><i>Correlated Events Log </i></summary>
<p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype,	vsys=$vsys,	evt.name=$eventid,	object=$object,	module=$module,	severity=$severity,	opaque=$opaque,	seqno=$seqno, actionflags=$actionflags, vsys_name=$vsys_name,	device_name=$device_name  </p>
</details>

<details>
<summary><i>GTP Log </i></summary>
<p> timestamp=$start, serial=$serial, type=$type, subtype=$subtype,	network.client.ip=$src,	network.destination.ip=$dst, rule=$rule, app=$app, vsys=$vsys,	from=$from,	to=$to,	inbound_if=$inbound_if,	outbound_if=$outbound_if, logset=$logset,	sessionid=$sessionid,	network.client.port=$sport,	network.destination.port=$dport, proto=$proto,	evt.name=$action,	event_type=$event_type,	msisdn=$msisdn,	apn=$apn,	rat=$rat,	msg_type=$msg_type,	end_ip_adr=$end_ip_adr,	teid1=$teid1,	teid2=$teid2,	gtp_interface=$gtp_interface,	cause_code=$cause_code,	severity=$severity,	mcc=$mcc,	mnc=$mnc,	area_code=$area_code,	cell_id=$cell_id,	event_code=$event_code,	srcloc=$srcloc,	dstloc=$dstloc,	imsi=$imsi,	imei=$imei,	start=$start,	elapsed=$elapsed,	tunnel_insp_rule=$tunnel_insp_rule  </p>
</details>

[logo]: https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 2"


### PANOS server profile
Configure the firewall to send an HTTP-based API request directly to a third-party service to trigger an action based on the attributes in a firewall log. Login to PANOS System and follow below steps.

- Create an HTTP server profile.      
   * Select Device >> Server Profiles >> HTTP, add a Name for the server profile, select the Location, Enter a Name, IP Address, HTTPS protocol, method as POST, username and password if available. Finally click on test connection.

- Select the Payload format.

   * Select the Log Type link, URI format (datadog REST API URL) and copy respective log payload from earlier step. In HTTP Header's click on add button and then  add DD-API-KEY from data dog and Content-Type as text/plain.
    
- Define the match criteria.
   
   * Select the log types for which you want to trigger a workflow and use the new Filter Builder to define the match criteria. Finally add the HTTP server profile for forwarding logs to datadog.


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
