# PANOS Integration

## Overview

The Datadog-PANOS integration allows you to get your PANOS log events into Datadog.

## Setup

### Set up PANOS log collection

To enable logs collection for Datadog Agent, we need to below information. 

 - API-KEY from Datadog 
 - PANOS System

###API-KEY from Datadog
API-Key is required to send the logs to Datadog over REST API calls. Please refer to the [Log Collection & Integrations guide](https://docs.datadoghq.com/logs/log_collection/?tab=http). You can login to datadog 
and select integrations option on left side menu. After selecting integrations options you need to select API sub option and generate the API-Key 

###PANOS System

You need PANOS system access to configure the server profile which will allows you to forward the logs to http destination (Datadog). You can configure any of below logs which is required to configure, it's not mandatory to configure all below logs.

<details>
<summary><i>- Traffic Log </i> </summary>
<p>  timestamp=$start, serial=$serial, type=$type, subtype=$subtype, time_generated=$time_generated, network.client.ip=$src, network.destination.ip=$dst, natsrc=$natsrc, natdst=$natdst, rule=$rule, usr.id=$srcuser, dstuser=$dstuser,	app=$app,	vsys=$vsys,	from=$from,	to=$to,	inbound_if=$inbound_if,	outbound_if=$outbound_if,	logset=$logset,	sessionid=$sessionid,	repeatcnt=$repeatcnt,	network.client.port=$sport,	network.destination.port=$dport, natsport=$natsport	natdport=$natdport,	flags=$flags,	proto=$proto,	 evt.name=$action,	bytes=$bytes,	network.bytes_read=$bytes_sent,	network.bytes_written=$bytes_received, start=$start, elapsed=$elapsed, category=$category,	seqno=$seqno,	actionflags=$actionflags,	network.client.geoip.country.name=$srcloc,	dstloc=$dstloc,	pkts_sent=$pkts_sent, pkts_received=$pkts_received, session_end_reason=$session_end_reason,	device_name=$device_name,	action_source=$action_source,	src_uuid=$src_uuid,	dst_uuid=$dst_uuid,	tunnelid=$tunnelid,  imsi= $imsi, monitortag=$monitortag, imei=$imei,	parent_session_id=$parent_session_id,	parent_start_time=$parent_start_time,	tunnel=$tunnel,	assoc_id=$assoc_id,	chunks=$chunks	chunks_sent=$chunks_sent	chunks_received=$chunks_received </p>
</details>

<details>
<summary><i>- Threat Log </i></summary>
<p> timestamp=$receive_time, serial=$serial, type=$type, subtype=$subtype, time_generated=$time_generated, network.client.ip=$src, network.destination.ip=$dst, natsrc=$natsrc, natdst=$natdst, rule=$rule, usr.id=$srcuser, dstuser=$dstuser,	app=$app,	vsys=$vsys,	from=$from,	to=$to,	inbound_if=$inbound_if,	outbound_if=$outbound_if,	logset=$logset,	sessionid=$sessionid,	repeatcnt=$repeatcnt,	network.client.port=$sport,	network.destination.port=$dport,	natsport=$natsport,	natdport=$natdport,	flags=$flags,	proto=$proto,	 evt.name=$action,	misc=$misc,	threatid=$threatid,	category=$category,	severity=$severity,	direction=$direction,	seqno=$seqno,	actionflags=$actionflags,	network.client.geoip.country.name=$srcloc,	dstloc=$dstloc,	contenttype=$contenttype,	pcap_id=$pcap_id,	filedigest=$filedigest,	cloud=$cloud,	url_idx=$url_idx,	http.useragent=$user_agent,	filetype=$filetype,	xff=$xff	referer=$referer,	sender=$sender,	subject=$subject,	recipient=$recipient,	reportid=$reportid,	vsys_name=$vsys_name,	device_name=$device_name,	src_uuid=$src_uuid,	dst_uuid=$dst_uuid,	http_method=$http_method,	tunnel_id=$tunnel_id, imsi=$imsi, monitortag=$monitortag, imei=$imei,	parent_session_id=$parent_session_id,	parent_start_time=$parent_start_time,	tunnel=$tunnel,	thr_category=$thr_category,	contentver=$contentver,	assoc_id=$assoc_id,	ppid=$ppid,	http_headers=$http_headers  </p>
</details>

<details>
<summary><i>- Authentication Log </i></summary>
<p>  timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype, vsys=$vsys,	network.client.ip=$ip, usr.id=$user, normalize_user=$normalize_user, object=$object, authpolicy=$authpolicy, repeatcnt=$repeatcnt,	authid=$authid,	vendor=$vendor	, logset=$logset, serverprofile=$serverprofile,	message=$message	,clienttype=$clienttype,	evt.name=$event,	factorno=$factorno,	seqno=$seqno,	actionflags=$actionflags, vsys_name=$vsys_name,	device_name=$device_name,	vsys_id=$vsys_id,	authproto=$authproto  </p>
</details>

<details>
<summary><i>- HIP Match Log </i></summary>
<p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype, time_generated=$time_generated,	usr.id=$srcuser, vsys=$vsys, machinename=$machinename, os=$os, network.client.ip=$src, matchname=$matchname, repeatcnt=$repeatcnt,	matchtype=$matchtype,	seqno=$seqno,	actionflags=$actionflags, vsys_name=$vsys_name,	device_name=$device_name,	vsys_id=$vsys_id,	srcipv6=$srcipv6,	hostid=$hostid  </p>
</details>

<details>
<summary><i>- User-ID Log </i></summary>
<p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype, vsys=$vsys,	network.client.ip=$ip,	usr.id=$user, datasourcename=$datasourcename,	evt.name=$eventid,	repeatcnt=$repeatcnt, timeout=$timeout,	network.client.port=$beginport,	network.destination.port=$endport,	datasource=$datasource,	datasourcetype=$datasourcetype,	seqno=$seqno,	actionflags=$actionflags, vsys_name=$vsys_name,	device_name=$device_name,	vsys_id=$vsys_id,	factortype=$factortype,	factorcompletiontime=$factorcompletiontime,,	factorno=$factorno,	ugflags=$ugflags,	userbysource=$userbysource  </p>
</details>

<details>
<summary><i>- Tunnel Inspection Log </i></summary>
<p> timestamp=$parent_start_time,	serial=$serial,	type=$type,	subtype=$subtype, network.client.ip=$src, network.destination.ip=$dst,	natsrc=$natsrc,	natdst=$natdst,	rule=$rule,	usr.id=$srcuser, dstuser=$dstuser,	app=$app, vsys=$vsys, from=$from,	to=$to,	inbound_if=$inbound_if,	outbound_if=$outbound_if,	logset=$logset,	sessionid=$sessionid,	repeatcnt=$repeatcnt,	network.client.port=$sport,	network.destination.port=$dport,	natsport=$natsport,	natdport=$natdport,	flags=$flags,	proto=$proto,	evt.name=$action,	severity=$severity,	seqno=$seqno,	actionflags=$actionflags,	srcloc=$srcloc,	dstloc=$dstloc,	vsys_name=$vsys_name,	device_name=$device_name,	tunnelid=$tunnelid,	monitortag=$monitortag,	parent_session_id=$parent_session_id,	parent_start_time=$parent_start_time,	tunnel=$tunnel,	bytes=$bytes,	network.bytes_read=$bytes_sent,	network.bytes_written=$bytes_received,	packets=$packets,	pkts_sent=$pkts_sent,	pkts_received=$pkts_received,	max_encap=$max_encap,	unknown_proto=$unknown_proto,	strict_check=$strict_check,	tunnel_fragment=$tunnel_fragment,	sessions_created=$sessions_created,	sessions_closed=$sessions_closed,	session_end_reason=$session_end_reason,	action_source=$action_source,	start=$start,	elapsed=$elapsed,	tunnel_insp_rule=$tunnel_insp_rule  </p>
</details>

<details>
<summary><i>- SCTP Log </i></summary>
<p> timestamp=$time_generated, serial=$serial, type=$type, network.client.ip=$src,	network.destination.ip=$dst, rule=$rule, vsys=$vsys, from=$from, to=$to, inbound_if=$inbound_if, outbound_if=$outbound_if, logset=$logset, sessionid=$sessionid,	repeatcnt=$repeatcnt,	network.client.port=$sport,	network.destination.port=$dport,	proto=$proto,	action=$action, vsys_name=$vsys_name,	device_name=$device_name,	seqno=$seqno,	assoc_id=$assoc_id,	ppid=$ppid,	severity=$severity,	sctp_chunk_type=$sctp_chunk_type,	sctp_event_type=$sctp_event_type,	verif_tag_1=$verif_tag_1,	verif_tag_2=$verif_tag_2,	sctp_cause_code=$sctp_cause_code,	diam_app_id=$diam_app_id,	diam_cmd_code=$diam_cmd_code,	diam_avp_code=$diam_avp_code,	stream_id=$stream_id,	assoc_end_reason=$assoc_end_reason,	op_code=$op_code,	sccp_calling_ssn=$sccp_calling_ssn,	sccp_calling_gt=$sccp_calling_gt,	sctp_filter=$sctp_filter,	chunks=$chunks,	chunks_sent=$chunks_sent,	chunks_received=$chunks_received,	packets=$packets,	pkts_sent=$pkts_sent,	pkts_received=$pkts_received  </p>
</details>

<details>
<summary><i>- Config Log  </i></summary>
<p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype,	 network.client.ip=$host,	vsys=$vsys,	cmd=$cmd, usr.id=$admin, client=$client, evt.name=$result,	path=$path, before_change_detail=$before_change_detail,	after_change_detail=$after_change_detail,	seqno=$seqno,	actionflags=$actionflags, vsys_name=$vsys_name, device_name=$device_name  </p>
</details>

<details>
<summary><i>- System Log </i></summary>
<p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype,	vsys=$vsys,	evt.name=$eventid,	object=$object,	module=$module,	severity=$severity,	opaque=$opaque,	seqno=$seqno, actionflags=$actionflags, vsys_name=$vsys_name, device_name=$device_name  </p>
</details>

<details>
<summary><i>- Correlated Events Log </i></summary>
<p> timestamp=$time_generated, serial=$serial, type=$type, subtype=$subtype,	vsys=$vsys,	evt.name=$eventid,	object=$object,	module=$module,	severity=$severity,	opaque=$opaque,	seqno=$seqno, actionflags=$actionflags, vsys_name=$vsys_name,	device_name=$device_name  </p>
</details>

<details>
<summary><i>- GTP Log </i></summary>
<p> timestamp=$start, serial=$serial, type=$type, subtype=$subtype,	network.client.ip=$src,	network.destination.ip=$dst, rule=$rule, app=$app, vsys=$vsys,	from=$from,	to=$to,	inbound_if=$inbound_if,	outbound_if=$outbound_if, logset=$logset,	sessionid=$sessionid,	network.client.port=$sport,	network.destination.port=$dport, proto=$proto,	evt.name=$action,	event_type=$event_type,	msisdn=$msisdn,	apn=$apn,	rat=$rat,	msg_type=$msg_type,	end_ip_adr=$end_ip_adr,	teid1=$teid1,	teid2=$teid2,	gtp_interface=$gtp_interface,	cause_code=$cause_code,	severity=$severity,	mcc=$mcc,	mnc=$mnc,	area_code=$area_code,	cell_id=$cell_id,	event_code=$event_code,	srcloc=$srcloc,	dstloc=$dstloc,	imsi=$imsi,	imei=$imei,	start=$start,	elapsed=$elapsed,	tunnel_insp_rule=$tunnel_insp_rule  </p>
</details>

[logo]: https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 2"


### PANOS server profile
Configure the firewall to send an HTTP-based API request directly to a third-party service to trigger an action based on the attributes in a firewall log. Login to PANOS System and follow below steps.


- Create an HTTP server profile to forward logs to an HTTP(S) destination.
   
   The HTTP server profile allows you to specify how to access the server and define the format in which to forward logs to the HTTP(S) destination
   
   * Select DeviceServer ProfilesHTTP, add a Name for the server profile, and select the Location. The profile can be Shared across all virtual systems or can belong to a specific virtual system.
   * Click Add to provide the details for each server. Each profile can have a maximum of 4 servers.
   * Enter a Name and IP Address.
   * Select the Protocol (HTTP or HTTPS). The default Port is 80 or 443 respectively; you can modify the port number to match the port on which your HTTP server listens.
   * Select the HTTP Method that the third-party service supports—PUT, POST (default), GET and DELETE.
   * Enter the Username and Password for authenticating to the server, if needed. Click OK.
   * Select Test Server Connection to verify network connectivity between the firewall and the HTTP(S) server.
   
- Select the Payload Format for the HTTP request.

   * Select the Log Type link for each log type for which you want to define the HTTP request format.
   * URI Format should be data dog URL.
   * Select the Pre-defined Formats drop-down to view the formats available through content updates, or create a custom format.
   * Send Test Log to verify that the HTTP server receives the request. When you interactively send a test log, the firewall uses the format as is and does not replace the variable with a value from a firewall log. If your HTTP server sends a 404 response, provide values for the parameters so that the server can process the request successfully.
    
- Define the match criteria for when the firewall will forward logs to the HTTP server, and attach the HTTP server profile to use.
   
   * Select the log types for which you want to trigger a workflow:
   Add a Log Forwarding Profile (ObjectsLog Forwarding Profile) for logs that pertain to user activity. For example, Traffic, Threat, or Authentication logs.
   Select DeviceLog Settings for logs that pertain to system events, such as Configuration or System logs.
   * Select the Log Type and use the new Filter Builder to define the match criteria.
   * Add the HTTP server profile for forwarding logs to the HTTP destination.
   * Add a tag to the source or destination IP address in the log entry. This capability allows you to use dynamic address groups and security policy rules to limit network access or isolate the IP address until you can triage the affected user device.
    Select Add in the Built-in Actions section and select the Target, Action: Add Tag, and Registration to register the tag to the local User-ID on a firewall or to the Panorama that is managing the firewall.

- Register or unregister a tag on a source or destination IP address in a log entry to a remote User-ID agent.
   
   * Select DeviceServer ProfilesHTTP, add a Name for the server profile, and select the Location. The profile can be Shared across all virtual systems or can belong to a specific virtual system.
   * Select Tag Registration to enable the firewall to register the IP address and tag mapping with the User-ID agent on a remote firewall. With tag registration enabled, you cannot specify the payload format.
   * Add the connection details to access the remote User-ID agent.
   * Select the log type (ObjectsLog Forwarding Profile or DeviceLog Settings) for which you want to add a tag to the source or destination IP address in the log entry.
   * Select Add in the Built-in Actions section and Name the action. Select the following options to register the tag on the remote User-ID agent:
    Target: Select source or destination IP address. Action: Add Tag or Remove Tag.
    Registration: Remote User-ID agent.HTTP Profile: Select the profile you created with Tag Registration enabled.
    Tag: Enter a new tag or select from the drop-down.


PANOS server profile. Please refer to the [Forward Logs to an HTTP(S) Destination](https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-admin/monitoring/forward-logs-to-an-https-destination).

Check points to verify.
 - URI (e.g. https://http-intake.logs.datadoghq.com/v1/input?ddsource=panos&ddtags=optional) 
 - DD-API-KEY and Content-Type



For more information on log types and fields check below links
 
 - https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions
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
