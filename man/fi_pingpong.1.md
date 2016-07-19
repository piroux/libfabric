---
layout: page
title: fi_pingpong(1)
tagline: Libfabric Programmer's Manual
---
{% include JB/setup %}


# NAME

fu_pingpong  \- Quick and simple pingpong test for libfabric


# SYNOPSYS

```
 fi_pingpong [OPTIONS] -s <server IP>	start server
 fi_pingpong [OPTIONS] <server IP>	connect to server
```


# DESCRIPTION

`fi_pingpong` is a generic pingpong test allowing provider authors and libfabric users to test
the core feature of the libfabric library: transmitting data between two nodes.
Moreover it agregates some data during the test on each end in order to diplay some statistics
after each test has been run, and potentially ask to verify data consistency.

An endpoint can be specified to be used as the data endpoint. By default, the DGRAM endpoint
is always selected. Therefore it is designed to transmit data from one node toward the other
over the selected endpoint, or the default DGRAM if none is selected.


# HOW TO RUN TESTS

To launch properly a pingpong test, two termimals have to be open : one for the client,
the other for the server. However the server must be already running to start the client.

As a client-server test, each have the following usage model:

server$	fi_pingpong -s <server endpoint address>	: start server
client$	fi_pingpong <server endpoint address>		: connect to server


# OPTIONS

The command line of the server and the client must be launched with exactly the same set of options. Otherwise the test would fail because the two nodes would not be able to communicate properly.

## Nodes addressing

*-b <src_port>*
: The non-default source port number of the endpoint.

*-p <dest_port>*
: The non-default destination port number of the endpoint.

*-s <src_addr>*
: The source address.

## Fabric

*-f <provider_name>*
: The name of the underlying fabric provider e.g. sockets, verbs, psm etc. If the provider name is not provided, the test will pick one from the list of the available providers it finds by fi_getinfo call.

*-e <endpoint> where endpoint = (dgram|rdm|msg)*
The type of endpoint to be used for data messaging between the two nodes.

*-n <domain>*
: The name of the specific domain to be used.

## Messaging

*-I <iter>*
: The number of iterations of the test will run.

*-S <msg_size>*
: The specific size of the message in bytes the test will use or 'all' to run all the default sizes.

## Utils

*-v*
: Activate the verification of incoming data.

*-d*
: Activate output debugging (warning: highly verbose)

*-h*
: Displays help output for the pingpong test.


# USAGE EXAMPLES

## A simple example

	run server: fi_pingpong -f <provider_name> -s <source_addr>
		server$ fi_pingpong -f sockets -s 192.168.0.123
	run client: gi_pingpong -f <provider_name> <server_addr>
		client$	fi_pingpong -f sockets 192.168.0.123

## An example with various options

	run server:
		server$ fi_pingpong -f usnic -I 1000 -S 1024 -s 192.168.0.123
	run client:
		client$ fi_pingpong -f usnic -I 1000 -S 1024 192.168.0.123


Specifically, this will run only one test with :

	- usNIC provider
	- 1000 iterations
	- 1024 bytes message size
	- server node as 123.168.0.123

## A longer test

	run server:
		server$ fi_pingpong -f usnic -I 10000 -S all -s 192.168.0.123
	run client:
		client$ fi_pingpong -f usnic -I 10000 -S all 192.168.0.123

## Defaults

For the provider, there is no default value as such. The selection of the provider
is ultimately determined by libfabric while probing for hardware with the sets of hints generated with the options.

For the provider, the default value is 'dgram'.

The default tested sizes are :  64, 256, 1024, 4096

# OUTPUT

Each test generates data messages which are accounted for. Specifically, the displayed statitics at the end are :

 - 'bytes'          : number of bytes per message sent
 - '#sent'          : number of messages (ping) sent from the client to the server
 - '#ack'           : number of replies (pong) of the server received by the client
 - 'total'          : amount of memory exchanged between the nodes
 - 'time'           : duration of this single test
 - 'MB/sec'         : throughput computed from 'total' and 'time'
 - 'usec/xfer'      : average time for transfering a message outbound (ping or pong) in microseconds
 - 'Mxfers/sec'     : average amount of transfers of message outbound per second

# SEE ALSO

[`fi_info`(1)](info.1.html),
[`fabric`(7)](fabric.7.html),
[`fi_provider`(7)](fi_provider.7.html),
