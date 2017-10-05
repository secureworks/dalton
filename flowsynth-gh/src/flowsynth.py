#!/usr/bin/env python
"""
   flowsynth - a tool for rapidly modeling network traffic

   Copyright 2014 SecureWorks Corp.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   author: Will Urbanski <will.urbanski@gmail.com>
"""



import argparse
import logging
import re
import random
import shlex
import sys
import socket
import time
import json

#include scapy; suppress all errors
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, UDP, RandMAC, hexdump, wrpcap

#global variables
APP_VERSION_STRING = "1.0.6"
LOGGING_LEVEL = logging.INFO
ARGS = None

#compiler specific vars
COMPILER_FLOWS = {}            # this is a dictionary containing the flow objects
COMPILER_OUTPUT = []        # the output buffer containing a list of packets
COMPILER_TIMELINE = []        # this is a list containing the global compiler timeline

#timing
START_TIME = 0
END_TIME = 0

#for recording the build status
BUILD_STATUS = {}

class SynSyntaxError(Exception):
    """ an exception for a syntax error when parsing a synfile """
    def __init__(self, value):
        self.value = value
        Exception.__init__(self)
    def __str__(self):
        return repr(self.value)

class SynTerminalError(Exception):
    """ an exception for a terminal error that cannot be recovered from """
    def __init__(self, value):
        self.value = value
        Exception.__init__(self)
    def __str__(self):
        return repr(self.value)

class SynCompileError(Exception):
    """a compile-time exception"""
    def __init__(self, value):
        self.value = value
        Exception.__init__(self)
    def __str__(self):
        return repr(self.value)

class FSLexer:
    """a lexer for the synfile format"""
    
    LEX_NEW = 0
    LEX_EXISTING = 1

    INSTR_FLOW = 0
    INSTR_EVENT = 1

    status = 0    #status of the line lex
    instr = 0

    instructions = []
    dnscache = {}

    def __init__(self, synfiledata):
        
        #init
        self.instructions = []
        self.dnscache = {}

        lexer = list(shlex.shlex(synfiledata))
        itr_ctr = 0
        while len(lexer) > 0:
            token = lexer[0]
            #should be the start of a new line
            #print "New lexer rotation. Starting with Token %s" % token
            #print "Tokens are %s" % lexer
            if (token.lower() == 'flow'):
                (flowdecl, lexer) = self.lex_flow(lexer[1:])
                self.instructions.append(flowdecl)
            else:
                #treat as an event
                (eventdecl, lexer) = self.lex_event(lexer)
                self.instructions.append(eventdecl)
            itr_ctr = itr_ctr + 1

    def resolve_dns(self, shost):
        """Perform DNS lookups once per file, and cache the results. tested."""
        rdns = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        if (re.match(rdns, shost) == None):
            if shost in self.dnscache:
                logging.debug("Host %s in DNSCACHE, returned %s", shost, self.dnscache[shost])
                shost = self.dnscache[shost]
            else:
                logging.debug("Host %s not in DNSCACHE", shost)
                #try socket lookupt
                try:
                    resolved_ip = socket.gethostbyname(shost)
                    self.dnscache[shost] = resolved_ip
                    logging.debug("Resolved %s to %s", shost, resolved_ip)
                    shost = resolved_ip
                except socket.gaierror:
                    compiler_bailout("Cannot resolve %s" % shost)
        return shost
            
    def lex_flow(self, tokens):
        """ lex flow declarations"""
        logging.debug("lex_flow() called with %s", tokens)

        if (type(tokens) is not list):
            parser_bailout("FSLexer tried to flowlex a %s" % type(tokens))

        #need to read the following mandatory values:
        try:
            flow_name = tokens[0]
            flow_proto = tokens[1]
            tokens = tokens[2:]
        except IndexError:
            raise SynSyntaxError("Corrupt flowdecl")

        flow_src = ""
        tok_ctr = 0
        for token in tokens:
            if (token == ':'):
                break
            else:
                flow_src = "%s%s" % (flow_src, token)
                tok_ctr = tok_ctr + 1
        tokens = tokens[tok_ctr+1:]
        try:
            flow_src_port = tokens[0]
        except IndexError:
            raise SynSyntaxError("No flow source port specified")

        directionality = tokens[1]
        if (directionality != ">" and directionality != "<"):
            raise SynSyntaxError("Unexpected flow directionality: %s" % directionality)

        tokens = tokens[2:]
        flow_dst = ""
        tok_ctr = 0
        for token in tokens:
            if (token == ':'):
                break
            else:
                flow_dst = "%s%s" % (flow_dst, token)
                tok_ctr = tok_ctr + 1
        tokens = tokens[tok_ctr+1:]
        flow_dst_port = tokens[0]
        tokens = tokens[1:]

        if (flow_proto.lower() == 'udp'):
            flow_proto = Flow.PROTO_UDP
        else:
            flow_proto = Flow.PROTO_TCP

        #logging.debug("Building flowdecl")

        #start to build our flow decl
        flowdecl = {}
        flowdecl['type'] = 'flow'
        flowdecl['name'] = flow_name
        flowdecl['proto'] = flow_proto
        flowdecl['src_host'] = self.resolve_dns(flow_src)
        flowdecl['src_port'] = flow_src_port
        flowdecl['dst_host'] = self.resolve_dns(flow_dst)
        flowdecl['dst_port'] = flow_dst_port
        flowdecl['flow'] = directionality
        flowdecl['attributes'] = {}

        if (tokens[0] == ";"):
            tokens = tokens[1:]

            #return flowdecl, tokens
            return (flowdecl, tokens)
        elif (tokens[0] == '('):
            tokens = tokens[1:]
            #parse modifiers

            while tokens[0] != ";":
                token = tokens[0]
                #print "token is %s" % token
                if (token == ")"):
                    #end of attribute spec. jump forward two (should always be ');')
                    tokens = tokens[1:]
                    break
                modifier_key = ""
                tok_ctr = 0
                single_modifier = False
                for token in tokens:
                    if (token == ':'):
                        tokens = tokens[tok_ctr+1:]
                        break
                    elif (token == ";"):
                        tokens = tokens[tok_ctr+1:]
                        single_modifier = True
                        break
                    else:
                        modifier_key = "%s%s" % (modifier_key, token)
                        tok_ctr = tok_ctr + 1

                #print "ModKey: %s" % modifier_key
                if (single_modifier == False):
                    modifier_value = ""
                    tok_ctr = 0
                    for token in tokens:
                        if (token == ';' or token == ")"):
                            tokens = tokens[tok_ctr+1:]
                            break
                        else:
                            modifier_value = "%s%s" % (modifier_value, token)
                            tok_ctr = tok_ctr + 1
                else:
                    modifier_value = True

                flowdecl['attributes'][modifier_key] = modifier_value

                #print "ModValue: %s" % modifier_value
            tokens = tokens[1:]
            #print 'Flowdecl: %s' % flowdecl
            #print 'Tokens: %s' % tokens
            return (flowdecl, tokens)
        else:
            parser_bailout("Invalid Syntax. unexpected value %s" % tokens[0])


    def lex_event(self, tokens):
        """ lex an event declarations"""
        logging.debug("lex_event() called with %s", tokens)

        flow_name = tokens[0]
        try:
            if (tokens[1] == '.'):
                idx_flowdir = 2
            else:
                idx_flowdir = 1        
        except IndexError:
            parser_bailout("Invalid Syntax. Unexpected flow directionality.")

        flow_directionality = tokens[idx_flowdir]
        tokens = tokens[idx_flowdir+1:]

        #print "Flow name: %s" % flow_name
        #print "Flow directionality: %s" % flow_directionality

        eventdecl = {}
        eventdecl['name'] = flow_name
        eventdecl['type'] = 'event'
        eventdecl['attributes'] = {}
        eventdecl['contents'] = []
        if (flow_directionality == '>' or flow_directionality == 'to_server'):
            eventdecl['flow'] = Flow.FLOW_TO_SERVER
        else:
            eventdecl['flow'] = Flow.FLOW_TO_CLIENT

        #print "Tokens are %s" % tokens

        if (tokens[0] == '('):
            tokens = tokens[1:]

            while tokens[0] != ";":
                token = tokens[0]
                #print "token is %s" % token
                if (token == ")"):
                    #end of attribute spec. jump forward two (should always be ');')
                    tokens = tokens[1:]
                    break
                modifier_key = ""
                tok_ctr = 0
                single_modifier = False
                for token in tokens:
                    if (token == ':'):
                        tokens = tokens[tok_ctr+1:]
                        break
                    elif (token == ";"):
                        tokens = tokens[tok_ctr+1:]
                        single_modifier = True
                        break
                    else:
                        modifier_key = "%s%s" % (modifier_key, token)
                        tok_ctr = tok_ctr + 1

                #print "ModKey: %s" % modifier_key
                if (single_modifier == False):
                    modifier_value = ""
                    tok_ctr = 0
                    for token in tokens:
                        if (token == ';' or token == ")"):
                            tokens = tokens[tok_ctr+1:]
                            break
                        else:
                            modifier_value = "%s%s" % (modifier_value, token)
                            tok_ctr = tok_ctr + 1
                else:
                    modifier_value = True

                if (modifier_key.lower() == 'content'):
                    #content
                    eventdecl['contents'].append({'type': 'string', 'value': modifier_value})
                elif (modifier_key.lower() == 'filecontent'):
                    #filecontent
                    eventdecl['contents'].append({'type': 'file', 'value': modifier_value})
                elif (modifier_key.lower() == 'uricontent'):
                    #uricontent
                    eventdecl['contents'].append({'type': 'uri', 'value': modifier_value})
                else:
                    eventdecl['attributes'][modifier_key] = modifier_value

                #print "ModValue: %s" % modifier_value
            
            #skip trailing ;
            tokens = tokens[1:]


        return (eventdecl, tokens)


class Flow:
    """a class for modeling a specific flow"""

    #consts for different protocols
    PROTO_TCP = 0
    PROTO_UDP = 1

    #consts for flow directionality
    FLOW_TO_SERVER = 0
    FLOW_TO_CLIENT = 1
    FLOW_BIDIRECTIONAL = 2

    #specific values for the flow
    proto = 0
    flow = 0
    name = ""
    src_mac = ""
    dst_mac = ""
    src_host = ""
    src_port = 0
    dst_host = ""
    dst_port = 0
    initialized = False
    timeline = []

    #tcp specific values
    to_server_seq = 0
    to_client_seq = 0
    to_server_ack = 0
    to_client_ack = 0
    tcp_mss = 1460

    #has test case
    def __init__(self, flowdecl = None):
        """constructor for the flow class. accepts a flowdecl (dictionary) with flow info"""
        if (type(flowdecl) != dict):
            parser_bailout("Flowdecl must be a dictionary.")
        try:
            self.name = flowdecl['name']
            self.proto = flowdecl['proto']
            self.src_host = flowdecl['src_host']
            self.src_port = flowdecl['src_port']
            self.flow = flowdecl['flow']
            self.dst_host = flowdecl['dst_host']
            self.dst_port = flowdecl['dst_port']
        except KeyError:
            parser_bailout("Invalid flowdecl passed to Flow.init")

        self.src_mac = RandMAC()
        self.dst_mac = RandMAC()

        self.to_server_seq = random.randint(10000, 99999)
        self.to_client_seq = random.randint(10000, 99999)
        self.to_server_ack = 0
        self.to_client_ack = 0
        self.tcp_server_bytes = 0
        self.tcp_client_bytes = 0

        try:
            self.tcp_mss = int(flowdecl['attributes']['mss'])
        except KeyError:
            self.tcp_mss = 1460

    #has test case
    #This function expects all inputs to be enclosed within double quotes
    def parse_content(self, content):
        """ parse and render a content keyword """
        #pcre_file = r"file\([^\)]+\)"
        #pcre_url = r"url\([^\)]+\)"
        pcre_text = r'"([^\\"]*(?:\\.[^\\"]*)*)"'

        #print "CONTENT: %s" % content
        
        #first, check for text
        mo_text = re.match(pcre_text, content)
        if (mo_text != None):
            logging.debug("Content: %s", mo_text.group(1))
        
            content_text = mo_text.group(1)
            replacements = re.findall(r"\\x[a-fA-F0-9]{2}", content_text)
            for replacement in replacements:
                content_text = content_text.replace(replacement, chr(int(replacement[2:], 16)))

            # replacements = re.findall(r"\|[A-Fa-f0-9\ ]+\|", content_text)
            # for replacement in replacements:
            #     #remove all spaces
            #     orig_replacement = replacement
            #     replacement = replacement.replace(" ","").replace("|","")
            #     replacement_text = ""
            #     for sub in [replacement[i:i+2] for i in range(0, len(replacement), 2)]:
            #         #break into groups of two characters
            #         replacement_text = "%s%s" % (replacement_text, chr(int(sub, base=16)))
            #     content_text = content_text.replace(orig_replacement, replacement_text)

            return content_text

    def render_payload(self, event):
        """ render all content matches into one payload value """
        str_payload = ""
        for modifier in event['attributes']:
            #logging.debug("Found modifier: %s", modifier)
            keyword = modifier
            value = event['attributes'][keyword]

            #logging.debug("Parsed keyword: %s value: %s", keyword, value)

        if 'contents' in event:
            for contentobj in event['contents']:
                content_value = contentobj['value']
                content_type = contentobj['type']
                if (content_type == 'string'):
                    str_payload = "%s%s" % (str_payload, self.parse_content(content_value))
                elif (content_type == 'file'):
                    str_payload = "%s%s" % (str_payload, self.get_file_content(content_value))

        return str_payload

    def get_file_content(self, filepath):
        #we need to strip quotes from the filepath
        filepath = filepath.strip()[1:-1]

        try:
            fptr = open(filepath,'r')
            fdata = fptr.read()
            fptr.close()
            return fdata.replace('"','\"')
        except IOError:
            raise SynCompileError("File not found -- %s" % filepath)
            sys.exit(-1)

    def format_port(port):
        """format a port specifier"""
        if type(port) == int:
            return int(port)
        elif type(port) == str and port.upper() == 'ANY':
            #return a random port between 1024 and 65k
            return random.randint(1024, 65000)
        elif type(port) == str:
            try:
                port = int(port)
                return port
            except ValueError:
                raise SynSyntaxError("Invalid Syntax. %s is not a valid port" % port)

    def render(self, eventid):
        """ render a specific eventid """
        
        event = self.timeline[eventid]
        pkts = []

        #get the payload
        hasPayload = False
        payload = ""
        total_payload = self.render_payload(event)
        if len(total_payload) > 0:
            hasPayload = True

        # 0-len payloads are OK, but only if no payload at beginning of render()
        # +-len payloads are OK, but dont get processed if they are zero-sized
        hasIterated = False
        while ((len(total_payload) > 0 and hasPayload == True) or (hasPayload == False and hasIterated == False)):
            hasIterated = True

            if (hasPayload == True):
                #we have a payload and we are using TCP; observe the MSS
                if (len(total_payload) > self.tcp_mss and self.proto == Flow.PROTO_TCP):
                    payload = total_payload[:self.tcp_mss]
                    total_payload = total_payload[self.tcp_mss:]
                else:
                    payload = total_payload
                    total_payload = ""

            #figure out what the src/dst port and host are

            if (event['flow'] == Flow.FLOW_TO_SERVER):
                #preserve src/dst
                src_host = self.src_host
                src_port = int(self.src_port)
                src_mac = self.src_mac
                dst_host = self.dst_host
                dst_port = int(self.dst_port)
                dst_mac = self.dst_mac

                #use the clients seq/ack
                self.tcp_server_bytes = self.tcp_server_bytes + len(payload)
                tcp_seq = self.to_server_seq
                tcp_ack = self.to_server_ack
                logging.debug("*** Flow %s --> S:%s A:%s B:%s", self.name, tcp_seq, tcp_ack, self.tcp_server_bytes)
                logging.debug("*** %s", self.timeline[eventid])
                
                #nooooooooooo
                if (len(payload) > 0):
                    #set tcp ack to last ack
                    tcp_ack = self.to_client_seq

            else:
                #reverse src/dst
                src_host = self.dst_host
                src_port = int(self.dst_port)
                src_mac = self.dst_mac
                dst_host = self.src_host
                dst_port = int(self.src_port)
                dst_mac = self.src_mac

                #use the servers seq/ack
                self.tcp_client_bytes = self.tcp_client_bytes + len(payload)
                tcp_seq = self.to_client_seq
                tcp_ack = self.to_client_ack
                logging.debug("*** Flow %s <-- S:%s A:%s B:%s", self.name, tcp_seq, tcp_ack, self.tcp_client_bytes)
                logging.debug("*** %s", self.timeline[eventid])

                if (len(payload) > 0):
                    tcp_ack = self.to_server_seq



            pkt = None
            logging.debug("SRC host: %s", src_host)
            logging.debug("DST host: %s", dst_host)
            lyr_ip = IP(src = src_host, dst = dst_host)
            lyr_eth = Ether(src = src_mac, dst = dst_mac)
            if (self.proto == Flow.PROTO_UDP):
                #generate udp packet
                lyr_udp = UDP(sport = src_port, dport = dst_port) / payload
                pkt = lyr_eth / lyr_ip / lyr_udp
                pkts.append(pkt)
            else:
                #generate tcp packet
                logging.debug("TCP Packet")
                
                #handle SEQ
                if 'tcp.seq' in event['attributes']:
                    logging.debug("tcp.seq has been set manually")
                    tcp_seq = event['attributes']['tcp.seq']
                    if (type(tcp_seq) == str):
                        tcp_seq = int(tcp_seq)

                if 'tcp.ack' in event['attributes']:
                    logging.debug("tcp.ack has been set manually")
                    tcp_ack = event['attributes']['tcp.ack']
                    if (type(tcp_ack) == str):
                        tcp_ack = int(tcp_ack)

                #check for tcp flags
                if 'tcp.flags.syn' in event['attributes']:
                    flags = "S"
                elif 'tcp.flags.ack' in event['attributes']:
                    flags = 'A'
                elif 'tcp.flags.synack' in event['attributes']:
                    flags = 'SA'
                elif 'tcp.flags.rst' in event['attributes']:
                    flags = 'R'
                    #implied noack
                    event['attributes']['tcp.noack'] = True
                else:
                    flags = 'PA'

                logging.debug('Data packet with inferred flags S:%s A:%s', tcp_seq, tcp_ack)
                lyr_tcp = TCP(flags=flags, seq=tcp_seq, ack=tcp_ack, sport = src_port, dport = dst_port) / payload
                pkt = lyr_eth / lyr_ip / lyr_tcp
                pkts.append(pkt)

                # if (event['flow'] == Flow.FLOW_TO_CLIENT):
                # 	#if flow is to the client, don't increment the PSH ACK, increment the following ack..
                #     #increment the SEQ based on payload size
                #     self.tcp_seq = self.tcp_ack
                #     self.tck_ack = self.tcp_ack + len(payload)

                logging.debug("Payload size is: %s" % len(payload))
                logging.debug("tcp_seq is %s" % tcp_seq)
                logging.debug("tcp_ack is %s" % tcp_ack)
                payload_size = len(payload)

                logging.debug("Moving to ACKnowledgement stage")

                #send an ACK
                if (event['flow'] == Flow.FLOW_TO_CLIENT):
                    logging.debug('SERVER requires ACK: Flow is TO_CLIENT')
                    #flow is SERVER -> CLIENT. Use SERVERs TCP SEQ #s
                    logging.debug("self.to_client_seq %s" % self.to_client_seq)
                    logging.debug("self.to_client_ack %s" % self.to_client_ack)
                    logging.debug("len payload %s" % len(payload))

                    tcp_seq = tcp_ack
                    tcp_ack = self.to_client_seq + len(payload)
                    
                    self.to_client_ack = self.to_client_seq + len(payload)
                    self.to_client_seq = self.to_client_ack

                    #trying to fix this:
                    #tcp_ack = self.to_client_seq + len(payload)
                    #tcp_seq = self.to_client_ack
                    
                    #self.to_client_ack = self.to_client_seq + len(payload)
                    #self.to_client_seq = self.to_client_ack

                    #previously commented out
                    #self.tcp_server_bytes = self.tcp_server_bytes + len(payload)
                    #self.to_server_ack = self.to_server_seq + len(payload)
                    #tcp_seq = self.to_server_ack
                    #tcp_seq = self.to_client_seq #None
                    #tcp_ack = self.to_client_ack
                else:
                    logging.debug('CLIENT requires ACK: Flow is TO_SERVER')
                    #self.tcp_client_bytes = self.tcp_client_bytes + len(payload)

                    tmp_ack = self.to_server_seq
                    tmp_seq = self.to_server_ack

                    #tcp_ack = self.to_server_seq #None
                    #tcp_seq = self.to_server_ack    #reversed
                    tcp_seq = tcp_ack
                    tcp_ack = tmp_ack + payload_size
                    

                    self.to_server_ack = self.to_server_seq + payload_size
                    self.to_server_seq = self.to_server_ack

                if 'tcp.noack' not in event['attributes']:
                    logging.debug('INFERRED ACK: S:%s A:%s', tcp_seq, tcp_ack)
                    lyr_eth = Ether(src = dst_mac, dst=src_mac)
                    lyr_ip = IP(src=dst_host, dst=src_host)
                    lyr_tcp = TCP(sport = dst_port, dport = src_port, flags='A', seq=tcp_seq, ack=tcp_ack)
                    pkt = lyr_eth / lyr_ip / lyr_tcp
                    pkts.append(pkt)


        logging.debug("*** End Render Flow")

        logging.debug("**Flow State Table **")
        logging.debug("to_server S: %s A: %s", self.to_server_seq, self.to_server_ack)
        logging.debug("to_client S: %s A: %s", self.to_client_seq, self.to_client_ack)
        logging.debug("*********************\n\n")


        #print hexdump(pkt)
        return pkts

def parse_cmd_line():
    """ use ArgumentParser to parse command line arguments """

    app_description = "FlowSynth v%s\nWill Urbanski <will.urbanski@gmail.com>\n\na tool for rapidly modeling network traffic" % APP_VERSION_STRING

    parser = argparse.ArgumentParser(description=app_description, formatter_class = argparse.RawTextHelpFormatter)
    parser.add_argument('input', help='input files')
    parser.add_argument('-f', dest='output_format', action='store', default="hex",
        help='Output format. Valid output formats include: hex, pcap')
    parser.add_argument('-w', dest='output_file', action='store', default="", help='Output file.')
    parser.add_argument('-q', dest='quiet', action='store_true', default=False, help='Run silently')
    parser.add_argument('-d', dest='debug', action='store_true', default=False, help='Run in debug mode')
    parser.add_argument('--display', dest='display', action='store', default='text', choices=['text','json'], help='Display format')

    args = parser.parse_args()

    if (args.quiet == True):
        LOGGING_LEVEL = logging.CRITICAL
    if (args.debug == True):
        LOGGING_LEVEL = logging.DEBUG

    return args

def main():
    """ the main function """

    global ARGS
    global LOGGING_LEVEL
    global START_TIME

    START_TIME = time.time()

    ARGS = parse_cmd_line()

    logging.basicConfig(format='%(levelname)s: %(message)s', level=LOGGING_LEVEL)

    run(ARGS.input)

    
def run(sFile):
    """ executes the compiler """
    global BUILD_STATUS

    #initialize the build status
    BUILD_STATUS['app_version'] = APP_VERSION_STRING
    BUILD_STATUS['successful'] = False
    BUILD_STATUS['compiler'] = {}
    BUILD_STATUS['compiler']['start-time'] = START_TIME
    BUILD_STATUS['compiler']['end-time'] = -1
    BUILD_STATUS['compiler']['instructions'] = -1
    BUILD_STATUS['compiler']['events'] = -1
    BUILD_STATUS['compiler']['packets'] = -1

    #load the syn file
    logging.debug("Entering file loading phase")
    filedata = load_syn_file(sFile)
    BUILD_STATUS['input-file'] = sFile
    BUILD_STATUS['output-file'] = ARGS.output_file
    BUILD_STATUS['output-format'] = ARGS.output_format

    #process all instructions
    logging.debug("Entering parse phase")
    process_instructions(filedata)

    #render all instructions
    logging.debug("Entering render phase")
    render_timeline()

    #Output handled here
    #for now, print to screen
    logging.debug("Entering output phase")
    output_handler()
    BUILD_STATUS['compiler']['end-time'] = END_TIME
    BUILD_STATUS['compiler']['time'] = END_TIME - START_TIME
    BUILD_STATUS['compiler']['instructions'] = len(COMPILER_INSTRUCTIONS)
    BUILD_STATUS['compiler']['events'] = len(COMPILER_TIMELINE)
    BUILD_STATUS['compiler']['packets'] = len(COMPILER_OUTPUT)
    #ARGS.output_format, len(COMPILER_INSTRUCTIONS), len(COMPILER_TIMELINE), len(COMPILER_OUTPUT)
    BUILD_STATUS['successful'] = True

    #print the summary to the screen
    output_summary()

def output_summary():
    """print an output summary"""
    global RUNTIME
    if (ARGS.quiet == False):
        if (ARGS.display == 'text'):
            print "\n ~~ Build Summary ~~"
            print "Runtime:\t\t%ss\nOutput format:\t\t%s\nRaw instructions:\t%s\nTimeline events:\t%s\nPackets generated:\t%s\n" % ( RUNTIME, ARGS.output_format, len(COMPILER_INSTRUCTIONS), len(COMPILER_TIMELINE), len(COMPILER_OUTPUT))
        else:
            print json.dumps(BUILD_STATUS)

def output_handler():
    """ decide what to do about output """
    global ARGS
    global COMPILER_OUTPUT
    global COMPILER_TIMELINE
    global COMPILER_INSTRUCTIONS
    global START_TIME
    global END_TIME
    global RUNTIME

    if (ARGS.output_format == "hex"):
        hex_output()
    else:
        pcap_output()

    #print the output summary
    END_TIME = time.time()
    RUNTIME = round(END_TIME - START_TIME, 3)


#has test case
def pcap_output():
    """ write a libpcap formatted .pcap file containing the compiler output """
    global ARGS
    global COMPILER_OUTPUT

    if (len(COMPILER_OUTPUT) == 0):
        compiler_bailout("No output to write to disk.")

    if (ARGS.output_file == ""):
        raise SynTerminalError("No output file provided.")

    wrpcap(ARGS.output_file, COMPILER_OUTPUT)

def hex_output():
    """ produce a hexdump of the compiler output """
    global COMPILER_OUTPUT
    for pkt in COMPILER_OUTPUT:
        hexdump(pkt)

def render_timeline():
    """ render the global and flow timelines into COMPILER_OUTPUT """
    global COMPILER_TIMELINE
    global COMPILER_FLOWS

    for eventref in COMPILER_TIMELINE:
        flowname = eventref['flow']
        eventid = eventref['event']

        #have the flow render the pkt, and add it to our global output queue
        pkts = COMPILER_FLOWS[flowname].render(eventid)
        for pkt in pkts:
            COMPILER_OUTPUT.append(pkt)

def process_instructions(instr):
    global COMPILER_FLOWS
    global COMPILER_OUTPUT
    global COMPILER_TIMELINE
    global COMPILER_INSTRUCTIONS

    try:
        lexer = FSLexer(instr)
        #print lexer.instructions

        COMPILER_INSTRUCTIONS = lexer.instructions

        for instr in lexer.instructions:
            name = instr['name']
            if instr['type'] == 'flow':
                #check if flow exists already ?
                if name in COMPILER_FLOWS:
                    logging.warning("Flow '%s' being redeclared!", name)

                #add the flow to the timeline
                add_flow(name, instr)

                if 'tcp.initialize' in instr['attributes']:
                    #add tcp establishment 
                    autogen_handshake(instr)

            else:
                #add an event instead
                add_event(name, instr)
    except SynSyntaxError as e:
        logging.critical("Syntax Error - %s" % (e.value))
        sys.exit(0)


def autogen_handshake(flowdecl):
    """generate render events for the tcp three-way handshake"""
    global COMPILER_TIMELINE
    global COMPILER_FLOWS

    parent_flow = COMPILER_FLOWS[flowdecl['name']]

    client_isn = 10    #random.randint(10000, 99999)
    server_isn = 100   #random.randint(10000, 99999)

    #send syn
    eventdecl = {}
    eventdecl['name'] = flowdecl['name']
    eventdecl['type'] = 'event'
    eventdecl['flow'] = Flow.FLOW_TO_SERVER
    eventdecl['attributes'] = {}
    eventdecl['attributes']['tcp.flags.syn'] = True
    eventdecl['attributes']['tcp.noack'] = True
    eventdecl['attributes']['tcp.seq'] = client_isn
    eventdecl['attributes']['tcp.ack'] = None
    add_event(flowdecl['name'], eventdecl)

    #send synack
    eventdecl = {}
    eventdecl['name'] = flowdecl['name']
    eventdecl['type'] = 'event'
    eventdecl['flow'] = Flow.FLOW_TO_CLIENT
    eventdecl['attributes'] = {}
    eventdecl['attributes']['tcp.flags.synack'] = True
    eventdecl['attributes']['tcp.noack'] = True
    eventdecl['attributes']['tcp.seq'] = server_isn
    eventdecl['attributes']['tcp.ack'] = client_isn + 1
    add_event(flowdecl['name'], eventdecl)

    #send ack
    eventdecl = {}
    eventdecl['name'] = flowdecl['name']
    eventdecl['type'] = 'event'
    eventdecl['flow'] = Flow.FLOW_TO_SERVER
    eventdecl['attributes'] = {}
    eventdecl['attributes']['tcp.flags.ack'] = True
    eventdecl['attributes']['tcp.noack'] = True
    eventdecl['attributes']['tcp.ack'] = server_isn + 1
    eventdecl['attributes']['tcp.seq'] = client_isn + 1
    add_event(flowdecl['name'], eventdecl)

    #dont set the parent flows SEQ/ACK until the end of this process
    parent_flow.to_server_seq = client_isn + 1
    parent_flow.to_client_seq = server_isn + 1
    parent_flow.to_server_ack = client_isn
    parent_flow.to_client_ack = server_isn + 1


#has test case
def add_flow(flowname, flowdecl):
    """adds a flow to the global flow manager"""
    global COMPILER_FLOWS
    logging.debug("Declaring flow %s [%s]", flowname, flowdecl)
    if (type(flowdecl) is not dict):
        compiler_bailout("Invalid flow decl passed to add_flow()")

    new_flow = Flow(flowdecl)
    COMPILER_FLOWS[flowname] = new_flow


#has test case
def add_event(flowname, eventdecl):
    """adds an event to the global timeline"""
    global COMPILER_FLOWS
    logging.debug("Declaring event in flow %s [%s]", flowname, eventdecl)

    if (type(eventdecl) is not dict):
        compiler_bailout("Invalid event decl passed to add_event()")

    #save the eventdecl to the flows local timeline
    try:
        COMPILER_FLOWS[flowname].timeline.append(eventdecl)
    except KeyError:
        compiler_bailout("Flow [%s] has not been instantiated." % flowname)

    #create an eventref for the global compiler timeline, and add it to that timeline
    eventref = {'flow': flowname, 'event': len(COMPILER_FLOWS[flowname].timeline)-1}
    COMPILER_TIMELINE.append(eventref)

#has test case
def load_syn_file(filename):
    """ loads a flowsynth file from disk and returns as a string"""
    try:
        filedata = ""
        fptr = open(filename,'r')
        filedata = fptr.read()
        fptr.close()
    except IOError:
        compiler_bailout("Cannot open file ('%s')", filename)

    return filedata

#helper function to report runtime errors
def compiler_bailout(msg):
    try:
        if ARGS.display == 'text':
            logging.critical("A unrecoverable runtime error was detected.")
            logging.critical(">> %s ", msg)
            logging.critical("Flowsynth is terminating.")
            raise SynTerminalError(msg)
        else:
            BUILD_STATUS['error'] = msg
            output_summary()
            sys.exit(-1)
    except AttributeError:
        raise SynTerminalError(msg)

#helper function to report syntax errors
def parser_bailout(msg):
    try:
        if ARGS.display == 'text':
            logging.critical("A unrecoverable syntax error was detected.")
            logging.critical(">> %s ", msg)
            logging.critical("Flowsynth is terminating.")
            raise SynSyntaxError(msg)
        else:
            BUILD_STATUS['error'] = msg
            output_summary()
            sys.exit(-1)
    except AttributeError:
        raise SynSyntaxError(msg)
        
def show_build_status():
    """print the build status to screen"""
    print json.dumps(BUILD_STATUS)

#application entrypoint
if __name__ == '__main__':
    main()