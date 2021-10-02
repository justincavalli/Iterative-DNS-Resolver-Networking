#Iterative DNS resolver that resolves A, CNAME, and MX records for hostnames with valid top-level domains
#Can test functionality by running 'resolver_tester.py' test script
#Authors: Chadmond Wu, Justin Cavalli

import sys
import socket
import argparse
import random

from struct import *

def stringToNetwork(orig_string):
    """
    Converts a standard string to a string that can be sent over
    the network.

    Args:
        orig_string (string): the string to convert

    Returns:
        bytes: The network formatted string (as bytes)

    Example:
        stringToNetwork('www.sandiego.edu.edu') will return
          (3)www(8)sandiego(3)edu(0)
    """
    ls = orig_string.split('.')
    toReturn = b""
    for item in ls:
        formatString = "B"
        formatString += str(len(item))
        formatString += "s"
        toReturn += pack(formatString, len(item), item.encode())
    toReturn += pack("B", 0)
    return toReturn


def networkToString(response, start_index):
    """
    Converts a network response string into a human readable string.

    Args:
        response (string): the entire network response message
        start_index (int): the location within the message where the network string
            start_indexs.

    Returns:
        A (string, int) tuple
            - string: The human readable string.
            - int: The start_index one past the end of the string, i.e. the start_indexing
              start_index of the value immediately after the string.

    Example:  networkToString('(3)www(8)sandiego(3)edu(0)', 0) would return
              ('www.sandiego.edu', 18)
    """

    toReturn = ""
    position = start_index
    length = -1
    while True:
        length = unpack("!B", response[position:position+1])[0]
        if length == 0:
            position += 1
            break

        # Handle DNS pointers (!!)
        elif (length & 1 << 7) and (length & 1 << 6):
            b2 = unpack("!B", response[position+1:position+2])[0]
            offset = 0
            """
            # strip off leading two bits shift by 8 to account for "length"
            # being the most significant byte
            ooffset += (length & 1 << i)ffset += (length & 0x3F) << 8  

            offset += b2
            """
            for i in range(6) :
                offset += (length & 1 << i) << 8
            for i in range(8):
                offset += (b2 & 1 << i)
            dereferenced = networkToString(response, offset)[0]
            return toReturn + dereferenced, position + 2

        formatString = str(length) + "s"
        position += 1
        toReturn += unpack(formatString, response[position:position+length])[0].decode()
        toReturn += "."
        position += length
    return toReturn[:-1], position


def constructQuery(ID, hostname, query_type):
    """
    Constructs a DNS query message for a given hostname and ID.

    Args:
        ID (int): ID # for the message
        hostname (string): What we're asking for
        query_type: Query type for the message (ex. A, MX)

    Returns:
        string: "Packed" string containing a valid DNS query message
    """
    flags = 0 # 0 implies basic iterative query

    # one question, no answers for basic query
    num_questions = 1
    num_answers = 0
    num_auth = 0
    num_other = 0

    # "!HHHHHH" means pack 6 Half integers (i.e. 16-bit values) into a single
    # string, with data placed in network order (!)
    header = pack("!HHHHHH", ID, flags, num_questions, num_answers, num_auth,
                  num_other)

    qname = stringToNetwork(hostname)
    remainder = pack("!HH", query_type, 1)
    query = header + qname + remainder
    return query

def resolve(hostname, is_mx=False):
    """
    Returns a string with the IP address (for an A record) or name of mail
    server associated with the given hostname.

    Args:
        hostname (string): The name of the host to resolve.
        is_mx (boolean): True if requesting the MX record result, False if
          requesting the A record.

    Returns:
        string: A string representation of an IP address (e.g. "192.168.0.1") or
          mail server (e.g. "mail.google.com"). If the request could not be
          resolved, None will be returned.
    """
    print("Hostname: " + hostname)

    # generate a list of the root servers from the txt file
    root_file = open("root-servers.txt", "r")
    root_list = []
    for line in root_file:
        root_list.append(line[0:-1]) 
    root_file.close()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)   # socket should timeout after 5 seconds

    # Generate a random ID
    ID = random.randint(0, 65535)
    query_type = 1

    #Check for invalid MX request with subdomain (ex. www.sandiego.edu)
    substring = "www"
    if (is_mx == True and substring in hostname):
        sock.close()
        print("Cannot resolve MX subdomain request (SOA), please try again with domain hostname")
        return None
    elif (is_mx == True):
        query_type = 15 #Set query to 15, MX record

    # Create an (example) query 
    query = constructQuery(ID, hostname, query_type)
    try:
        # Send the message to a server IP listed in root-servers.txt
        sock.sendto(query, (str(root_list[0]), 53))
        
        print("\nQuerying root server from root-servers.txt") 

        # Receive the response (timing out after 5 seconds)
        response = sock.recv(4096)
        print("Query response received, unpacking the query now")

        #Check for recv errors (-1, 0)
        if (response == -1):
            print("Server error")
            sock.close()
            return None
        elif (response == 0):
            print("Connection closed")
            sock.close()
            return None

        sock.close()

        # Extracting the necessary information from the response to get the answer
        header = response[0:12] 
        ID, flags, num_questions, num_answers, num_auth, num_other = unpack("!HHHHHH", header) #all hex
        start_index = 12 # Header makes up first 12 bytes

        #user friendly query summary messages
        print("Questions: " + str(num_questions) + ", Answer RRs: " +
        str(num_answers) + ", Authority RRs: " + str(num_auth) + ", Additional RRs: " + str(num_other) + "\n")
        
        #Parsing questions
        for i in range(num_questions):
            start_index = parseQuestions(start_index, response)

        #Flags should be 1 0000 1 0 0 1 000 0000 for A record
        #Query Response, standard query, authoritative, non-truncated,
        #Recursion desired, recursion not available, reserved bits, no error

        # check the flags to see if the name is valid
        # last 4 bits are reply code, AND all bits except last 4 to check
        reply_code = str(flags & 0xF)
        if (reply_code == "3"):
            print("Invalid hostname")
            return None 

        #Parsing answers
        answer_buffer = []
        for i in range(num_answers):
            start_index, answer, answer_type = parseAnswer(start_index, response, query_type)
            if answer_type == 6:
                print("Received SOA, server was unable to provide information, please try again with valid hostname")
                return None
                #Should not run into a CNAME record at this point

            #Append answers, auth info, additional info to separate arrays to parse through
            #Will return first element of array (e.g first domain in MX query)
            answer_buffer.append(answer)
        
        #Parsing authoritative section
        auth_buffer = []
        for i in range(num_auth):
            start_index, auth, answer_type = parseAuth(start_index, response, num_auth)
            auth_buffer.append(auth)

        #Parsing additional section
        add_buffer = []
        for i in range(num_other):
            start_index, add, answer_type = parseAdd(start_index, response, num_other)
            add_buffer.append(add)

        #If an answer is found immediately, it is most likely an A record
        if (num_answers > 0):
            return answer_buffer[0]
        
        #If no answers found, invoke a recursive query, most likely for CNAME/MX/NS records
        elif (num_auth > 0):
            return iterateQuery(ID, hostname, query_type, auth_buffer, 0)
        elif (num_other > 0):
            return iterateQuery(ID, hostname, query_type, add_buffer, 0)

    #If the first server given timeouts, try the next server down the root list
    except socket.timeout as e:
        print("Exception:", e)
        print("The connection timed out, trying to reconnect...")
        sock.close()
        return iterateQuery(ID, hostname, query_type, root_list, 1)

    return None #default case, request error

def iterateQuery(ID, hostname, query_type, root_list, timeout_flag):
    """
    Recursive call for resolve() that iteratively traverses the hierarchy
    until obtaining a list of answer responses, which it returns

    Args:
        ID (int): a randomly generated ID number for the query
        hostname (string): the name of the host to resolve
        query_type (int): a number representing the type of query
        root_list (list): list of servers to query
        timeout_flag (int): integer that is set (like bool) when the socket timeouts

    Returns:
        returns a buffer of answer records or None if it could not be resolved 
    """
    # constructing queries from the generated list of servers 
    for root in root_list:
        query = constructQuery(ID, hostname, query_type)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)   # socket should timeout after 5 seconds

    try:
        if (timeout_flag == 0): #normal operation, send the first root server listed
            sock.sendto(query, (root, 53))
            print("Querying the server: " + root_list[0])
        elif (timeout_flag == 1): #if the query times out, try to send another query to the next server listed
            sock.sendto(query, (root_list[1], 53))
            print("Querying the server: " + root_list[1])
        
        # Receive the response (timing out after 5 seconds)
        response = sock.recv(4096)
        print("Query response received, unpacking the query now")

        #Checking for recv errors
        if (response == -1):
            print("Server error")
            return None
        elif (response == 0):
            print("Connection closed")
            return None
        
        sock.close()
        
        # unpacking the header (12 bytes)
        header = response[0:12]
        ID, flags, num_questions, num_answers, num_auth, num_other = unpack("!HHHHHH", header)
        start_index = 12
   
   
        #user friendly query summary messages
        print("Questions: " + str(num_questions) + ", Answer RRs: " +
        str(num_answers) + ", Authority RRs: " + str(num_auth) + ", Additional RRs: " + str(num_other) + "\n")

        # check the flags to see if the name is valid 
        # last 4 bits are reply code, AND all bits except last 4 to check
        reply_code = str(flags & 0xF)
        if (reply_code == "3"):
            print("Invalid hostname")
            return None 

        #Parsing questions
        for i in range(num_questions):
            start_index = parseQuestions(start_index, response)

        #Parsing answers
        answer_buffer = []
        for i in range(num_answers):
            start_index, answer, answer_type = parseAnswer(start_index, response, query_type)
            if answer_type == 6: #DNS record 6: SOA (start of authority record)
                print("Received SOA, server was unable to provide information, please try again with valid hostname")
                return None

            elif answer_type == 5:
                return resolve(answer) #If CNAME record, restart entire query process with new hostname
                                        #Assumes that we must resolve alias once 
                
            answer_buffer.append(answer)
        
        #Parsing authoritative section
        auth_buffer = []
        for i in range(num_auth):
            start_index, auth, answer_type = parseAuth(start_index, response, num_auth)
            auth_buffer.append(auth)

        #Parsing additional section
        add_buffer = []
        for i in range(num_other):
            start_index, add, answer_type = parseAdd(start_index, response, num_other)
            add_buffer.append(add)

        if (num_answers > 0):
            return answer_buffer[0]
        
        #Further recursive calls to search for valid answer records
        elif (num_auth > 0):
            return iterateQuery(ID, hostname, query_type, auth_buffer, 0)
        elif (num_other > 0):
            return iterateQuery(ID, hostname, query_type, add_buffer, 0)

    #If the first server given timeouts, try the next server down
    except socket.timeout as e:
        print("Exception:", e)
        print("The connection timed out, trying to reconnect...")
        sock.close()
        return iterateQuery(ID, hostname, query_type, root_list, 1)

    return None #default case, request could not be resolved

def parseQuestions(start_index, response):
    """
    Returns the last start_index where the question segment ends

    Args:
        start_index (int): start_index of where the answer is indexed
        response (string): the network response message
    """

    question, start_index = networkToString(response, start_index)
    question_type, question_class = unpack("!HH", response[start_index:start_index + 4]) #Type and Class are 2 bytes each
    start_index += 4
    return start_index

def parseAnswer(start_index, response, query_type):
    """
    Parses the answer record and returns the corresponding data depending on
    the type (A, MX, NS, or CNAME), along with the index and type

    Args:
        start_index (int): index of where the answer record starts
        response (string): the network response message
        query_type (int): query type for the message (ex. A, MX, CNAME)

    Returns:
        3-tuple containing the index after the answer record, the answer data
        (IP, mail exchange, or CNAME depending on the query type), and the
        answer type
    """
    # MX type (handle seperately)
    if query_type == 15:
        ans_name, start_index = networkToString(response, start_index)
        ans_type, ans_class, ans_ttl, ans_len, pref = unpack("!HHIHH", response[start_index:start_index + 12]) #all fields are 2 bytes except ttl, which is 4
        start_index += 12
        mail_exchange, start_index = networkToString(response, start_index) #return mail name of domain
        return start_index, mail_exchange, ans_type
    
    #unpack the first 10 bytes (the same for type A and CNAME)
    ans_name, start_index = networkToString(response, start_index)
    ans_type, ans_class, ans_ttl, ans_len = unpack("!HHIH", response[start_index:start_index + 10])
    start_index += 10

    # A type 
    if ans_type == 1:
        ans_data = ""

        # unpack the IP address byte by byte (IPv4)
        # put each byte into temp array, separate with '.'
        for i in range(ans_len):
            temp = unpack("!B", response[start_index:start_index + 1])
            ans_data += str(temp[0])
            start_index += 1
            if (i < ans_len-1):
                ans_data += "."

        return start_index, ans_data, ans_type
    
    #CNAME type
    elif ans_type == 5: 
        c_name, start_index = networkToString(response, start_index)
        return start_index, c_name, ans_type       


def parseAuth(start_index, response, num_auth):
    """
    Parses the authority record and returns the hostname from the response
    (along with the index and type)

    Args: 
        start_index (int): index of where the authority record starts
        response (string): the network response message
        num_ath (int): the amount of authority records

    Returns:
        3-tuple containing the index after the authority record, the hostname
        given by the authority response, and the type 
    """
    
    # unpack the first 10 bytes of the message
    auth_name, start_index = networkToString(response, start_index)
    auth_type, auth_class, auth_ttl, auth_len = unpack("!HHIH", response[start_index:start_index + 10])
    start_index += 10

    # extract the hostname
    auth_data, start_index = networkToString(response, start_index)
    return start_index, auth_data, auth_type

def parseAdd(start_index, response, num_other):
    """
    Parses the additional record and returns the IP address depending on IPv4
    or IPv6 (along with the index and type)

    Args: 
        start_index (int): index of where the additional record starts
        response (string): the network response message
        num_other (int): the amount of additional records

    Returns:
        3-tuple containing index after the addional record, the IP address
        (either IPv4 or IPv6), and the type
    """
    
    # unpack the first 10 bytes of the message
    add_name, start_index = networkToString(response, start_index)
    add_type, add_class, add_ttl, add_len = unpack("!HHIH", response[start_index:start_index + 10])
    start_index += 10
    add_data = ""
    
    # MX record preference field
    if add_type == 15:
        pref = unpack("!H", response[start_index:start_index + 2])
        start_index += 2
    
    # unpack the IP address (IPv6)
    # put each set of 4 bytes into temp array, separate with '.'
    if add_type == 28:
        for i in range(int(add_len)//4): #looping through every 4 bytes
            # unpack 4 bytes at a time
            temp = unpack("!I", response[start_index:start_index + 4])
            add_data += str(temp[0])
            start_index += 4
            if (i < add_len-4):
                add_data += "."

    # IPv4 address, parse the same way as parseAnswer()
    else:
        for i in range(add_len):
            #unpack 1 byte at a time
            temp = unpack("!B", response[start_index:start_index + 1])
            add_data += str(temp[0])
            start_index += 1
            if (i < add_len-1):
                add_data += "."
    
    return start_index, add_data, add_type

def main(argv):

    #Parse CLI arguments for hostname and MX flag, automatically checks for valid args, implements -h help parameter
    parser = argparse.ArgumentParser(description='Resolve a DNS query using a root server from root-servers.txt')
    parser.add_argument('-m', action='store_true', help="Set this flag to request a MX record")
    parser.add_argument("hostname", help="The hostname to resolve", type=str)
    args = parser.parse_args()

    hostname = args.hostname
    is_mx = False #default is A record

    if args.m:
        is_mx = True #-m flag is set, get a MX record

    answer = resolve(hostname, is_mx) #returns hostname/IP from answer record
    if answer is not None:
        if (is_mx):
            print("The mail exchange for " + hostname + " resolves to: " + answer)
        else:
            print("The name " + hostname + " resolves to: " + answer)
    else:
        print("Could not resolve request.")

if __name__ == "__main__":
    main(sys.argv)