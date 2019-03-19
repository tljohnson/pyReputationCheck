### This script is designed to check a list of file hashes against VirusTotal. It will run
### 4 queries per minute and then rest 60 seconds in order to get around the VT throttling
### on public API calls. The output is specifically comparing against what a specific vendor
### thinks of a hash. 
### 
### One limitation of this script is that all hashes must be checked before the output file
### will be written.
###
### Example CSV output:
### hash, result
### 019e7eb13266ce0d556f1a30a1fd469d, McAfee: W97M/Downloader.ea
### 024e1550ed5cba2100bf8a4ef54f9e1f, Clean? Detected malicious by 12/64
### 025c1c35c3198e6e3497d5dbf97ae81f, McAfee: Generic.ayq
###
### Author: Tyler Johnson
### Date: March 2019
### Version: 1.0

import requests
import csv
import time

# primary vendor to check hashes against in VirusTotal
vendor = 'McAfee'
# input_file expects a plain txt document with one file hash per line
input_file = 'hashlist.txt'
# output_file will be a CSV
output_file = 'hash_check.csv'
# VirusTotal API key. You can also replace the following line with apikey = 'key'
from credentials import apikey

def write_dict_to_csv( file, columns, *args ):
    output_file = file
    csv_columns = columns

    # create the output file - important to remember utf-8 encoding on Windows
    # include extrasaction='ignore' if the dict has more fields than we want to print
    with open(output_file, 'w', encoding='utf-8') as csvfile:
        # init the csv writer
        writer = csv.DictWriter(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL, 
                            lineterminator = '\n', fieldnames=csv_columns, extrasaction='ignore')
        writer.writeheader()
        
        for hash_list in args:
            for hash in hash_list:
                writer.writerow(hash)

def check_hash( apikey, resource ):
    params = {'apikey': apikey, 'resource': resource}
    headers = {}
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
            if json_response['response_code'] == 1:
                if vendor in json_response['scans'] and json_response['scans'][vendor]['result']:
                    return "{}: {}".format(vendor, json_response['scans'][vendor]['result'])
                else:
                    return "Clean? Detected malicious by {}/{}".format(json_response['positives'],json_response['total']) 
            else:
                print("Response code {} for resource {} :: {}".format(json_response['response_code'], resource, json_response['verbose_msg']))
                return "No match"
        else:
            print("Response code {}. Sleeping 60 seconds...".format(response.status_code))
            time.sleep(60)
            check_hash(apikey, resource)
    except requests.exceptions.RequestException as error:
        print(error)
        time.sleep(5)
        check_hash(apikey, resource)

def main():
    with open(input_file) as file:
        hash_list = file.read().splitlines()

    check_results = []

    for file_hash in hash_list:
        result = check_hash( apikey, file_hash )
        print(file_hash, result)
        check_results.append( { 'hash': file_hash,
                            'result': result } )

    csv_columns = ['hash', 'result']

    write_dict_to_csv( output_file, csv_columns, check_results )

if __name__ == '__main__':
    main()