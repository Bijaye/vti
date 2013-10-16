#!/usr/bin/env python
#
# a script to make use of the various api methods available from VirusTotal.
# see the -h output for a list of supported api methods available. supports
# downloading of files from the virustotal intelligence portal provided you
# have an api key with that permission.
#
# built on a script from Adam Meyers @ CrowdStrike
#
# no license, go nuts
#
# madvillain
# villain@evilthings.org
#
__author__ = 'madvillain'
__version__ = '0.1'
__email__ = 'villain[at]evilthings.org'

import json
import optparse
import argparse
import hashlib
import os
import re
import sys
import pprint
import time
import urllib
import urllib2
import postfile

# set to location where files will be stored
LOCAL_STORE = 'files'

def title():
    print "-----------------------------------------------"
    print "\tvti",__version__ , "\n"
    print "\t", __email__
    print "\thttp://www.evilthings.org"
    print "-----------------------------------------------"
    print

def create_download_folder(query=None):
  folder_name = time.strftime('%Y%m%dT%H')
  if not os.path.exists(LOCAL_STORE):
    os.mkdir(LOCAL_STORE)
  folder_path = os.path.join(LOCAL_STORE, folder_name)
  if not os.path.exists(folder_path):
    os.mkdir(folder_path)
  return folder_path


class virustotalAPI():
    def __init__(self):
        self.api = '*** YOUR APIKEY HERE ***'
        self.base = 'https://www.virustotal.com/vtapi/v2/'
        self.iurl = 'https://www.virustotal.com/intelligence/download/?hash=%s&apikey=%s'

    def getFileReport(self, md5):
        param = {'resource': md5, 'apikey': self.api}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url, data)
        jsondata = json.loads(result.read())
        return jsondata

    def getURLReport(self, vturl):
        param = {'resource': vturl, 'apikey': self.api}
        url = self.base + "url/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url, data)
        jsondata = json.loads(result.read())
        return jsondata

    def scanURL(self, vturl):
        param = {'url': vturl, 'apikey': self.api}
        url = self.base + "url/scan"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url, data)
        print "\n\t[x] VirusTotal scan initiated for: " + vturl + "\n"

    def rescan(self, md5):
        param = {'resource': md5, 'apikey': self.api}
        url = self.base + "file/rescan"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url, data)
        print "\n\t[x] VirusTotal rescan initiated for: " + md5 + "\n"

    def getIPReport(self, vtip):
        param = {'ip': vtip, 'apikey': self.api}
        url = self.base + "ip-address/report"
        response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(param))).read()
        jsondata = json.loads(response)
        return jsondata

    def getDomainReport(self, vtdomain):
        param = {'domain': vtdomain, 'apikey': self.api}
        url = self.base + "domain/report"
        response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(param))).read()
        jsondata = json.loads(response)
        #print jsondata.dumps(jsondata, sort_keys=True, indent=4)
        return jsondata

    def submitfile(self, vtfile):
        host = "www.virustotal.com"
        selector = "https://www.virustotal.com/vtapi/v2/file/scan"
        fields = [("apikey", self.api)]
        file_to_send = open(vtfile, "rb").read()
        files = [("file", vtfile, file_to_send)]
        jsondata = postfile.post_multipart(host, selector, fields, files)
        print "\n\t[x] VirusTotal scan initiated for: " + vtfile + "\n"
        return jsondata

    def getIntelFile(self, md5):
        param = {'resource': md5, 'apikey': self.api}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url, data)
        jsondata = json.loads(result.read())
        filesha256 = jsondata.get("sha256")
        folder = create_download_folder()
        destination_file = os.path.join(folder, md5)
        if filesha256 is not None:
            fileloc = self.iurl %(filesha256, self.api)
            try:
                urllib.urlretrieve(fileloc, destination_file)
                print "\t[x] Successfully retrieved:", md5, "to", folder,"\n"
                return
            except Exception:
                print "\t[x] Failed to retrieve:", md5,"\n"
                return
        else:
            print "\t[x] Not found in VirusTotal intelligence database:", md5,"\n"
        return jsondata

# parse functions

def parsemd5(vtdata, md5):
  if vtdata['response_code'] == 0:
    print "\t[x] No reports for hash:", md5,"\n"
    return 0
  if vtdata['response_code'] == -2:
    print "\t[x] Still queued for processing\n"
    return 0
  print "\t[x] Details for file\n\n\t\tsha1:",vtdata['sha1'],"\n\t\tsha256:",vtdata['sha256'],"\n\t\tmd5:",vtdata['md5'],"\n\n\tDetections:",vtdata['positives'],'/',vtdata['total'], "\n\tScan Date:",vtdata['scan_date'],"\n"
  for engine in vtdata['scans']:
      print '\t', engine,'\t' if len(engine) < 7 else '','\t' if len(engine) < 14 else '','\t',vtdata['scans'][engine]['detected'], '\t',vtdata['scans'][engine]['result']
  print

def parseurl(vtdata, vturl):
  if vtdata['response_code'] == 0:
    print "\t[x] No reports for URL:", vturl,"\n"
    return 0
  if vtdata['response_code'] == -2:
    print "\t[x] Still queued for processing\n"
    return 0
  print "\t[x] Results for URL:",vtdata['url'],"\n\n\tDetections:",vtdata['positives'],'/',vtdata['total'],"\n\tScan Date:",vtdata['scan_date'],"\n"
  for engine in vtdata['scans']:
    print '\t', engine,'\t\t' if len(engine) < 7 else '\t','\t' if len(engine) < 14 else '','\t',vtdata['scans'][engine]['detected'], '\t',vtdata['scans'][engine]['result']
  print

def parseip(vtdata, vtip):
  if vtdata['response_code'] == 0:
    print "\t[x] No reports for IP:", vtip,"\n"
    return 0
  if vtdata['response_code'] == -2:
    print "\t[x] Still queued for processing\n"
    return 0
  print "\n\t[x] Results for IP:",vtip,"\n"

  print "\t[x] Passive DNS Info:\n"
  print "\t\t%-24s%s" % ("Last Resolved","Hostname")
  for res in vtdata["resolutions"]:
    print "\t\t%-24s%s" % (res["last_resolved"],res["hostname"])

  if "undetected_downloaded_samples" in vtdata:
    print "\n\t[x] Undetected Downloaded Samples\n"
    print "\t\t%-13s %-20s %-19s" % ("Detections","Scan Date","sha256")
    for res in vtdata["undetected_downloaded_samples"]:
      print "\t\t%d / %-9d %-20s %s" % (res["positives"],res["total"],res["date"],res["sha256"])

  if "detected_urls" in vtdata:
    print "\n\t[x] Detected URLs\n"
    print "\t\t%-13s %-20s %-19s" % ("Detections","Scan Date","URL")
    for res in vtdata["detected_urls"]:
      print "\t\t%d / %-9d %-20s %s" % (res["positives"],res["total"],res["scan_date"],res["url"],)
    print

def parsedomain(vtdata, vtdomain):
  if vtdata['response_code'] == 0:
    print "\t[x] No reports for domain:", vtdomain,"\n"
    return 0
  if vtdata['response_code'] == -2:
    print "\t[x] Still queued for processing\n"
    return 0
  print "\n\t[x] Results for Domain:", vtdomain,"\n"

  print "\t[x] Passive DNS Info:\n"
  print "\t\t%-24s%s" % ("Last Resolved","IP Address")
  for res in vtdata["resolutions"]:
    print "\t\t%-24s%s" % (res["last_resolved"],res["ip_address"])

  if "detected_downloaded_samples" in vtdata:
    print "\n\t[x] Detected Downloaded Samples\n"
    print "\t\t%-13s %-20s %-19s" % ("Detections","Scan Date","sha256")
    for res in vtdata["detected_downloaded_samples"]:
      print "\t\t%d / %-9d %-20s %s" % (res["positives"],res["total"],res["date"],res["sha256"])

  if "detected_urls" in vtdata:
    print "\n\t[x] Detected URLs\n"
    print "\t\t%-13s %-20s %-19s" % ("Detections","Scan Date","URL")
    for res in vtdata["detected_urls"]:
      print "\t\t%d / %-9d %-20s %s" % (res["positives"],res["total"],res["scan_date"],res["url"],)
  print

def main():
  title()
  arg=argparse.ArgumentParser(description="search and download from virustotal")
  arg.add_argument("<indicator>", help="enter the hash (md5/sha1/sha256), path to a file, or a url/ip/domain")
  arg.add_argument("-s", "--search", action="store_true", help="retrieve report for hash")
  arg.add_argument("-u", "--scanurl", action="store_true", help="initiate scan of url")
  arg.add_argument("-g", "--urlreport", action="store_true", help="retrieve url scan report")
  arg.add_argument("-r", "--rescan",action="store_true", help="force rescan of hash")
  arg.add_argument("-i", "--ip", action="store_true", help="retreive ip report")
  arg.add_argument("-o", "--domain", action="store_true", help="retrieve domain report")
  arg.add_argument("-d", "--download", action="store_true", help="download file (via intelligence portal")
  arg.add_argument("-f", "--submit", action="store_true", help="submit file to virustotal")
  if len(sys.argv)<=1:
    arg.print_help()
    sys.exit(1)
  args=arg.parse_args()
  vt=virustotalAPI()
  if args.search:
    md5 = sys.argv[2]
    parsemd5(vt.getFileReport(md5), md5)
  if args.rescan:
    md5 = sys.argv[2]
    vt.rescan(md5)
  if args.scanurl:
    vturl = sys.argv[2]
    vt.scanURL(vturl)
  if args.urlreport:
    vturl = sys.argv[2]
    parseurl(vt.getURLReport(vturl), vturl)
  if args.ip:
    vtip = sys.argv[2]
    parseip(vt.getIPReport(vtip), vtip)
  if args.domain:
    vtdomain = sys.argv[2]
    parsedomain(vt.getDomainReport(vtdomain), vtdomain)
  if args.download:
    vtfile = sys.argv[2]
    vt.getIntelFile(vtfile)
  if args.submit:
    vtfile = sys.argv[2]
    vt.submitfile(vtfile)

if __name__ == '__main__':
    main()
