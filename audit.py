#!/usr/bin/python2.7

from __future__ import print_function
from apiclient import errors
from apiclient.discovery import build
import csv
from datetime import datetime
import mimetypes
import os
import sys
import traceback

PYDRIVE_FORKED_LOCATION = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'PyDrive')
sys.path.append(PYDRIVE_FORKED_LOCATION)
from pydrive.auth import GoogleAuth

MY_DOMAIN = 'kentfieldschools.org'

class SharingReport:

  def __init__(self, excluded_domains):
    self.service = None
    self.user = None
    self.verbose = False
    self.excluded_domains = excluded_domains
    # A collection of file extensions we did not have mimetypes for
    self.missing = { }
    # A list of extensions that will be mapped to 'text/plain'
    # Unknown file extensions will be mapped to 'application/octect-stream'
    self.plain_texts = ['.cs', '.m', '.php', '.properties', '.rb', '.yaml', '.yml']
    self.report_keys = [
      'account',
      'fileid',
      'filename',
      'filetype',
      'filemod',
      'shareid',
      'sharetype',
      'withlink',
      'sharerole',
      'sharee',
      'shareemail',
      'sharedomain'
    ]
    self.share_types_skipped = { }
    self.init_mimetypes()

  def init_mimetypes(self):
    mimetypes.add_type('application/gzip', '.gz', True)
    mimetypes.add_type('application/vnd.apple.pages', '.pages', True)  
    mimetypes.add_type('application/vnd.apple.keynote', '.key', True)  
    mimetypes.add_type('application/vnd.apple.numbers', '.numbers', True) 
    mimetypes.add_type('application/clarisworks', '.cwk', True)
    mimetypes.add_type('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', '.xlsx', True)
    mimetypes.add_type('application/vnd.openxmlformats-officedocument.spreadsheetml.template', '.xltx', True)
    mimetypes.add_type('application/vnd.openxmlformats-officedocument.presentationml.template', '.potx', True)
    mimetypes.add_type('application/vnd.openxmlformats-officedocument.presentationml.slideshow', '.ppsx', True)
    mimetypes.add_type('application/vnd.openxmlformats-officedocument.presentationml.presentation', '.pptx', True)
    mimetypes.add_type('application/vnd.openxmlformats-officedocument.presentationml.slide', '.sldx', True)
    mimetypes.add_type('application/vnd.openxmlformats-officedocument.wordprocessingml.document', '.docx', True)
    mimetypes.add_type('application/vnd.openxmlformats-officedocument.wordprocessingml.template', '.dotx', True)
    mimetypes.add_type('application/vnd.ms-excel.addin.macroEnabled.12', '.xlam', True)
    mimetypes.add_type('application/vnd.ms-excel.sheet.binary.macroEnabled.12', '.xlsb', True)
    mimetypes.add_type('text/x-markdown', '.md', True)  
    for ext in self.plain_texts:
      mimetypes.add_type('text/plain', ext, True)  

  # Debugging information post-mortem
  def dump_missing_mimetypes(self):
    for ext in self.missing:
      print("No mimetype mapped to", ext, "for", self.missing[ext], file=sys.stderr)

  # The GDrive mimetype for a folder
  def get_folder_mimetype(self):
    return 'application/vnd.google-apps.folder'

  # Use extensions or guess mimetypes
  def get_file_mimetype(self, file_path):
    base, ext = os.path.splitext(file_path)
    mt = None
    if ext:
        ext = ext.lower()
    try:
        mt = mimetypes.types_map[ext]
    except KeyError as e:
        self.missing[ext] = file_path
    if mt is None:
        mt, enc = mimetypes.guess_type(file_path, False)
    return mt
    
  # Change ':' to '/' in file/folder titles
  def map_mac_filename(self, filename):
    return re.sub(r'\:', "/", filename)

  def retrieve_permissions(self, file_id, title, share_types):
    """Retrieve a list of permissions.

    Args:
      file_id: ID of the file to retrieve permissions for.
    Returns:
      List of permissions.

    Notes.  Each permission returned by the API has these elements. * entries are in 
      Drive API v2, not in DocsList.
      [kind]         = drive#permission
      [type]         = user | group | domain | anyone
      [role]         = owner | reader | writer
     *[additionalRoles] = list of extra roles, right now only commenter
     *[withLink]     = true if link is required
      [id]           = sharee's id or 'anyoneWithLink'
      [emailAddress] = sharee's email address if type is user
      [domain]       = domain to share with if type is domain, or domain of email address

    """
    shares = [ ]
    try:
      permissions = self.service.permissions().list(fileId=file_id).execute()
      result = permissions.get('items', [])
      i = 1
      for x in result:
        id = x['id']
        type_ = x['type']
        if type_ in share_types:
          role = x['role']
          domain = x.get('domain', None)
          email = x.get('emailAddress', None)
          name = x.get('name', None)
          with_link = x.get('withLink', False)
          if self.verbose:
            if i == 1:
              print("title %s - file_id %s" % (title, file_id))
            print(" [%02d] id %s role %s type %s link %s email %s domain %s" % (i, id, role, type_, with_link, email, domain))
          shares.append({ 'type': type_, 'link': with_link, 'id': id, 'role': role, 'domain': domain, 'name': name, 'email': email })
          i += 1
        else:
          self.share_types_skipped[type_] = 1
    except errors.HttpError, error:
      print('An error occurred: %s' % error)
    return shares

  def report_shared_files_for_user(self, user, share_types):
    """Retrieve a list of File resources.

    Args:
      service: Drive API service instance.
    Returns:
      List of File resources.
    """
    
    limit = -1 # for debugging, set this to a positive number
    found = 0
    j = 0
    result = [ ]
    page_token = None
    while True:
      try:
        # NOTE: 'me' in owners doesn't work
        # Nor does using the 'About' resource (always returns same permissionId)
        query = "'%s' in owners and trashed = false" % user
        param = { 'q': query }
        if limit > 0:
          param['maxResults'] = limit
        if page_token:
          param['pageToken'] = page_token
        # print("%s list %r" % (user, param))
        files = self.service.files().list(**param).execute()
        found += len(files)
        for item in files['items']:
          j += 1
          if not self.verbose and (j % 100) == 0:
            print("%d..." % j)
          fileid = item['id']
          title = item['title'].encode('ascii', 'replace')
          mimeType = item['mimeType']
          modDate = item['modifiedDate']
          shares = self.retrieve_permissions(fileid, title, share_types)
          if len(shares):
            result.append({ 'fileid': fileid, 'title': title, 
              'mimeType': mimeType, 'modDate': modDate, 'shares': shares })
        page_token = files.get('nextPageToken')
        if not page_token or (limit > 0 and found >= limit):
          break
      except errors.HttpError, error:
        print('An error occurred: %s' % error)
        break
    return result

  # Find all permissions for all documents for given users
  def audit_reports(self, users, share_types, prefix, suffix):
    for user in users:
      files = [ ]
      sub_user = "%s@%s" % (user, MY_DOMAIN)
      print("auditing files owned by %s" % sub_user)
      try:
        gauth = GoogleAuth()
        gauth.ServiceAccountAuth(sub_user)
        self.service = gauth.service
        if self.service is None:
          raise Exception("No service for %s" % sub_user)
        print("authenticated")
        files = self.report_shared_files_for_user(sub_user, share_types)
      except:
        print("could not authenticate %s" % sub_user)
        print(traceback.format_exc())
      if len(files):
        csvfname = "%s-%s-%s.csv" % (prefix, user, suffix)
        with open(csvfname, 'wb') as csvfile:
          csvw = csv.writer(csvfile)
          csvw.writerow(self.report_keys)
          for item in files:
            for s in item['shares']:
              csvw.writerow([ user, item['fileid'], item['title'], item['mimeType'], item['modDate'],
                s['id'], s['type'], s['link'], s['role'], s['name'], s['email'], s['domain'] ])

        txtfname = "%s-%s-%s.txt" % (prefix, user, suffix)
        with open(txtfname, 'w') as txtfile:
          txtfile.write("Dear %s,\n\n" % user)
          txtfile.write("Here are a list of folders and documents shared to the domain or to anyone.\n")
          txtfile.write("First go through the folders and verify that you want students to have access.\n")
          txtfile.write("Then do the same for the documents.\n\nFolders\n-------\n")
          folders = [item for item in files if item['mimeType'] == 'application/vnd.google-apps.folder']
          for item in folders:
            txtfile.write("%s\n" % item['title'])
            for s in item['shares']:
              share = 'anyone'
              if s['type'] == 'domain':
                share = 'anyone in the domain'
              if s['link']:
                share += ' with the link'
              role = 'can view'
              if s['role'] == 'writer':
                role = 'can edit'
              txtfile.write("  - %s %s\n" % (share, role))
          txtfile.write("\nDocuments\n---------\n")
          docs = [item for item in files if item['mimeType'] != 'application/vnd.google-apps.folder']
          for item in docs:
            txtfile.write("%s\n" % item['title'])
            for s in item['shares']:
              share = 'anyone'
              if s['type'] == 'domain':
                share = 'anyone in the domain'
              if s['link']:
                share += ' with the link'
              role = 'can view'
              if s['role'] == 'writer':
                role = 'can edit'
              txtfile.write("  - %s %s\n" % (share, role))
      self.service = None
      gauth = None
    print("sharing types not reported: ", ", ".join(self.share_types_skipped.keys()))

if __name__ == "__main__":
  with open('./example.txt') as f:
    users = [line.rstrip('\n') for line in f]
  # print(users)
  share_types = [ 'domain', 'anyone' ]
  excluded_domains = [ 'kentstudents.org' ]
  report = SharingReport(excluded_domains)
  report.audit_reports(users, share_types, 'audit', datetime.today().strftime('%Y%m%d'))
