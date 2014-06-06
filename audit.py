#!/usr/bin/python2.7

from __future__ import print_function
from pydrive.auth import GoogleAuth
from apiclient import errors
from apiclient.discovery import build
import mimetypes
import os
import csv

# A collection of file extensions we did not have mimetypes for
missing = { }

# A list of extensions that will be mapped to 'text/plain'
# Unknown file extensions will be mapped to 'application/octect-stream'
plain_texts = ['.cs', '.m', '.php', '.properties', '.rb', '.yaml', '.yml']

def init_mimetypes():
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
  for ext in plain_texts:
    mimetypes.add_type('text/plain', ext, True)  

# Debugging information post-mortem
def dump_missing_mimetypes():
  for ext in missing:
    print("No mimetype mapped to", ext, "for", missing[ext], file=sys.stderr)

# The GDrive mimetype for a folder
def get_folder_mimetype():
  return 'application/vnd.google-apps.folder'

# Use extensions or guess mimetypes
def get_file_mimetype(file_path):
  base, ext = os.path.splitext(file_path)
  mt = None
  if ext:
      ext = ext.lower()
  try:
      mt = mimetypes.types_map[ext]
  except KeyError as e:
      missing[ext] = file_path
  if mt is None:
      mt, enc = mimetypes.guess_type(file_path, False)
  return mt
  
# Change ':' to '/' in file/folder titles
def map_mac_filename(filename):
  return re.sub(r'\:', "/", filename)

def retrieve_permissions(service, file_id, excluded_domains):
  """Retrieve a list of permissions.

  Args:
    service: Drive API service instance.
    file_id: ID of the file to retrieve permissions for.
  Returns:
    List of permissions.
  """
  shares = [ ]
  try:
    permissions = service.permissions().list(fileId=file_id).execute()
    result = permissions.get('items', [])
    for x in result:
      stype = x['type']
      domain = x.get('domain', None)
      if stype == 'anyone' or domain not in excluded_domains:
        email = x.get('emailAddress', domain)
        shares.append({ 'type': stype, 'id': x['id'], 'role': x['role'], 'domain': domain, 'name': x.get('name', ''), 'email': email })
  except errors.HttpError, error:
    print('An error occurred: %s' % error)
  return shares
  
REPORT_KEYS = [
  'account',
  'fileid',
  'filename',
  'filetype',
  'filemod',
  'sharetype',
  'shareid',
  'sharerole',
  'sharee',
  'shareemail',
  'sharedomain'
]

def report_shared_files(service, user, excluded_domains, csvw):
  """Retrieve a list of File resources.

  Args:
    service: Drive API service instance.
  Returns:
    List of File resources.
  """
  result = []
  page_token = None
  param = {  }
  limit = 20
  if limit >= 0:
    param['maxResults'] = limit
  while True:
    try:
      if page_token:
        param['pageToken'] = page_token
      files = service.files().list(**param).execute()
      for item in files['items']:
        fileid = item['id']
        shares = retrieve_permissions(service, fileid, excluded_domains)
        for s in shares:
          csvw.writerow([ user, item['id'], item['title'], item['mimeType'], item['modifiedDate'],
            s['type'], s['id'], s['role'], s['name'], s['email'], s['domain'] ])
      # result.extend(files['items'][0:1])
      break
      page_token = files.get('nextPageToken')
      if not page_token:
        break
    except errors.HttpError, error:
      print('An error occurred: %s' % error)
      break
  return result

# Find all permissions for all documents for given users
def permission_report(service, user, excluded_domains, fname):
  init_mimetypes()
  with open(fname, 'wb') as csvfile:
    csvw = csv.writer(csvfile)
    csvw.writerow(REPORT_KEYS)
    files = report_shared_files(service, user, excluded_domains, csvw)
  # dump_missing_mimetypes()

def get_userinfo_email(gauth):
  oauth_service = build('oauth2', 'v2', http=gauth.http)
  userinfo = oauth_service.userinfo().get().execute()
  return userinfo.get('email')

EXCLUDED_DOMAINS = [
  'kentfieldschools.org',
  'kentstudents.org'
]

if __name__ == "__main__":
  gauth = GoogleAuth()
  gauth.LocalWebserverAuth()  
  user = get_userinfo_email(gauth)
  permission_report(gauth.service, user, EXCLUDED_DOMAINS, 'audit.csv')

  