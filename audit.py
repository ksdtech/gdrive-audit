#!/usr/bin/python2.7

from __future__ import print_function
from apiclient import errors
from apiclient.discovery import build
import csv
import mimetypes
import os
import sys

PYDRIVE_FORKED_LOCATION = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'PyDrive')
sys.path.append(PYDRIVE_FORKED_LOCATION)
from pydrive.auth import GoogleAuth

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
      role = x['role']
      stype = x['type']
      domain = x.get('domain', None)
      if stype == 'anyone' or domain not in excluded_domains:
        email = x.get('emailAddress', domain)
        shares.append({ 'type': stype, 'id': x['id'], 'role': role, 'domain': domain, 'name': x.get('name', ''), 'email': email })
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
  
  limit = -1 # for debugging, set this to a positive number
  found = 0
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
      print("%s list %r" % (user, param))
      files = service.files().list(**param).execute()
      found += len(files)
      for item in files['items']:
        fileid = item['id']
        title = item['title']
        shares = retrieve_permissions(service, fileid, excluded_domains)
        for s in shares:
          csvw.writerow([ user, fileid, title, item['mimeType'], item['modifiedDate'],
            s['type'], s['id'], s['role'], s['name'], s['email'], s['domain'] ])
      page_token = files.get('nextPageToken')
      if not page_token or (limit > 0 and found >= limit):
        break
    except errors.HttpError, error:
      print('An error occurred: %s' % error)
      break
  return result


# Find all permissions for all documents for given users
def permission_report(users, excluded_domains, fname):
  init_mimetypes()
  with open(fname, 'wb') as csvfile:
    csvw = csv.writer(csvfile)
    csvw.writerow(REPORT_KEYS)
    gauth = GoogleAuth()
    for sub_user in users:
      try:
        gauth.ServiceAccountAuth(sub_user)
      except:
        print("could not authenticate %s" % sub_user)
        continue
      files = report_shared_files(gauth.service, sub_user, excluded_domains, csvw)

EXCLUDED_DOMAINS = [
  'kentfieldschools.org',
  'kentstudents.org'
]

if __name__ == "__main__":
  users = [ 'sthelen@kentfieldschools.org', 'jeynon@kentfieldschools.org' ]
  permission_report(users, EXCLUDED_DOMAINS, 'audit.csv')

  