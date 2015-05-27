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

class Privatizer:

  def __init__(self):
    self.verbose = False
    self.csvr = None
    self.user = None
    self.service = None
    
  # Change ':' to '/' in file/folder titles
  def map_mac_filename(self, filename):
    return re.sub(r'\:', "/", filename)

  def remove_permission(self, file_id, share_id):
    """Remove a file or folder permission.

    Args:
      file_id: ID of the file
      share_id: ID of the permission
    Returns:
      True if succeeded

    """

    success = False
    try:
      result = self.service.permissions().delete(fileId=file_id, permissionId=share_id).execute()
      # Should return an empty result
      success = True
    except errors.HttpError, error:
      # We get a 404 error if the file or permission is gone
      pass
    return success


  # Find all permissions for all documents for given users
  def privatize(self, fname, prefix, suffix):
    gauth = None
    with open(fname) as csvfile:
      self.csvr = csv.DictReader(csvfile)
      for row in self.csvr:
        if self.user is None:
          self.user = row['account']
          sub_user = "%s@%s" % (self.user, MY_DOMAIN)
          print("privatizing files owned by %s" % sub_user)
          try:
            gauth = GoogleAuth()
            gauth.ServiceAccountAuth(sub_user)
            self.service = gauth.service
            if self.service is None:
              raise Exception("No service for %s" % sub_user)
            print("authenticated")
          except:
            print("could not authenticate %s" % sub_user)
            print(traceback.format_exc())
        if self.service is None:
          break
        result = self.remove_permission(row['fileid'], row['shareid'])
        if result:
          print("removed %s permission for %s" % (row['sharetype'], row['filename']))
        else:
          print("could not remove %s permission for %s" % (row['sharetype'], row['filename']))

      self.user = None
      self.service = None
      gauth = None

if __name__ == "__main__":
  fname = sys.argv[1]
  job = Privatizer()
  job.privatize(fname, 'results', datetime.today().strftime('%Y%m%d'))
