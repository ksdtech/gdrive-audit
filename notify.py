from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from glob import glob
import re
import smtplib

if __name__ == "__main__":
  s = smtplib.SMTP('172.16.121.233', 25)

  subject = 'List of files you own that are publicly shared'
  fromEmail = 'pzingg@kentfieldschools.org'

  for fname in glob('audit-*-2015*.txt'):
      m = re.search('audit-(.+)-2015[\d]+\.txt', fname)
      doc = ''
      with open(fname) as f:
        doc = f.read()

      if m and doc != '':
        user = m.group(1)

        lines = [ 'Dear %s,\n' % user, 
          'Please review the list of files that you should review.',
          'You can also download, print or add the attachment to your Google Drive.',
          'Email me if you have any questions.  Thanks,\n',
          'Peter\n\n' ]

        body = '\n'.join(lines) + doc

        toEmail = user + '@kentfieldschools.org'
        print "mailing to %s" % toEmail

        msg = MIMEMultipart()
        msg['From'] = fromEmail
        msg['To'] = toEmail
        msg['Subject'] = subject

        text = MIMEText(body)
        msg.attach(text)

        attachment = MIMEText(doc)
        attachment.add_header('Content-Disposition', 'attachment', filename=fname)
        msg.attach(attachment)
        try:
          s.sendmail(fromEmail, toEmail, msg.as_string())
        except:
          print(traceback.format_exc())

  s.quit()