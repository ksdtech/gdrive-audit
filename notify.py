from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from glob import glob
import re
import smtplib

if __name__ == "__main__":
  s = smtplib.SMTP('172.16.121.233', 25)

  subject = 'List of files you own that are shared publicly'
  fromEmail = 'pzingg@kentfieldschools.org'

  for fname in glob('audit-*.txt'):
      m = re.search('audit-(.+)-2015[\d]+\.txt', fname)
      doc = ''
      with open(fname) as f:
        doc = f.read()

      if m and doc != '':
        user = m.group(1)

        lines = [ 'Dear %s,\n' % user, 
          'Please review the attached list of files that you have shared publicly.',
          'You can also download, print or add the attachment to your Google Drive.',
          '',
          'And here\'s my cheat sheet with tips and reminders if you need some help:',
          '',
          'Making a Shared Google Drive Folder or Document Private',
          'https://docs.google.com/a/kentfieldschools.org/document/d/1rzgGg1gfydocvX3XCkio2kEeOdgVK9syTB9F2JXK7Ok/edit?usp=sharing',
          '',
          'Email me if you have any questions.  Thanks,',
          '',
          'Peter',
          '',
          '' ]

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