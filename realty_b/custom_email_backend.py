import ssl
import certifi
from django.core.mail.backends.smtp import EmailBackend
from smtplib import SMTP, SMTP_SSL

class CustomEmailBackend(EmailBackend):
    def __init__(self, *args, **kwargs):
        self.debug_level = kwargs.pop('debug_level', 0)  # Set default debug level to 0
        super().__init__(*args, **kwargs)

    def open(self):
        if self.connection:
            return False
        try:
            if self.use_ssl:
                self.connection = SMTP_SSL(
                    self.host, self.port, timeout=self.timeout
                )
            else:
                self.connection = SMTP(
                    self.host, self.port, timeout=self.timeout
                )
                if self.use_tls:
                    context = ssl.create_default_context(cafile=certifi.where())
                    self.connection.starttls(context=context)

            self.connection.set_debuglevel(self.debug_level)

            if self.username and self.password:
                self.connection.login(self.username, self.password)
        except:
            if not self.fail_silently:
                raise
        return True
