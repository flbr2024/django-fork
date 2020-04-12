import os
import signal
import subprocess

from django.db.backends.base.client import BaseDatabaseClient


class DatabaseClient(BaseDatabaseClient):
    executable_name = 'psql'

    def runshell(self, executable_name=None):
        if executable_name is not None:
            self.executable_name = executable_name

        args = [self.executable_name]

        conn_params = self.connection.get_connection_params()
        host = conn_params.get('host', '')
        port = conn_params.get('port', '')
        dbname = conn_params.get('database', '')
        user = conn_params.get('user', '')
        passwd = conn_params.get('password', '')
        sslmode = conn_params.get('sslmode', '')
        sslrootcert = conn_params.get('sslrootcert', '')
        sslcert = conn_params.get('sslcert', '')
        sslkey = conn_params.get('sslkey', '')

        if user:
            args += ['-U', user]
        if host:
            args += ['-h', host]
        if port:
            args += ['-p', str(port)]
        args += [dbname]

        sigint_handler = signal.getsignal(signal.SIGINT)
        subprocess_env = os.environ.copy()
        if passwd:
            subprocess_env['PGPASSWORD'] = str(passwd)
        if sslmode:
            subprocess_env['PGSSLMODE'] = str(sslmode)
        if sslrootcert:
            subprocess_env['PGSSLROOTCERT'] = str(sslrootcert)
        if sslcert:
            subprocess_env['PGSSLCERT'] = str(sslcert)
        if sslkey:
            subprocess_env['PGSSLKEY'] = str(sslkey)
        try:
            # Allow SIGINT to pass to psql to abort queries.
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            subprocess.run(args, check=True, env=subprocess_env)
        finally:
            # Restore the original SIGINT handler.
            signal.signal(signal.SIGINT, sigint_handler)
