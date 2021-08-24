
import subprocess
import time
import os


class FreeBSDJail(object):
    def __init__(self, name):
        self.name = name

    def start(self):
        self.process = subprocess.Popen(['jail', '-i', '-c', 'path=/', 'host.hostname=%s' % self.name, 'vnet=new', 'command=/bin/sh', '-c', 'echo IGN; read IGN || true'],
                stdin = subprocess.PIPE, stdout = subprocess.PIPE, shell = False)
        self.jid = int(self.process.stdout.readline())
        self.process.stdout.readline()

    def end(self):
        subprocess.check_call(['jail', '-r', '%d' % self.jid])

        self.process.stdin.close()
        self.process.wait()
        del self.process

    def prefix(self):
        return ['jexec', str(self.jid)]

    def popen(self, cmdline, *args, **kwargs):
        return subprocess.Popen(self.prefix() + cmdline, *args, **kwargs)
    def check_call(self, cmdline, *args, **kwargs):
        return subprocess.check_call(self.prefix() + cmdline, *args, **kwargs)
    def check_output(self, cmdline, *args, **kwargs):
        return subprocess.check_output(self.prefix() + cmdline, *args, **kwargs)

if __name__ == '__main__':
    ns = FreeBSDJail('test')
    ns.start()
    ns.check_call(['ifconfig', '-a'])
    ns.check_call(['/bin/sh', '-c', 'sleep 3'])
    time.sleep(3)
    ns.end()
    print('ended')
    time.sleep(3)
