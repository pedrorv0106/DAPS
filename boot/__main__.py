print('Starting script')

from time import sleep
from pexpect import pxssh

from config import args, ssh, send, disconnect, config as s
from subprocess import call

from getpass import getpass

def status(servers = s['servers']):
    for server in servers:
        print '\033[94m'+server['name']+'   -   '+server['address']+'\033[0m'
        try:
            connect = ssh(server)
            if connect:
                print '\033[92m'+send(connect, 'uptime')+'\033[0m'
                if (s['main']['name']==server['name']): #status checks for main server
                    res = send(connect, "ps -e|grep mongo")
                    if (len(res)>21):
                        print '\033[92m'+res+'\033[0m'
                    else:
                        print '\033[91m'+res+'\nNo mongo service detected\033[0m'
                    res = send(connect, "ps -e|grep node")
                    if (len(res)>21):
                        print '\033[92m'+res+'\033[0m'
                        server['mongodown']=True
                    else:
                        print '\033[91m'+res+'\nNo node service detected\033[0m'
                        server['nodedown']=True
                    print send(connect, 'dapscoin-cli '+s['serveroption']+'status')
                    disconnect(connect)
                    call('ping -c 1 '+server['address'], shell=True)
                else:
                    print send(connect, 'dapscoin-cli '+s['serveroption']+'status')
                    print send(connect, 'dapscoin-cli '+s['serveroption']+'getbalance')
                    disconnect(connect)
                print("\n\n")
                sleep(2)
            else:
                server['down']=True
        except pxssh.ExceptionPxssh, err:
            print err

def stop():
    for server in s['servers']:
        print 'wip'

def start():
    print 'wip'

def reboot(servers = s['servers']):
    for server in servers:
        try:
            connect = ssh(server)
            if connect:
                print send(connect, 'su reboot')
                send(connect, getpass())
        except pxssh.ExceptionPxssh, err:
            print err
    sleep(60)
    for server in servers:
        try:
            connect = ssh(server)
            if connect:
                print send(connect, 'dapscoind')
        except pxssh.ExceptionPxssh, err:
            print err

def transfer(masternode, worker, amount=s['coinamount'] ):
    connect = ssh(masternode)
    print send(connect, 'dapscoind')#needs to connect
    print send(connect, 'dapscoin-cli '+s['serveroption']+'masternode genkey')
    coinAddress = send(connect,'dapscoin-cli '+s['serveroption']+'getaccountaddress'+s['alias'])#what is alias?
    print coinAddress
    disconnect(connect)
    connect = ssh(worker)
    print send(connect, 'dapscoin-cli '+s['serveroption']+'sendtoaddress '+coinAddress+amount)
    disconnect(connect)
    connect = ssh(masternode)
    print send(connect, 'dapscoin-cli '+s['serveroption']+'getbalance')

def awaitWorkers(workers, amount=s['coinamount']):
    ready = False
    while (not ready):
        ready = True
        for worker in workers:
            connect = ssh(worker)
            balance = send(connect, 'dapscoin-cli getbalance')
            if (balance<amount):
                ready = False
            disconnect(connect)
        sleep(s['checkworkerinterval'])

def autoGCloud(servers=s['servers']):
    for server in servers:
        call('xterm -e gcloud compute --project "'+s['project']+'" ssh --zone "'+s['zone']+'" "'+server['name']+'"', shell=True)


#-------------------------------------------------
def runArgs():
    if (len(args)):
        for arg in args:
            if (arg['k'].find('-stat')!=-1):
                if (len(arg['v'])):
                    status(arg['v'])
                else:
                    status()
            elif (arg['k'].find('auto')!=-1):
                if (len(arg['v'])):
                    autoGCloud(arg['v'])
                else:
                    autoGCloud()

runArgs()