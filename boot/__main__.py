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
                    send(connect, 'dapscoin-cli '+s['serveroption']+'status')
                    disconnect(connect)
                    call('ping -c 1 '+server['address'], shell=True)
                else:
                    send(connect, 'dapscoin-cli '+s['serveroption']+'masternode status')
                    send(connect, 'dapscoin-cli '+s['serveroption']+'getbalance')
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

def startStaking(server):
    connect = ssh(server)
    result = send(connect, 'dapscoin-cli '+s['serveroption']+'getstakingstatus')
    print result
    if ((result.find('false')!=-1) or (result.find("couldn't")!=-1)):
        send(connect, 'dapscoind '+s['serveroption']+'stop')
        print "Waiting for 30 seconds..."
        sleep(30)
        send(connect, 'dapscoind '+s['serveroption'])#+  -daemon?
        #unlock wallet

def masternodeScript(masterservers, stakingserver):
    genStakingNodeConfigFileScript(masterservers, stakingserver)
    connect = ssh(stakingserver)
    send(connect, 'dapscoind '+s['serveroption']+'-daemon')
    key = send(connect, 'dapscoin-cli '+s['serveroption']+'masternode genkey')
    if ((key[0].lower().find('not')==-1) and (key[0].lower().find('error')==-1)):
        for server in masterservers:
            genMasternodeConfigFileScript(server, stakingserver, key)
    else:
        print('could not complete process')



def genMasternodeConfigFileScript(masterserver, stakingserver, nodeprivkey):
    dapsConfData = open('boot/config/dapscoin.conf', 'r').read()+'externalip='+masterserver['address']+'\nmasternodeprivkey='+nodeprivkey
    connect = ssh(masterserver)
    send(connect, 'mkdir ~/.dapscoin')
    send(connect, 'touch ~/.dapscoin/dapscoin.conf')
    send(connect, 'echo "'+dapsConfData+'">~/.dapscoin/dapscoin.conf')
    send(connect, 'dapscoin-cli '+s['serveroption']+'-daemon -connect '+ip)
    sleep(5)
    send(connect, 'dapscoin-cli '+s['serveroption']+'masternode genkey')

def genStakingNodeConfigFileScript(masterservers, stakingserver):
    nodes = ''
    for server in masterservers:
        nodes += 'addnode='+server['address']+'\n'
    dapsConfData = open('boot/config/dapscoin.conf', 'r').read()+'addnode='+nodes
    connect = ssh(stakingserver)
    send(connect, 'mkdir ~/.dapscoin')
    send(connect, 'touch ~/.dapscoin/dapscoin.conf')
    send(connect, 'echo "'+dapsConfData+'">~/dapscoin/dapscoin.conf')


def reboot(servers = s['servers']):
    for server in servers:
        try:
            connect = ssh(server)
            if connect:
                send(connect, 'su reboot')
                send(connect, getpass())
        except pxssh.ExceptionPxssh, err:
            print err
    sleep(60)
    for server in servers:
        try:
            connect = ssh(server)
            if connect:
                send(connect, 'dapscoind')
        except pxssh.ExceptionPxssh, err:
            print err

def transfer(masternode, worker, amount=s['coinamount'] ):
    connect = ssh(masternode)
    send(connect, 'dapscoind')#needs to connect
    send(connect, 'dapscoin-cli '+s['serveroption']+'masternode genkey')
    coinAddress = send(connect,'dapscoin-cli '+s['serveroption']+'getaccountaddress'+s['alias'])#what is alias?
    print coinAddress
    disconnect(connect)
    connect = ssh(worker)
    send(connect, 'dapscoin-cli '+s['serveroption']+'sendtoaddress '+coinAddress+amount)
    disconnect(connect)
    connect = ssh(masternode)
    send(connect, 'dapscoin-cli '+s['serveroption']+'getbalance')

def awaitWorkers(workers, amount=s['coinamount']):
    ready = False
    while (not ready):
        ready = True
        for worker in workers:
            connect = ssh(worker)
            balance = send(connect, 'dapscoin-cli '+s['serveroption']+'getbalance')
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
#genConfigFileScript(s['masternodes'][0],'92zcRZrsy2JJjuY9kXGA4n7jSihfjGzrjKwB4s4Mq4UG42NPgBe', '38.29.176.86')
masternodeScript(s['masternodes'],s['stakingnodes'][0])