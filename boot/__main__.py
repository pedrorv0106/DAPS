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
                    send(connect, 'dapscoin-cli '+s['serveroption']+' masternode status')
                    send(connect, 'dapscoin-cli '+s['serveroption']+' getbalance')
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

def stopAllWalletDaemons():
    for server in s['servers']:
        stopAWallet(server)

def stopAWallet(server):
    try:
        connect = ssh(server)
        if connect:
            print("Trying to stop daemon:" + server['name'] + "\n")
            send(connect, 'dapscoin-cli '+s['serveroption']+' stop')
            sleep(2)    #wait 2 seconds
        else:
            print("Server" + server['name'] + " is down\n")
    except pxssh.ExceptionPxssh, err:
        print err


def startStakingWallet(server, hard=false):#Main server producing PoW blocks, hard=true meaning to erase block data and restart wallet
    try:
        connect = ssh(server)
        if connect:
            if hard:
                removeBlockchainData(main)
            genStakingNodeConfigFileScript(s['servers'], main)   
            send(connect, 'dapscoind '+s['serveroption']+' -daemon')#Start daemon
            sleep(2)    #wait 2 seconds
            if server == s['main']:#Start generating PoW blocks
                send(connect, 'dapscoin-cli '+s['serveroption']+' setgenerate true 1')
            #if hard:
                #Need to reindex explorer database
        else:
            print("Staking server " + server['name'] + " is down\n")
    except pxssh.ExceptionPxssh, err:
        print err

def removeBlockchainData(server):
    if s['serveroption'] != '-testnet':
        send(connect, 'rm -r ~/.dapscoin/')
    else: 
        send(connect, 'rm -r ~/.dapscoin/testnet4/')


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
    dapsConfData = open('boot/config/dapscoin.conf', 'r').read() + nodes
    connect = ssh(stakingserver)
    send(connect, 'mkdir ~/.dapscoin')
    send(connect, 'touch ~/.dapscoin/dapscoin.conf')
    send(connect, 'echo "'+dapsConfData+'">~/dapscoin/dapscoin.conf')

def restartAllWallets(hard=false):#hard restart = erase data and start blockchain from beginning
    stopAllWalletDaemons();
    if hard:
        for server in s['servers']:
            removeBlockchainData(server)
    startStakingWallet(s['main'])
    print('Wait 10s for a number of PoW blocks generated\n')
    sleep(10)

    #start control wallet that controls the first masternode, this assume the machine running
    #this script is running control wallet
    mn1 = s['masternodes'][0]
    mn1ip = mn1['address']
    if hard:
        #1. Stop control wallet
        p = subprocess.Popen('dapscoin-cli ' + s['serveroption'] + " stop", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            print line,
        sleep(2)
        #2. Start daemon
        subprocess.Popen('dapscoind ' + s['serveroption'] + " -daemon", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sleep(2)

        #3. generate masternodeprivatekey
        p = subprocess.Popen('dapscoin-cli ' + s['serveroption'] + " masternode genkey", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = p.stdout.readlines()
        mnprivateKey = lines[0]
        mnalias = "masternode1"

        #4. generate account
        p = subprocess.Popen('dapscoin-cli ' + s['serveroption'] + " getaccountaddress " + mnalias, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = p.stdout.readlines()
        accountAddress = lines[0]

        #5. send 10 000 daps to accountaddress
        txhash = transferFromMainWallet(accountAddress)
        if txhash:
            #check whether the transaction is confirmed
            confirmed = False
            while !confirmed:
                print('Checking tx masternode send confirmation\n')
                p = subprocess.Popen('dapscoin-cli ' + s['serveroption'] + " masternode outputs", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                lines = p.stdout.readlines()
                if txhash in str(lines):
                    confirmed = True
        else:
            print('cannot send daps to masternode')
            return 0
        
        #6. create masternode.conf file
        mp1port = '53572'
        mnconfPath = '~/.dapscoin/masternode.conf'
        if s['serveroption'] == '-testnet':
            mn1port = '53575'
            mnconfPath = '~/.dapscoin/testnet4/masternode.conf'
        mnconfContent = mnalias + ' ' + mn1ip + ':' + mn1port + ' ' + mnprivateKey + ' ' + txhash + ' 1'
        subprocess.Popen('echo "' + mnconfContent + '" >' + mnconfPath, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        #7. Start masternode daemon
        startStakingWallet(mn1, hard)
        stopAWallet(mn1)
        nodes = ''
        for server in s['servers']:
            nodes += '\naddnode='+server['address']
        dapsConfData = open('boot/config/dapscoin.conf', 'r').read() + nodes 
        dapsConfData = dapsConfData + '\n' + 'masternode=1\n' + 'externalip=' + mn1ip + '\nmasternodeprivkey=' + mnprivateKey
        mn1Connect=ssh(mn1)
        send(mn1Connect, 'echo "'+dapsConfData+'">~/dapscoin/dapscoin.conf')
        send(mn1Connect, 'dapscoind '+s['serveroption']+' -daemon')#Start daemon

        #8. Start masternode from control wallet
        p = subprocess.Popen('dapscoin-cli ' + s['serveroption'] + ' startmasternode alias false ' + mnalias, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = p.stdout.readlines()
        if 'Successfully started 1' in str(lines):
            print('Sucessfully start control wallet masternode\n')
        else:
            print('Failed to start control wallet masternode\n')    
            return 0
        
        #9. Start masternode in VPS
        res = send(mn1Connect, 'dapscoin-cli '+s['serveroption']+' startmasternode local false')#Start daemon
        print(res + '\n')

        #10. Start staking nodes...

def transferFromMainWallet(destination, amount = '10000'):
    main = s['main']
    try:
        connect = ssh(main)
        if connect:
            response = send(connect, 'dapscoin-cli ' + s['serveroption' + ' sendtoaddress ' + destination + ' 10000'])
            if response:
                txhash = response[0]
                return txhash
    except pxssh.ExceptionPxssh, err:
        print err        
        return 0

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