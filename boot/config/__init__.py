import json
import sys
from pexpect import pxssh

with open('./boot/config/config.json') as json_data:
    config = json.load(json_data)

def assignUser(server):
    if (not 'username' in server):
        server['username']=config['username']
    if (not 'password' in server):
        server['password']=config['password']
    if ( ('publickeyfile' in config) and (len(config['publickeyfile'])) and (not 'publickeyfile' in server) ):
        server['publickeyfile']=config['publickeyfile']
    if (not 'port' in server):
        server['port']=None

def parseArgs(args=sys.argv):
    del args[0]
    parsed = []
    while (len(args)):
        if (args[0].find('-')==0):
            parsed.append( {'k':args[0].lower(),'v':[]} )
        else:
            servs=[]
            match=False
            for server in config['servers']:
                if (args[0]==server['name'] or args[0]==server['address']):
                    match=[server]
                else:
                    if (server['name'].find(args[0])!=-1):
                        servs.append(server)
            if (match):
                parsed[len(parsed)-1]['v']+=match
            else:
                parsed[len(parsed)-1]['v']+=servs
        del args[0]
    return parsed

assignUser(config['main'])

for node in config['masternodes']:
    assignUser(node)

for node in config['stakingnodes']:
    assignUser(node)

config['servers']=[config['main']]+config['masternodes']+config['stakingnodes']
args = parseArgs()
if (not 'serveroption' in config):
    config['serveroption']=""
else:
    config['serveroption']=' '+config['serveroption']+' '

def ssh(server):
    print '\033[0;36;48m  Connecting to '+server['name']+'...\033[0m'
    connect = pxssh.pxssh()
    try:
        if ('publickeyfile' in server):
            connectionString = server['username']+'@'+server['address']
            connect.login (connectionString, None, port=server['port'], ssh_key=server['publickeyfile'])
        else:
            connect.login (server['address'], server['username'], server['password'], port=server['port'])
        return connect
    except pxssh.ExceptionPxssh, err:
        print err
        return 0

def disconnect(connect):
    print '\033[0;36;48m   Disconnecting... \033[0m'
    connect.logout()

def send(sshConnect, command):
    try:
        sshConnect.sendline(command)
        sshConnect.prompt()    
        print sshConnect.before
        response = sshConnect.before.replace('\r','')
        response = response.split('\n')  
        del response[0]
        return response  
    except pxssh.ExceptionPxssh, err:
        print err
        return 0
