DAPScoin Core Daemon Management
=====================================

The initial dapscoin-cli execution assists in quirying the daemons in order to discover current running and a relaunch if required.  When a command executions are successful or not a determination must be made to continue (on success) or recover from an error.

The files of focus at this point are listed below:
 
    * <del>trycatch.sh helper file to mimic a normal try catch block</del> 
    * <del>prooftest.sh is a demonstration and proof</del> 
    * <del>deply.sh is the end target deployment script for daemon excution and manage</del> 


[![Build Status](https://travis-ci.org/DAPScoin-Project/DAPScoin.svg?branch=master)](https://travis-ci.org/DAPScoin-Project/DAPScoin) [![GitHub version](https://badge.fury.io/gh/DAPScoin-Project%2FDAPScoin.svg)](https://badge.fury.io/gh/DAPScoin-Project%2FDAPScoin)

DAPScoin is a cutting edge cryptocurrency, with many features not available in most other cryptocurrencies.
- Anonymized transactions using coin mixing technology, we call it _Obfuscation_.
- Fast transactions featuring guaranteed zero confirmation transactions, we call it _SwiftTX_.
- Decentralized blockchain voting providing for consensus based advancement of the current Masternode
  technology used to secure the network and provide the above features, each Masternode is secured
  with a collateral of 10K DAPS.

More information at [dapscoin.org](http://www.dapscoin.org) Visit our ANN thread at [BitcoinTalk](http://www.bitcointalk.org/index.php?topic=1262920)

### DAPScoint scripts
<table>
<tr><td>name</td><td>descr</td></tr>
<tr><td>trycatch.sh</td><td>Implement a Try Catch helper script</td></tr>
 <tr><td>ddaps.sh</td><td>Main Script to manage worflow</td></tr> 
</table>

### BASH 
   * Bash version: *4.4.20(1)-release*
   
### PID Access
<table>
<tr><td>name</td><td>usage</td><td>returns</td></tr>
 <tr><td>pgrep</td><td>prgrep dapscoind</td><td>PID#</td></tr>
 <tr><td> </td><td> </td><td> </td></tr>
</table>

   
### dapscoin-cli
<table>
<tr><td>name</td><td>usage</td></tr>
<tr><td></td><td>Implement a Try Catch helper script</td></tr>
 <tr><td>ddaps.sh</td><td>Main Script to manage worflow</td></tr> 
</table>
