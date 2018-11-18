./dapscoin-cli stop
echo "Wait for 4 seconds"
sleep 4
echo "Now start daemon"
./dapscoind -daemon
echo "Wait for 10 seconds"
sleep 10
echo "Checking block count"
./dapscoin-cli getblockcount
echo "Unlock wallet"
./dapscoin-cli walletpassphrase 1234567890 0
./dapscoin-cli getstakingstatus
echo "Finish restart"