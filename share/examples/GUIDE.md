# Getting Started With Liquid Core

Liquid Core is a Liquid full node with a familiar graphical user interface. It is based on Bitcoin Core’s QT interface, which it extends to support the many features provided by Liquid.

If you have used Bitcoin Core “bitcoin-qt” in the past, you will be familiar with the process of setting up Liquid Core and the interface it provides.

To set up and run Liquid Core on your machine you need to download the Liquid Core binary for your platform.

All binaries variants are available at https://github.com/Blockstream/liquid/releases/tag/liquid.3.14.1.23

#### Windows installation


For windows you can download the installer available [here](https://github.com/Blockstream/liquid/releases/download/liquid.3.14.1.23/liquid-3.14.1.23-win64-setup-unsigned.exe).

If you prefer a 32bit variant or a variant without installer please see [here](https://github.com/Blockstream/liquid/releases/tag/liquid.3.14.1.23).

Note: If you want to use a different data directory, for example an external hard drive, you can follow [this guide](https://bitzuma.com/posts/moving-the-bitcoin-core-data-directory/).

If you want to make changes to your Liquid settings, locate the config file in the default data directory (`%homepath%\AppData\Roaming\Liquid`).

Note that after making the required changes, you will need to restart your Liquid node so that they take effect.


#### MacOs X Installation 



For MacOs X you can download the dmg file available [here](https://github.com/Blockstream/liquid/releases/download/liquid.3.14.1.23/liquid-3.14.1.23-osx-unsigned.dmg)


Note: If you want to use a different data directory, for example an external hard drive, you can follow [this guide](https://bitzuma.com/posts/moving-the-bitcoin-core-data-directory/).

If you want to make changes to your Liquid settings, use Finder to locate the config file by selecting Macintosh HD then `Library/Application Support/Liquid` and opening the configuration file with a text editor.

Note that after making the required changes, you will need to restart your Liquid node so that they take effect.


#### Linux Installation 


Download and untar the Liquid binaries available [here](https://github.com/Blockstream/liquid/releases/download/liquid.3.14.1.23/liquid-3.14.1.23-x86_64-linux-gnu.tar.gz)

Note: If you want to use a different data directory, for example an external hard drive, you can follow [this guide](https://bitzuma.com/posts/moving-the-bitcoin-core-data-directory/).

If you want to make changes to your Liquid settings, locate and edit the config file in `~/.liquid/ `.

Note that after making the required changes, you will need to restart your Liquid node so that they take effect.


## Setting up Configuration Files

By default, Liquid Core requires that you run a Bitcoin node so that Liquid can validate peg-ins (transactions that move bitcoin into the Liquid Network).

This guide assumes you are already running a Bitcoin full node.

To allow Liquid Core to communicate with your Bitcoin node, certain parameters must be included in your Bitcoin configuration file and potentially to the Liquid configuration file.

#### bitcoin.conf


Note: Using a cookie file is now the prefered way of authenticating against bitcoind. Alternatively, you can also use the RPC parameters (‘rpcuser’, ‘rpcport’, and ‘rpcpassword’) as the authentication method.

Include the following parameters in your bitcoin.conf file:

`server=1`

You may also want to include the ‘prune’ parameter in your Bitcoin node settings. Pruned mode reduces disk space requirements but will will not change the initial amount of time required for download and validation of the chain.

#### liquid.conf

If your Bitcoin is installed in the normal default location Liquid should automatically find it.  But if you use a non default datadir for bitcoin you may want to add to your liquid.conf the following parameter to point to the cookie file created by bitcoin (by default in the default datadir):

`mainchainrpccookiefile=<location_of_your_bitcoin_datadir>`

If bitcoind rpc authentication is done through user and password, include the following parameters instead. Notice that these values should be taken from your bitcoin.conf file.

`mainchainrpcuser=<your_bitcoin_rpc_user_here>`


`mainchainrpcpassword=<your_bitcoin_rpc_password_here>`


If you do not wish to validate peg-ins against your Bitcoin node, you can set the validatepegin parameter to a value of zero. This can be done either in the liquid.conf file, or passed in as a command line parameter:

`validatepegin=0`

With this setting, you do not need to run a Bitcoin node and Liquid will not attempt to connect to one on startup. 

**We advise against disabling peg-in validation unless you are aware of the implications**, running in a testing environment, or are not dealing with large amounts of funds.  

The template Liquid configuration file can be used as a reference when configuring your own Liquid node.

