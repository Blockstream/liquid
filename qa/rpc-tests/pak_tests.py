#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import copy

def pak_to_option(pak):
    l = list(map(lambda x: "-pak=%s:%s" % (x[0], x[1]), pak))
    return l

# This tests a PAK list transition from the genesis state ('reject') to pak1 to
# 'reject' and finally to pak2. There are 5 nodes each with different
# configurations
# All nodes validate pegouts but the first one
args = [["-acceptnonstdtxn=1"]] + [["-acceptnonstdtxn=0"]]*4
# The node at index 0 doesn't validate pegouts
i_novalidate = 0
# The node at index 1 has no paklist in config
i_undefined = 1
# Paklist 1 in config
i_pak1 = 2
pak1 = [("02fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f", "02a28b3078b6fe9d2b0f098ffb491b8e98a7fe56ebe321ba52f90becdd06507bbf"),
        ("02101bed11081c19b25e02dd618da53af1ba29849bbe4006fb3d6e2d3b0d874405", "02c9cf4bdef23d38e6c9ae73b83001711debea113573cfbe0fb729ff81638549da")]
# Paklist 2 in config
i_pak2 = 3
pak2 = [("03767a74373b7207c5ae1214295197a88ec2abdf92e9e2a29daf024c322fae9fcb", "033e4740d0ba639e28963f3476157b7cf2fb7c6fdf4254f97099cf8670b505ea59"),
        ("02f4a7445f9c48ee8590a930d3fc4f0f5763e3d1d003fdf5fc822e7ba18f380632", "036b3786f029751ada9f02f519a86c7e02fb2963a7013e7e668eb5f7ec069b9e7e")]
# Reject in config
i_reject = 4
args[i_reject] = args[i_reject] + ['-pak=reject']

# Novalidate has pak entry, should not act on it ever
args[i_novalidate] = args[i_novalidate] + pak_to_option(pak1)

class CTTest (BitcoinTestFramework):
    def setup_chain(self):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 5)

    def _setup_network(self, extra_args, split=False):
        self.nodes = start_nodes(5, self.options.tmpdir, extra_args)
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)
        connect_nodes_bi(self.nodes,0,3)
        connect_nodes_bi(self.nodes,1,3)
        connect_nodes_bi(self.nodes,2,3)
        connect_nodes_bi(self.nodes,0,4)
        connect_nodes_bi(self.nodes,1,4)
        connect_nodes_bi(self.nodes,2,4)
        connect_nodes_bi(self.nodes,3,4)
        self.is_network_split=False
        self.sync_all()

    def setup_network(self, split=False):
        extra_args = copy.deepcopy(args)
        extra_args[i_pak1] = extra_args[i_pak1] + pak_to_option(pak1)
        extra_args[i_pak2] = extra_args[i_pak2] + pak_to_option(pak2)
        self._setup_network(extra_args, split)

    # Set up blockchain such that all coins belong to node i_undefined
    def _setup_initial_state(self):
        self.nodes[i_novalidate].generate(101)
        self.sync_all()
        i_novalidate_balance = self.nodes[i_novalidate].getbalance()["bitcoin"]
        self.nodes[i_novalidate].sendtoaddress(self.nodes[i_novalidate].getnewaddress(), i_novalidate_balance, "", "", True)
        self.nodes[i_novalidate].generate(101)
        self.sync_all()
        assert_equal(self.nodes[0].getbalance()["bitcoin"], i_novalidate_balance)
        assert("bitcoin" not in self.nodes[1].getbalance())
        assert("bitcoin" not in self.nodes[2].getbalance())
        assert("bitcoin" not in self.nodes[3].getbalance())
        assert("bitcoin" not in self.nodes[4].getbalance())

    def run_test(self):
        self._setup_initial_state()

        # This function tests the result of the getpakinfo RPC.
        # *_pak is either False (undefined paklist), "reject" or a list of
        # (online, offline) tuples
        def test_pak(node, config_pak, block_pak, validate):
            getpakinfo = node.getpakinfo()
            def compare(actual, expected):
                if expected is False:
                    assert_equal(actual, {})
                elif "reject" in expected:
                    assert_equal(actual['offline'], [])
                    assert_equal(actual['online'], [])
                    assert_equal(actual['reject'], True)
                else:
                    offline = list(map(lambda x: x[0], expected))
                    online = list(map(lambda x: x[1], expected))
                    assert_equal(actual['offline'], offline)
                    assert_equal(actual['online'], online)
                    assert_equal(actual['reject'], False)
            compare(getpakinfo['config_paklist'], config_pak)
            compare(getpakinfo['block_paklist'], block_pak)

        # In the beginning the blockchain paklist is "reject"
        empty_pak = []
        test_pak(self.nodes[i_novalidate], pak1, "reject", False)
        test_pak(self.nodes[i_undefined], False, "reject", True)
        test_pak(self.nodes[i_pak1], pak1, "reject", True)
        test_pak(self.nodes[i_pak2], pak2, "reject", True)
        test_pak(self.nodes[i_reject], "reject", "reject", True)

        # i_novalidate creates block without a commitment
        block_proposal = self.nodes[i_novalidate].getnewblockhex()
        assert_equal(self.nodes[i_novalidate].testproposedblock(block_proposal), None)
        assert_equal(self.nodes[i_undefined].testproposedblock(block_proposal), None)
        errorString = ""
        try:
            assert_equal(self.nodes[i_pak1].testproposedblock(block_proposal), None)
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("Proposal does not have required PAK commitment." in errorString, True)
        errorString = ""

        # i_undefined creates a block without a commitment
        block_proposal = self.nodes[i_undefined].getnewblockhex()
        assert_equal(self.nodes[i_novalidate].testproposedblock(block_proposal), None)
        assert_equal(self.nodes[i_undefined].testproposedblock(block_proposal), None)
        try:
            assert_equal(self.nodes[i_pak1].testproposedblock(block_proposal), None)
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("Proposal does not have required PAK commitment." in errorString, True)
        errorString = ""

        # PAK transition: reject -> pak1
        # Create a new block with node i_pak1. Because it contains a commitment
        # to pak1 it should be rejected by i_pak2 and i_reject.
        block_proposal = self.nodes[i_pak1].getnewblockhex()
        assert_equal(self.nodes[i_novalidate].testproposedblock(block_proposal), None)
        assert_equal(self.nodes[i_undefined].testproposedblock(block_proposal), None)
        assert_equal(self.nodes[i_pak1].testproposedblock(block_proposal), None)
        try:
            assert_equal(self.nodes[i_pak2].testproposedblock(block_proposal), None)
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("Proposal PAK commitment and config PAK do not match" in errorString, True)
        errorString = ""
        try:
            assert_equal(self.nodes[i_reject].testproposedblock(block_proposal), None)
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("Proposal PAK commitment and config PAK do not match." in errorString, True)
        errorString = ""
        # Submit block with commitment to pak1 and check each node's state.
        self.nodes[i_undefined].submitblock(block_proposal)
        self.sync_all()
        test_pak(self.nodes[i_novalidate], pak1, pak1, False)
        test_pak(self.nodes[i_undefined], False, pak1, True)
        test_pak(self.nodes[i_pak1], pak1, pak1, True)
        test_pak(self.nodes[i_pak2], pak2, pak1, True)
        test_pak(self.nodes[i_reject], "reject", pak1, True)
        # Check that another block by i_pak1 (without a commitment) is valid to
        # i_pak1 but invalid to i_pak2 and i_reject
        block_proposal = self.nodes[i_undefined].getnewblockhex()
        assert_equal(self.nodes[i_novalidate].testproposedblock(block_proposal), None)
        assert_equal(self.nodes[i_undefined].testproposedblock(block_proposal), None)
        assert_equal(self.nodes[i_pak1].testproposedblock(block_proposal), None)
        try:
            assert_equal(self.nodes[i_pak2].testproposedblock(block_proposal), None)
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("Proposal does not have required PAK commitment." in errorString, True)
        errorString = ""
        try:
            assert_equal(self.nodes[i_reject].testproposedblock(block_proposal), None)
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("Proposal does not have required PAK commitment." in errorString, True)
        errorString = ""


        # PAK transition: pak1 -> reject
        # Create a new block with i_reject which should have a "reject" commitment
        # and check that it's correctly rejected or accepted.
        block_proposal = self.nodes[i_reject].getnewblockhex()
        assert_equal(self.nodes[i_novalidate].testproposedblock(block_proposal), None)
        assert_equal(self.nodes[i_undefined].testproposedblock(block_proposal), None)
        try:
            assert_equal(self.nodes[i_pak1].testproposedblock(block_proposal), None)
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("Proposal PAK commitment and config PAK do not match." in errorString, True)
        errorString = ""
        assert_equal(self.nodes[i_reject].testproposedblock(block_proposal), None)
        # Submit "reject" block and check state.
        self.nodes[i_undefined].submitblock(block_proposal)
        self.sync_all()
        test_pak(self.nodes[i_novalidate], pak1, "reject", False)
        test_pak(self.nodes[i_undefined], False, "reject", True)
        test_pak(self.nodes[i_pak1], pak1, "reject", True)
        test_pak(self.nodes[i_pak2], pak2, "reject", True)
        test_pak(self.nodes[i_reject], "reject", "reject", True)
        # Check that another block by i_reject (without a commitment) is valid to i_reject.
        block_proposal = self.nodes[i_reject].getnewblockhex()
        assert_equal(self.nodes[i_reject].testproposedblock(block_proposal), None)
        # Check that i_undefined can't peg-out because of the pegout freeze.
        try:
            self.nodes[i_undefined].sendtomainchain(1)
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("Pegout freeze is under effect" in errorString, True)
        errorString = ""

        # PAK transition: reject -> pak2
        # Restart nodes while putting pak2 in i_pak1's config instead of pak1.
        stop_nodes(self.nodes)
        extra_args = copy.deepcopy(args)
        extra_args[i_pak1] = extra_args[i_pak1] + pak_to_option(pak2)
        extra_args[i_pak2] = extra_args[i_pak2] + pak_to_option(pak2)
        # Also test novalidate behaves correctly when set to reject after removing
        # the two pak entries
        extra_args[i_novalidate] = extra_args[i_novalidate][:-2] + ['-pak=reject']
        self._setup_network(extra_args, False)
        # Check current state of i_pak1
        test_pak(self.nodes[i_pak1], pak2, "reject", True)
        # Create a new block with i_pak1 which should have a commitment to pak2
        # and check that it's correctly rejected or accepted.
        block_proposal = self.nodes[i_pak1].getnewblockhex()
        assert_equal(self.nodes[i_novalidate].testproposedblock(block_proposal), None)
        assert_equal(self.nodes[i_undefined].testproposedblock(block_proposal), None)
        assert_equal(self.nodes[i_pak1].testproposedblock(block_proposal), None)
        assert_equal(self.nodes[i_pak2].testproposedblock(block_proposal), None)
        try:
            assert_equal(self.nodes[i_reject].testproposedblock(block_proposal), None)
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("Proposal PAK commitment and config PAK do not match." in errorString, True)
        errorString = ""
        # Submit block with commitment to pak2 and check state.
        self.nodes[i_pak1].submitblock(block_proposal)
        self.sync_all()
        test_pak(self.nodes[i_novalidate], "reject", pak2, False)
        test_pak(self.nodes[i_undefined], False, pak2, True)
        test_pak(self.nodes[i_pak1], pak2, pak2, True)
        test_pak(self.nodes[i_pak2], pak2, pak2, True)
        test_pak(self.nodes[i_reject], "reject", pak2, True)

        # Reset PAK conf arguments to start to test mempool acceptance and wallet

        # We will re-use the same xpub, but each wallet will create its own online pak
        # so the lists will be incompatible, even if all else was synced
        xpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"
        init_results = []
        info_results = []
        for i in range(5):
            init_results += [ self.nodes[i].initpegoutwallet(xpub) ]
            info_results += [ self.nodes[i].getpakinfo() ]
            assert_equal(init_results[i]["address_lookahead"], info_results[i]["address_lookahead"])
            assert_equal(init_results[i]["liquid_pak"], info_results[i]["liquid_pak"])
            assert_equal(init_results[i]["liquid_pak_address"], info_results[i]["liquid_pak_address"])
            assert_equal(info_results[i]["bitcoin_xpub"], xpub)
            assert_equal(info_results[i]["derivation_path"], "/0/0")

        # Use custom derivation counter values, check if stored correctly,
        # address lookahead looks correct and that new liquid_pak was chosen
        try:
            assert_equal(self.nodes[i_novalidate].initpegoutwallet(xpub, -1), False)
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("bip32_counter must be between 0 and 1,000,000,000, inclusive." in errorString, True)
        errorString = ""
        try:
            assert_equal(self.nodes[i_novalidate].initpegoutwallet(xpub, 1000000001), False)
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("bip32_counter must be between 0 and 1,000,000,000, inclusive." in errorString, True)
        errorString = ""
 
        new_init = self.nodes[i_novalidate].initpegoutwallet(xpub, 2)
        assert_equal(self.nodes[i_novalidate].getpakinfo()["derivation_path"], "/0/2")
        assert_equal(new_init["address_lookahead"][0], init_results[i_novalidate]["address_lookahead"][2])
        assert(new_init["liquid_pak"] != init_results[i_novalidate]["liquid_pak"])

        # Load additional pak entry for each, restart (reject node disallows pak list in conf)
        # By adding different pak entries, all nodes that validate the list should conflict
        stop_nodes(self.nodes)
        extra_args = copy.deepcopy(args)
        extra_args[i_novalidate] = extra_args[i_novalidate]+["-"+init_results[i_novalidate]["pakentry"]]
        extra_args[i_pak1] = extra_args[i_pak1]+["-"+init_results[i_pak1]["pakentry"]]
        extra_args[i_pak2] = extra_args[i_pak2]+["-"+init_results[i_pak2]["pakentry"]]
        self._setup_network(extra_args, False)

        # Check PAK settings persistance in wallet across restart
        restarted_info = self.nodes[i_novalidate].getpakinfo()
        assert_equal(restarted_info["bitcoin_xpub"], xpub)
        assert_equal(restarted_info["liquid_pak"], new_init["liquid_pak"])
        assert_equal(restarted_info["derivation_path"], "/0/2")

        # Have nodes send pegouts, check it fails to enter mempool of other nodes with incompatible
        # PAK settings
        self.nodes[i_novalidate].sendmany("", {self.nodes[i_undefined].getnewaddress():10, self.nodes[i_pak1].getnewaddress():10, self.nodes[i_pak2].getnewaddress():10, self.nodes[i_reject].getnewaddress():10})
        self.nodes[i_novalidate].generate(1)
        self.sync_all()

        # Attempt to send peg-out, without the proper liquid_pak being set
        # This node is non-validating, so it does not load a config_paklist, and cannot make
        # block commitments.
        try:
            self.nodes[i_novalidate].sendtomainchain(1)
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("Given online key is not in Pegout Authorization Key List" in errorString, True)
        errorString = ""

        # Ensure counter is untouched
        assert_equal(self.nodes[i_novalidate].getpakinfo()["derivation_path"], "/0/2")

        # pak1 generates a block, creating block commitment
        self.nodes[i_pak1].generate(1)
        self.sync_all()

        # pak1 will now create a pegout.
        pak1_pegout_txid = self.nodes[i_pak1].sendtomainchain(1)["txid"]
        assert_equal(self.nodes[i_pak1].getpakinfo()["derivation_path"], "/0/1")
        time.sleep(4)
        assert_equal(pak1_pegout_txid in self.nodes[i_novalidate].getrawmempool(), True)
        assert_equal(pak1_pegout_txid in self.nodes[i_undefined].getrawmempool(), True)
        assert_equal(pak1_pegout_txid in self.nodes[i_pak2].getrawmempool(), False)
        assert_equal(pak1_pegout_txid in self.nodes[i_reject].getrawmempool(), False)

        # pak_reject will make a block commitment, causing all validating nodes to dump
        # the peg transaction
        self.nodes[i_reject].generate(1)
        sync_blocks(self.nodes)

        assert_equal(pak1_pegout_txid in self.nodes[i_novalidate].getrawmempool(), True)
        assert_equal(pak1_pegout_txid in self.nodes[i_undefined].getrawmempool(), False)
        assert_equal(pak1_pegout_txid in self.nodes[i_pak2].getrawmempool(), False)
        assert_equal(pak1_pegout_txid in self.nodes[i_reject].getrawmempool(), False)

        # Fail to peg-out too-small value
        try:
            self.nodes[i_novalidate].sendtomainchain(Decimal('0.0009'))
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("Invalid amount for send, must send more than 1 millibit" in errorString, True)
        errorString = ""

        # Use wrong network's extended pubkey
        mainnetxpub = "xpub6AATBi58516uxLogbuaG3jkom7x1qyDoZzMN2AePBuQnMFKUV9xC2BW9vXsFJ9rELsvbeGQcFWhtbyM4qDeijM22u3AaSiSYEvuMZkJqtLn"
        try:
            assert_equal(self.nodes[i_novalidate].initpegoutwallet(mainnetxpub), False)
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("bitcoin_xpub is invalid for this network" in errorString, True)
        errorString = ""

        # TODO add manual peg-out checks

if __name__ == '__main__':
    CTTest ().main ()
