// Copyright (c) 2017-2017 Blockstream
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "clientversion.h"
#include "chainparams.h"
#include "checkqueue.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "validation.h" // For CheckTransaction
#include "policy/policy.h"
#include "script/script.h"
#include "script/script_error.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "util.h"

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>

std::vector<std::vector<unsigned char> > witness_stack = {
    ParseHex("00ca9a3b00000000"),
    ParseHex("58a9a322b0efd74ded229b40ce286cbfeb3d00f4d0c1c0641bfe47410a87a2f1"),
    ParseHex("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"),
    ParseHex("00143cabe97f4de47c7766195e785818f26d2be84bbb"),
    ParseHex("0200000001a37817c0f0f9a23b29171d64683ef39d0bb0bc6500fde2244b2ea3125388a7350000000048473044022065d5853dff557737831adbdf0f889a7c74d2464a4d503f09847ead526bef1df9022051212b7c42941ef6a9cd3ae17743b49a26475a432081a4da408c2d418c3a405501fdffffff0228196bee000000001976a91469535386ce308703c35d14efecbf1a96dc3c54a988ac00ca9a3b0000000017a9146fb8e0e9913e6c9a1c2a357fab9c022bdbb76cb28705000000"),
    ParseHex("0000002004e85645189d0fdae575d9cf4a47eb870086688d1def2cf7458cedda156ffa46d7c625c4efc1bb127114d68e04eab70a8dc0b35f615e54cb6ff0a00d436d389128e1325affff7f200000000002000000028dd04231cf334259c532315cf20ba0a7168374e1d22ccd6f829a22f33a3a07e5ecc881ce9ebbfee16fef2e3b339e225bb4c10e2f3998b1fff21ed8e4fe7a9f660105")
};

std::vector<unsigned char> pegin_transaction = ParseHex("020000000101ecc881ce9ebbfee16fef2e3b339e225bb4c10e2f3998b1fff21ed8e4fe7a9f660100004000ffffffff020158a9a322b0efd74ded229b40ce286cbfeb3d00f4d0c1c0641bfe47410a87a2f101000000003b9ab2f4001976a914e29d3f85dbb0cc6a43ade15baa2402aca0d975b688ac0158a9a322b0efd74ded229b40ce286cbfeb3d00f4d0c1c0641bfe47410a87a2f101000000000000170c0000000000000000024730440220241f8f73c4dbdeb5f1d14af990535edbb4fde7e3dcc3db5a8e6e7c5f9ce224f6022041d3a479f2a6823ae008f3aab572d58a14ea6e2ce5a9fdfa526aa512c189e1060121031809a0e53e782b235f200c2dfd1cc4f7d1f219e7f4f1c973e44869db0115c060060800ca9a3b000000002058a9a322b0efd74ded229b40ce286cbfeb3d00f4d0c1c0641bfe47410a87a2f12006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1600143cabe97f4de47c7766195e785818f26d2be84bbbbd0200000001a37817c0f0f9a23b29171d64683ef39d0bb0bc6500fde2244b2ea3125388a7350000000048473044022065d5853dff557737831adbdf0f889a7c74d2464a4d503f09847ead526bef1df9022051212b7c42941ef6a9cd3ae17743b49a26475a432081a4da408c2d418c3a405501fdffffff0228196bee000000001976a91469535386ce308703c35d14efecbf1a96dc3c54a988ac00ca9a3b0000000017a9146fb8e0e9913e6c9a1c2a357fab9c022bdbb76cb28705000000970000002004e85645189d0fdae575d9cf4a47eb870086688d1def2cf7458cedda156ffa46d7c625c4efc1bb127114d68e04eab70a8dc0b35f615e54cb6ff0a00d436d389128e1325affff7f200000000002000000028dd04231cf334259c532315cf20ba0a7168374e1d22ccd6f829a22f33a3a07e5ecc881ce9ebbfee16fef2e3b339e225bb4c10e2f3998b1fff21ed8e4fe7a9f66010500000000");

COutPoint prevout(uint256S("669f7afee4d81ef2ffb198392f0ec1b45b229e333b2eef6fe1febb9ece81c8ec"), 1);

// Needed for easier parent PoW check, and setting fedpegscript
struct RegtestingSetup : public TestingSetup {
        RegtestingSetup() : TestingSetup(CBaseChainParams::REGTEST, "74528763512103dff4923d778550cc13ce0d887d737553b4b58f4e8e886507fc39f5e447b218645167020001b275522103dff4923d778550cc13ce0d887d737553b4b58f4e8e886507fc39f5e447b218642103dff4923d778550cc13ce0d887d737553b4b58f4e8e886507fc39f5e447b218645268ae") {}
};

BOOST_FIXTURE_TEST_SUITE(pegin_witness_tests, RegtestingSetup)

BOOST_AUTO_TEST_CASE(witness_valid)
{

    CScriptWitness witness;
    witness.stack = witness_stack;

    BOOST_CHECK(IsValidPeginWitness(witness, prevout));

    // Missing byte on each field to make claim ill-formatted
    // This will break deserialization and other data-matching checks
    for (unsigned int i = 0; i < witness.stack.size(); i++) {
        witness.stack[i].pop_back();
        BOOST_CHECK(!IsValidPeginWitness(witness, prevout));
        witness.stack = witness_stack;
        BOOST_CHECK(IsValidPeginWitness(witness, prevout));
    }

    // Test mismatched but valid nOut to proof
    COutPoint fake_prevout = prevout;
    fake_prevout.n = 0;
    BOOST_CHECK(!IsValidPeginWitness(witness, fake_prevout));

    // Test mistmatched but valid txid
    fake_prevout = prevout;
    fake_prevout.hash = uint256S("2f103ee04a5649eecb932b4da4ca9977f53a12bbe04d9d1eb5ccc0f4a06334");
    BOOST_CHECK(!IsValidPeginWitness(witness, fake_prevout));

    // Ensure that all witness stack sizes are handled
    BOOST_CHECK(IsValidPeginWitness(witness, prevout));
    for (unsigned int i = 0; i < witness.stack.size(); i++) {
        witness.stack.pop_back();
        BOOST_CHECK(!IsValidPeginWitness(witness, prevout));
    }
    witness.stack = witness_stack;

    // Extra element causes failure
    witness.stack.push_back(witness.stack.back());
    BOOST_CHECK(!IsValidPeginWitness(witness, prevout));
    witness.stack = witness_stack;

    // Check validation of peg-in transaction's inputs and balance
    CDataStream ssTx(pegin_transaction, SER_NETWORK, PROTOCOL_VERSION);
    CTransactionRef txRef;
    ssTx >> txRef;
    CTransaction tx(*txRef);

    // Only one(valid) input witness should exist, and should match
    BOOST_CHECK(tx.wit.vtxinwit.size() == 1);
    BOOST_CHECK(tx.wit.vtxinwit[0].m_pegin_witness.stack == witness_stack);
    BOOST_CHECK(tx.vin[0].m_is_pegin);
    // Check that serialization doesn't cause issuance to become non-null
    BOOST_CHECK(tx.vin[0].assetIssuance.IsNull());
    BOOST_CHECK(IsValidPeginWitness(tx.wit.vtxinwit[0].m_pegin_witness, prevout));

    std::set<std::pair<uint256, COutPoint> > setPeginsSpent;
    CValidationState state;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    BOOST_CHECK(Consensus::CheckTxInputs(tx, state, coins, 0, setPeginsSpent, nullptr, false));
    BOOST_CHECK(setPeginsSpent.size() == 1);
    setPeginsSpent.clear();

    // Strip pegin_witness
    CMutableTransaction mtxn(tx);
    mtxn.wit.vtxinwit[0].m_pegin_witness.SetNull();
    CTransaction tx2(mtxn);
    BOOST_CHECK(!Consensus::CheckTxInputs(tx2, state, coins, 0, setPeginsSpent, nullptr, false));
    BOOST_CHECK(setPeginsSpent.empty());

    // Invalidate peg-in (and spending) authorization by pegin marker.
    // This only checks for peg-in authorization, with the only input marked
    // as m_is_pegin
    CMutableTransaction mtxn2(tx);
    mtxn2.vin[0].m_is_pegin = false;
    CTransaction tx3(mtxn2);
    BOOST_CHECK(!Consensus::CheckTxInputs(tx3, state, coins, 0, setPeginsSpent, nullptr, false));
    BOOST_CHECK(setPeginsSpent.empty());


    // TODO Test mixed pegin/non-pegin input case
    // TODO Test spending authorization in conjunction with valid witness program in pegin auth

}

BOOST_AUTO_TEST_SUITE_END()
