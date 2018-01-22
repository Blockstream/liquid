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
    ParseHex("e13da48cd2489551ba5c4749f0e87a6566df8c0a71f5cb5865991de1c71c6d68"),
    ParseHex("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"),
    ParseHex("00143fd9e2dd6fddb292c1756ea8a4232bdc4778fdfa"),
    ParseHex("02000000019f15926099f03eb83aa9a7033ead61251134e48ea485952bdd71dc58154223ac0000000049483045022100a082acded3b4b07656b992835cb2914d23a910f8fae4fa6dfdffab72f50627b802202ae910309c257ee64cee2f72677577a6e406a110528c162f929b55dcce9b83e401fdffffff0250196bee0000000017a914032219e59890b855333f795430d6be7c2317f60d8700ca9a3b0000000017a914f0b371c2caad4dc2ab9b9d18cf8dcd5ed6399a8d8765000000"),
    ParseHex("0000002019012458b559e25cb28b4a7a1bbf7ed9f21aa534eaffafb95180b60915e78f297f90e5961b1e31891c20358ba59fa5f3e746cb81dc889a248f4be6fb0741d156623f625affff7f20000000000200000002e9356f452ac067d744d9bebae569c9fcfebd24a87ff391638c82037a244d3fde46d1860f7d3ce3711c69a1ed3a78613321aeaf4e5b3560ab0bbc62edb1f649dd0105")
};

std::vector<unsigned char> pegin_transaction = ParseHex("02000000010146d1860f7d3ce3711c69a1ed3a78613321aeaf4e5b3560ab0bbc62edb1f649dd0100004000ffffffff0201e13da48cd2489551ba5c4749f0e87a6566df8c0a71f5cb5865991de1c71c6d6801000000003b9ab2f4001976a914e960f3b3149abbeed93419a8ad7c61d6dff7ea8188ac01e13da48cd2489551ba5c4749f0e87a6566df8c0a71f5cb5865991de1c71c6d6801000000000000170c00000000000000000247304402206a29b6ce97619a0ff623af2b6e1c598cb17949806288dacbc4353000b80a6a4102203728658c5bf603bf0422e2bda65bd5b0d088d149dd471c33b6442a6314aed2190121031eeece02cd7cf0991767576bccc59fc8c61fd04bd22e6c400f18a4d2b14e4175060800ca9a3b0000000020e13da48cd2489551ba5c4749f0e87a6566df8c0a71f5cb5865991de1c71c6d682006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1600143fd9e2dd6fddb292c1756ea8a4232bdc4778fdfabc02000000019f15926099f03eb83aa9a7033ead61251134e48ea485952bdd71dc58154223ac0000000049483045022100a082acded3b4b07656b992835cb2914d23a910f8fae4fa6dfdffab72f50627b802202ae910309c257ee64cee2f72677577a6e406a110528c162f929b55dcce9b83e401fdffffff0250196bee0000000017a914032219e59890b855333f795430d6be7c2317f60d8700ca9a3b0000000017a914f0b371c2caad4dc2ab9b9d18cf8dcd5ed6399a8d8765000000970000002019012458b559e25cb28b4a7a1bbf7ed9f21aa534eaffafb95180b60915e78f297f90e5961b1e31891c20358ba59fa5f3e746cb81dc889a248f4be6fb0741d156623f625affff7f20000000000200000002e9356f452ac067d744d9bebae569c9fcfebd24a87ff391638c82037a244d3fde46d1860f7d3ce3711c69a1ed3a78613321aeaf4e5b3560ab0bbc62edb1f649dd010500000000");

COutPoint prevout(uint256S("dd49f6b1ed62bc0bab60355b4eafae213361783aeda1691c71e33c7d0f86d146"), 1);

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
