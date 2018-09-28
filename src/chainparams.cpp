// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "issuance.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "crypto/sha256.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

// Safer for users if they load incorrect parameters via arguments.
static std::vector<unsigned char> CommitToArguments(const Consensus::Params& params, const std::string& networkID, const CScript& signblockscript)
{
    CSHA256 sha2;
    unsigned char commitment[32];
    sha2.Write((const unsigned char*)networkID.c_str(), networkID.length());
    sha2.Write((const unsigned char*)HexStr(params.fedpegScript).c_str(), HexStr(params.fedpegScript).length());
    sha2.Write((const unsigned char*)HexStr(signblockscript).c_str(), HexStr(signblockscript).length());
    sha2.Finalize(commitment);
    return std::vector<unsigned char>(commitment, commitment + 32);
}

static CScript StrHexToScriptWithDefault(std::string strScript, const CScript defaultScript)
{
    CScript returnScript;
    if (!strScript.empty()) {
        std::vector<unsigned char> scriptData = ParseHex(strScript);
        returnScript = CScript(scriptData.begin(), scriptData.end());
    } else {
        returnScript = defaultScript;
    }
    return returnScript;
}

static CBlock CreateGenesisBlock(const Consensus::Params& params, const std::string& networkID, uint32_t nTime, const CScript& scriptChallenge, int32_t nVersion)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    // Any consensus-related values that are command-line set can be added here for anti-footgun
    txNew.vin[0].scriptSig = CScript(CommitToArguments(params, networkID, scriptChallenge));
    txNew.vout.clear();
    txNew.vout.push_back(CTxOut(CAsset(), 0, CScript() << OP_RETURN));

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.proof = CProof(scriptChallenge, CScript());
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/** Add an issuance transaction to the genesis block. Typically used to pre-issue
 * the policyAsset of a blockchain. The genesis block is not actually validated,
 * so this transaction simply has to match issuance structure. */
static void AppendInitialIssuance(CBlock& genesis_block, const COutPoint& prevout, const uint256& contract, const int64_t asset_outputs, const int64_t asset_values, const int64_t reissuance_outputs, const int64_t reissuance_values, const CScript& issuance_destination) {

    uint256 entropy;
    GenerateAssetEntropy(entropy, prevout, contract);

    CAsset asset;
    CalculateAsset(asset, entropy);

    // Re-issuance of policyAsset is always unblinded
    CAsset reissuance;
    CalculateReissuanceToken(reissuance, entropy, false);

    // Note: Genesis block isn't actually validated, outputs are entered into utxo db only
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vin[0].prevout = prevout;
    txNew.vin[0].assetIssuance.assetEntropy = contract;
    txNew.vin[0].assetIssuance.nAmount = asset_values*asset_outputs;
    txNew.vin[0].assetIssuance.nInflationKeys = reissuance_values*reissuance_outputs;

    for (unsigned int i = 0; i < asset_outputs; i++) {
        txNew.vout.push_back(CTxOut(asset, asset_values, issuance_destination));
    }
    for (unsigned int i = 0; i < reissuance_outputs; i++) {
        txNew.vout.push_back(CTxOut(reissuance, reissuance_values, issuance_destination));
    }

    genesis_block.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis_block.hashMerkleRoot = BlockMerkleRoot(genesis_block);
}

void CChainParams::UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Custom chain params
 */
class CCustomParams : public CChainParams {

protected:
    void UpdateFromArgs()
    {
        consensus.nSubsidyHalvingInterval = GetArg("-con_nsubsidyhalvinginterval", 150);
        // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Height = GetArg("-con_bip34height", 100000000);
        consensus.BIP34Hash = uint256S(GetArg("-con_bip34hash", "0x00"));
        consensus.BIP65Height = GetArg("-con_bip65height", 1351);
        consensus.BIP66Height = GetArg("-con_bip66height", 1251);
        consensus.powLimit = uint256S(GetArg("-con_powlimit", "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        consensus.parentChainPowLimit = uint256S(GetArg("-con_parentpowlimit", "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        consensus.nPowTargetTimespan = GetArg("-con_npowtargettimespan", 14 * 24 * 60 * 60); // two weeks
        consensus.nPowTargetSpacing = GetArg("-con_npowtargetspacing", 10 * 60);
        consensus.fPowAllowMinDifficultyBlocks = GetBoolArg("-con_fpowallowmindifficultyblocks", true);
        consensus.fPowNoRetargeting = GetBoolArg("-con_fpownoretargeting", true);
        consensus.nRuleChangeActivationThreshold = GetArg("-con_nrulechangeactivationthreshold", 108); // 75% for testchains
        consensus.nMinerConfirmationWindow = GetArg("-con_nminerconfirmationwindow", 144); // Faster than normal for custom (144 instead of 2016)
        consensus.mandatory_coinbase_destination = StrHexToScriptWithDefault(GetArg("-con_mandatorycoinbase", ""), CScript()); // Blank script allows any coinbase destination

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S(GetArg("-con_nminimumchainwork", "0x00"));
        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S(GetArg("-con_defaultassumevalid", "0x00"));
        consensus.pegin_min_depth = GetArg("-peginconfirmationdepth", DEFAULT_PEGIN_CONFIRMATION_DEPTH);
        // bitcoin regtest is the parent chain by default
        parentGenesisBlockHash = uint256S(GetArg("-parentgenesisblockhash", "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"));
        initialFreeCoins = GetArg("-initialfreecoins", 0);

        nDefaultPort = GetArg("-ndefaultport", 7042);
        nPruneAfterHeight = GetArg("-npruneafterheight", 1000);
        fMiningRequiresPeers = GetBoolArg("-fminingrequirespeers", false);
        fDefaultConsistencyChecks = GetBoolArg("-fdefaultconsistencychecks", true);
        fRequireStandard = GetBoolArg("-frequirestandard", false);
        fMineBlocksOnDemand = GetBoolArg("-fmineblocksondemand", true);
        anyonecanspend_aremine = GetBoolArg("-anyonecanspendaremine", true);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, GetArg("-pubkeyprefix", 235));
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, GetArg("-scriptprefix", 75));
        base58Prefixes[BLINDED_ADDRESS]= std::vector<unsigned char>(1, GetArg("-blindedprefix", 4));
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, GetArg("-secretprefix", 239));

        std::string extpubprefix = GetArg("-extpubkeyprefix", "043587CF");
        if (!IsHex(extpubprefix) || extpubprefix.size() != 8) {
            assert("-extpubkeyprefix must be hex string of length 8" && false);
        }
        base58Prefixes[EXT_PUBLIC_KEY] = ParseHex(extpubprefix);

        std::string extprvprefix = GetArg("-extprvkeyprefix", "04358394");
        if (!IsHex(extprvprefix) || extprvprefix.size() != 8) {
            assert("-extprvkeyprefix must be hex string of length 8" && false);
        }
        base58Prefixes[EXT_SECRET_KEY] = ParseHex(extprvprefix);
        base58Prefixes[PARENT_PUBKEY_ADDRESS] = std::vector<unsigned char>(1, GetArg("-parentpubkeyprefix", 111));
        base58Prefixes[PARENT_SCRIPT_ADDRESS] = std::vector<unsigned char>(1, GetArg("-parentscriptprefix", 196));

    }

public:
    CCustomParams(const std::string& chain) : CChainParams(chain)
    {
        this->UpdateFromArgs();

        const CScript defaultRegtestScript(CScript() << OP_TRUE);
        CScript genesisChallengeScript = StrHexToScriptWithDefault(GetArg("-signblockscript", ""), defaultRegtestScript);
        consensus.fedpegScript = StrHexToScriptWithDefault(GetArg("-fedpegscript", ""), defaultRegtestScript);

        if (consensus.fedpegScript != defaultRegtestScript && !consensus.fedpegScript.IsWatchmenScript()) {
            assert(false);
        }

        if (!anyonecanspend_aremine) {
            assert("Anyonecanspendismine was marked as false, but they are in the genesis block"
                    && initialFreeCoins == 0);
        }

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;

        // Generate pegged Bitcoin asset
        std::vector<unsigned char> commit = CommitToArguments(consensus, strNetworkID, genesisChallengeScript);
        uint256 entropy;
        GenerateAssetEntropy(entropy,  COutPoint(uint256(commit), 0), parentGenesisBlockHash);
        CalculateAsset(consensus.pegged_asset, entropy);

        genesis = CreateGenesisBlock(consensus, strNetworkID, 1296688602, genesisChallengeScript, 1);
        if (initialFreeCoins != 0) {
            AppendInitialIssuance(genesis, COutPoint(uint256(commit), 0), parentGenesisBlockHash, 100, initialFreeCoins/100, 0, 0, CScript() << OP_TRUE);
        }
        consensus.hashGenesisBlock = genesis.GetHash();


        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            (     0, consensus.hashGenesisBlock),
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };
    }
};

/**
 * Liquid v1
 */
class CLiquidV1Params : public CChainParams {
public:
    CLiquidV1Params(const std::string& chain) : CChainParams(chain)
    {
        CScript defaultSignblockScript;
        CScript genesisChallengeScript = StrHexToScriptWithDefault("5b21026a2a106ec32c8a1e8052e5d02a7b0a150423dbd9b116fc48d46630ff6e6a05b92102791646a8b49c2740352b4495c118d876347bf47d0551c01c4332fdc2df526f1a2102888bda53a424466b0451627df22090143bbf7c060e9eacb1e38426f6b07f2ae12102aee8967150dee220f613de3b239320355a498808084a93eaf39a34dcd62024852102d46e9259d0a0bb2bcbc461a3e68f34adca27b8d08fbe985853992b4b104e27412102e9944e35e5750ab621e098145b8e6cf373c273b7c04747d1aa020be0af40ccd62102f9a9d4b10a6d6c56d8c955c547330c589bb45e774551d46d415e51cd9ad5116321033b421566c124dfde4db9defe4084b7aa4e7f36744758d92806b8f72c2e943309210353dcc6b4cf6ad28aceb7f7b2db92a4bf07ac42d357adf756f3eca790664314b621037f55980af0455e4fb55aad9b85a55068bb6dc4740ea87276dc693f4598db45fa210384001daa88dabd23db878dbb1ce5b4c2a5fa72c3113e3514bf602325d0c37b8e21039056d089f2fe72dbc0a14780b4635b0dc8a1b40b7a59106325dd1bc45cc70493210397ab8ea7b0bf85bc7fc56bb27bf85e75502e94e76a6781c409f3f2ec3d1122192103b00e3b5b77884bf3cae204c4b4eac003601da75f96982ffcb3dcb29c5ee419b92103c1f3c0874cfe34b8131af34699589aacec4093399739ae352e8a46f80a6f68375fae", defaultSignblockScript);
        CScript defaultFedpegScript;
        consensus.fedpegScript = StrHexToScriptWithDefault("745c87635b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc40102102f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf072103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae", defaultFedpegScript);

        assert(consensus.fedpegScript.IsWatchmenScript());

        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.parentChainPowLimit = uint256S("0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.pegin_min_depth = 100;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;

        nDefaultPort = 7042;
        nPruneAfterHeight = 1000;

        parentGenesisBlockHash = uint256S("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");

        // Generate pegged Bitcoin asset
        std::vector<unsigned char> commit = CommitToArguments(consensus, strNetworkID, genesisChallengeScript);
        uint256 entropy;
        GenerateAssetEntropy(entropy,  COutPoint(uint256(commit), 0), parentGenesisBlockHash);
        CalculateAsset(consensus.pegged_asset, entropy);

        genesis = CreateGenesisBlock(consensus, strNetworkID, 1296688602, genesisChallengeScript, 1);
        consensus.hashGenesisBlock = genesis.GetHash();

        CScript default_mandatory_script;
        consensus.mandatory_coinbase_destination = StrHexToScriptWithDefault("76a914fc26751a5025129a2fd006c6fbfa598ddd67f7e188ac", default_mandatory_script);

        vFixedSeeds.clear();
        vSeeds.clear();

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        anyonecanspend_aremine = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            (     0, consensus.hashGenesisBlock),
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,57);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,39);
        base58Prefixes[BLINDED_ADDRESS]= std::vector<unsigned char>(1,12);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        base58Prefixes[PARENT_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[PARENT_SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
    }
};



/**
 * Liquid Beta 0.9
 */
class CLiquidParams : public CChainParams {
public:
    CLiquidParams(const std::string& chain) : CChainParams(chain)
    {
        CScript defaultSignblockScript;
        CScript genesisChallengeScript = StrHexToScriptWithDefault(GetArg("-signblockscript", ""), defaultSignblockScript);
        CScript defaultFedpegScript;
        consensus.fedpegScript = StrHexToScriptWithDefault(GetArg("-fedpegscript", ""), defaultFedpegScript);

        if (!consensus.fedpegScript.IsWatchmenScript()) {
            bool sad = false;
            assert("fedpegscript is invalid for Liquid Beta" && sad);
        }

        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.parentChainPowLimit = uint256S("0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.pegin_min_depth = 100;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xdb;
        nDefaultPort = 10100;
        nPruneAfterHeight = 1000;

        parentGenesisBlockHash = uint256S("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");

        // Generate pegged Bitcoin asset
        std::vector<unsigned char> commit = CommitToArguments(consensus, strNetworkID, genesisChallengeScript);
        uint256 entropy;
        GenerateAssetEntropy(entropy,  COutPoint(uint256(commit), 0), parentGenesisBlockHash);
        CalculateAsset(consensus.pegged_asset, entropy);

        genesis = CreateGenesisBlock(consensus, strNetworkID, 1296688602, genesisChallengeScript, 1);
        // Single "issuance" of only bitcoin
        AppendInitialIssuance(genesis, COutPoint(uint256(commit), 0), parentGenesisBlockHash, 1, 0, 0, 0, CScript() << OP_TRUE);
        consensus.hashGenesisBlock = genesis.GetHash();


        std::vector<unsigned char> coinbase_script_bytes(ParseHex("522102aef2b8a39966d49183fdddaefdc75af6d81ea6d16f7aba745cc4855e88f830842102141d452c3deeb937efff9f3378cd50bbde0543b77bbc6df6fc0e0addbf5578c52103948d24a9622cb14b198aed0739783d7c03d74c32c05780a86b43429c65679def53ae"));
        CScript raw_multisig(coinbase_script_bytes.begin(), coinbase_script_bytes.end());
        uint160 script_id(Hash160(raw_multisig.begin(), raw_multisig.end()));
        // same as CSV emergency clause for mainnet, 2 of 3 multisig
        consensus.mandatory_coinbase_destination = CScript() << OP_HASH160 << std::vector<unsigned char>(script_id.begin(), script_id.end()) << OP_EQUAL;

        vFixedSeeds.clear();
        vSeeds.clear();

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        anyonecanspend_aremine = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            (     0, consensus.hashGenesisBlock),
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,57);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,39);
        base58Prefixes[BLINDED_ADDRESS]= std::vector<unsigned char>(1,12);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        base58Prefixes[PARENT_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[PARENT_SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
    }
};

/**
 * Use base58 and other old configurations for outdated unittests
 */
class CMainParams : public CCustomParams {
public:
    CMainParams(const std::string& chain) : CCustomParams(chain)
    {
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[BLINDED_ADDRESS]= std::vector<unsigned char>(1,11);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[PARENT_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[PARENT_SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
    }
};


const std::vector<std::string> CChainParams::supportedChains =
    boost::assign::list_of
    ( CHAINPARAMS_REGTEST )
    ( CHAINPARAMS_LIQUID )
    ;

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return std::unique_ptr<CChainParams>(new CMainParams(chain));
    } else if (chain == CBaseChainParams::LIQUID) {
        return std::unique_ptr<CChainParams>(new CLiquidParams(chain));
    } else if (chain == CBaseChainParams::LIQUIDV1) {
        return std::unique_ptr<CChainParams>(new CLiquidV1Params(chain));
    }
    return std::unique_ptr<CChainParams>(new CCustomParams(chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
