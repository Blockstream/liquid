// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "core_io.h"

namespace {

static secp256k1_context *secp256k1_ctx;

class CSecp256k1Init {
public:
    CSecp256k1Init() {
        secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    }
    ~CSecp256k1Init() {
        secp256k1_context_destroy(secp256k1_ctx);
    }
};
static CSecp256k1Init instance_of_csecp256k1;
}

CScript CPAKList::Magic()
{
    CScript scriptPubKey;
    scriptPubKey.resize(6);
    scriptPubKey[0] = OP_RETURN;
    scriptPubKey[1] = 0x04;
    scriptPubKey[2] = 0xab;
    scriptPubKey[3] = 0x22;
    scriptPubKey[4] = 0xaa;
    scriptPubKey[5] = 0xee;
    return scriptPubKey;
}

std::vector<CScript> CPAKList::GenerateCoinbasePAKCommitments() const
{
    std::vector<CScript> commitments;
    CScript scriptPubKey = CPAKList::Magic();

    for (unsigned int i = 0; i < m_offline_keys.size(); i++) {
        CScript scriptCommitment(scriptPubKey);
        unsigned char pubkey[33];
        size_t outputlen = 33;
        secp256k1_ec_pubkey_serialize(secp256k1_ctx, pubkey, &outputlen, &m_offline_keys[i], SECP256K1_EC_COMPRESSED);
        assert(outputlen == 33);
        scriptCommitment << std::vector<unsigned char>(pubkey, pubkey+outputlen);
        secp256k1_ec_pubkey_serialize(secp256k1_ctx, pubkey, &outputlen, &m_online_keys[i], SECP256K1_EC_COMPRESSED);
        assert(outputlen == 33);
        scriptCommitment << std::vector<unsigned char>(pubkey, pubkey+outputlen);
        commitments.push_back(scriptCommitment);
    }

    return commitments;
}

CScript CPAKList::GenerateCoinbasePAKReject() const
{
    CScript scriptPubKey = CPAKList::Magic();

    std::vector<unsigned char> reject;
    reject.push_back('R');
    reject.push_back('E');
    reject.push_back('J');
    reject.push_back('E');
    reject.push_back('C');
    reject.push_back('T');

    scriptPubKey << reject;

    return scriptPubKey;
}

void CPAKList::CreateCommitments(std::vector<CScript> &commitments) const
{
    commitments.resize(0);
    if(reject) {
        commitments.push_back(GenerateCoinbasePAKReject());
    } else {
        commitments = GenerateCoinbasePAKCommitments();
    }
}

bool CPAKList::operator==(const CPAKList &other) const
{
    if (this->reject != other.reject) {
        return false;
    } else if (this->m_offline_keys.size() != other.m_offline_keys.size()) {
        return false;
    } else {
        for (unsigned int i = 0; i < this->m_offline_keys.size(); i++) {
            if (memcmp(&this->m_offline_keys[i], &other.m_offline_keys[i], sizeof(secp256k1_pubkey)) != 0 ||
                    memcmp(&this->m_online_keys[i], &other.m_online_keys[i], sizeof(secp256k1_pubkey)) != 0) {
                return false;
            }
        }
    }
    return true;
}

bool CPAKList::FromBytes(CPAKList &paklist, std::vector<std::vector<unsigned char> >& offline_keys_bytes, std::vector<std::vector<unsigned char> >& online_keys_bytes, bool is_reject)
{
    if(offline_keys_bytes.size() != online_keys_bytes.size()
        || offline_keys_bytes.size() > SECP256K1_WHITELIST_MAX_N_KEYS) {
        return false;
    }

    std::vector<secp256k1_pubkey> offline_keys;
    std::vector<secp256k1_pubkey> online_keys;
    for (unsigned int i = 0; i < offline_keys_bytes.size(); i++) {
        secp256k1_pubkey pubkey1;
        secp256k1_pubkey pubkey2;
        int ret1 = secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey1, &offline_keys_bytes[i][0], offline_keys_bytes[i].size());
        int ret2 = secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey2, &online_keys_bytes[i][0], online_keys_bytes[i].size());

        if (ret1 != 1 || ret2 != 1) {
            return false;
        }
        offline_keys.push_back(pubkey1);
        online_keys.push_back(pubkey2);
    }

    paklist = CPAKList(offline_keys, online_keys, is_reject);
    return true;
}

void CPAKList::ToBytes(std::vector<std::vector<unsigned char> >& offline_keys, std::vector<std::vector<unsigned char> >& online_keys, bool &is_reject) const
{
    offline_keys.resize(0);
    online_keys.resize(0);

    for (unsigned int i = 0; i < m_offline_keys.size(); i++) {
        unsigned char pubkey[33];
        size_t outputlen = 33;
        secp256k1_ec_pubkey_serialize(secp256k1_ctx, pubkey, &outputlen, &m_offline_keys[i], SECP256K1_EC_COMPRESSED);
        offline_keys.push_back(std::vector<unsigned char>(pubkey, pubkey+outputlen));
        secp256k1_ec_pubkey_serialize(secp256k1_ctx, pubkey, &outputlen, &m_online_keys[i], SECP256K1_EC_COMPRESSED);
        online_keys.push_back(std::vector<unsigned char>(pubkey, pubkey+outputlen));
    }
    is_reject = reject;
}

std::string CProof::ToString() const
{
    return strprintf("CProof(challenge=%s, solution=%s)",
                     ScriptToAsmStr(challenge), ScriptToAsmStr(solution));
}

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, proof=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime,
        proof.ToString(),
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i]->ToString() << "\n";
    }
    return s.str();
}

int64_t GetBlockWeight(const CBlock& block)
{
    // This implements the weight = (stripped_size * 4) + witness_size formula,
    // using only serialization with and without witness data. As witness_size
    // is equal to total_size - stripped_size, this formula is identical to:
    // weight = (stripped_size * 3) + total_size.
    return ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
}
