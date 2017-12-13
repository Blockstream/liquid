// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include "primitives/transaction.h"
#include "script/script.h"
#include "serialize.h"
#include "uint256.h"
#include "secp256k1/include/secp256k1_whitelist.h"

class CPAKList
{
private:
    std::vector<secp256k1_pubkey> m_offline_keys;
    std::vector<secp256k1_pubkey> m_online_keys;
    bool reject;

    std::vector<CScript> GenerateCoinbasePAKCommitments() const;
    CScript GenerateCoinbasePAKReject() const;

public:
    CPAKList()
    {
        reject = true;
    }
    /**
     * Creates a new CPAKList. Requires that the number of offline keys is the same as the number of online keys
     * and that this number is not larger than SECP256K1_WHITELIST_MAX_N_KEYS.
     */
    CPAKList(std::vector<secp256k1_pubkey> offline_keys, std::vector<secp256k1_pubkey> online_keys, bool reject) :
        m_offline_keys(offline_keys), m_online_keys(online_keys), reject(reject) {
            assert(m_offline_keys.size() == m_online_keys.size());
            assert(m_offline_keys.size() <= SECP256K1_WHITELIST_MAX_N_KEYS);
       }

    bool operator==(const CPAKList &other) const;
    bool operator!=(const CPAKList &other) const
    {
        return !(*this == other);
    }
    bool IsReject() const
    {
        return reject;
    }
    bool IsEmpty() const
    {
        return !reject && this->size() == 0;
    }
    std::vector<secp256k1_pubkey> OnlineKeys() const
    {
        return m_online_keys;
    }
    std::vector<secp256k1_pubkey> OfflineKeys() const
    {
        return m_offline_keys;
    }
    size_t size() const
    {
        return m_offline_keys.size();
    }

    static CScript Magic();
    /** Produce a list of scripts to add to the coinbase to signal changes in PAK list or rejection of any pak proofs to nodes */
    void CreateCommitments(std::vector<CScript> &commitments) const;

    static bool FromBytes(CPAKList &paklist, std::vector<std::vector<unsigned char> >& offline_keys, std::vector<std::vector<unsigned char> >& online_keys, bool is_reject);
    void ToBytes(std::vector<std::vector<unsigned char> >& offline_keys, std::vector<std::vector<unsigned char> >& online_keys, bool &is_reject) const;
};

class CProof
{
public:
    CScript challenge;
    CScript solution;

    CProof()
    {
        SetNull();
    }
    CProof(CScript challengeIn, CScript solutionIn) : challenge(challengeIn), solution(solutionIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(*(CScriptBase*)(&challenge));
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(*(CScriptBase*)(&solution));
    }

    void SetNull()
    {
        challenge.clear();
        solution.clear();
    }

    bool IsNull() const
    {
        return challenge.empty();
    }

    std::string ToString() const;
};

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nHeight;
    CProof proof;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nHeight);
        READWRITE(proof);
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nHeight = 0;
        proof.SetNull();
    }

    bool IsNull() const
    {
        return proof.IsNull();
    }

    uint256 GetHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nHeight        = nHeight;
        block.proof          = proof;
        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

/** Compute the consensus-critical block weight (see BIP 141). */
int64_t GetBlockWeight(const CBlock& tx);

#endif // BITCOIN_PRIMITIVES_BLOCK_H
