// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactionrecord.h"

#include "base58.h"
#include "consensus/consensus.h"
#include "validation.h"
#include "timedata.h"
#include "wallet/wallet.h"

#include <stdint.h>

#include <boost/foreach.hpp>

/* Return positive answer if transaction should be shown in list.
 */
bool TransactionRecord::showTransaction(const CWalletTx &wtx)
{
    if (wtx.IsCoinBase())
    {
        // Ensures we show generated coins / mined transactions at depth 1
        if (!wtx.IsInMainChain())
        {
            return false;
        }
    }
    return true;
}

/*
 * Decompose CWallet transaction to model transaction records.
 */
QList<TransactionRecord> TransactionRecord::decomposeTransaction(const CWallet *wallet, const CWalletTx &wtx)
{
    QList<TransactionRecord> parts;
    int64_t nTime = wtx.GetTxTime();
    uint256 hash = wtx.GetHash();
    std::map<std::string, std::string> mapValue = wtx.mapValue;

    bool involvesWatchAddress = false;
    isminetype fAllFromMe = ISMINE_SPENDABLE;
    bool any_from_me = false;
    std::set<CAsset> assets_issued_to_me_only;
    if (wtx.IsCoinBase()) {
        fAllFromMe = ISMINE_NO;
    } else {
        CAmountMap assets_received_by_me_only;
        for (unsigned int i = 0; i < wtx.tx->vout.size(); i++)
        {
            const CTxOut& txout = wtx.tx->vout[i];
            CAsset asset = wtx.GetOutputAsset(i);
            if (assets_received_by_me_only.count(asset) && assets_received_by_me_only.at(asset) < 0) {
                // Already known to be received by not-me
                continue;
            }
            isminetype mine = wallet->IsMine(txout);
            if (!mine) {
                assets_received_by_me_only[asset] = -1;
            } else {
                assets_received_by_me_only[asset] += wtx.GetOutputValueOut(i);
            }
        }

        any_from_me = false;
        for (size_t i = 0; i < wtx.tx->vin.size(); ++i)
        {
            const CTxIn& txin = wtx.tx->vin[i];
            isminetype mine = wallet->IsMine(txin);
            if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
            if(fAllFromMe > mine) fAllFromMe = mine;
            if (mine) any_from_me = true;

            CAmountMap assets = wtx.GetIssuanceAssets(i);
            for (const auto& asset : assets) {
                if (assets_received_by_me_only.count(asset.first) == 0) {
                    continue;
                }
                if (asset.second == assets_received_by_me_only.at(asset.first)) {
                    // Special case: collapse the chain of issue, send, receive to just an issue
                    assets_issued_to_me_only.insert(asset.first);
                    continue;
                }

                TransactionRecord sub(hash, nTime);
                sub.involvesWatchAddress = involvesWatchAddress;
                sub.asset = asset.first;
                sub.amount = asset.second;
                sub.type = TransactionRecord::IssuedAsset;
                parts.append(sub);
            }
        }
    }

    if (fAllFromMe || !any_from_me)
    {
        BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
        {
            isminetype mine = wallet->IsMine(txout);
            if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
        }

        for (unsigned int i = 0; i < wtx.tx->vout.size(); i++)
        {
            const CTxOut& txout = wtx.tx->vout[i];

            if (txout.scriptPubKey == CScript() /* explicit fee */) {
                // Fees are handled separately below
                continue;
            }

            CAsset asset = wtx.GetOutputAsset(i);

            if (wallet->IsChange(txout) && !(wtx.IsCoinBase() || assets_issued_to_me_only.count(asset))) {
                // Note: New coins need to always be entry'd, even if considered change
                continue;
            }

            if (fAllFromMe && assets_issued_to_me_only.count(asset) == 0) {
                //
                // Debit
                //

                TransactionRecord sub(hash, nTime);
                sub.idx = i;
                sub.involvesWatchAddress = involvesWatchAddress;
                sub.asset = asset;
                sub.amount = -wtx.GetOutputValueOut(i);

                CTxDestination address;
                if (ExtractDestination(txout.scriptPubKey, address))
                {
                    // Sent to Bitcoin Address
                    sub.type = TransactionRecord::SendToAddress;
                    sub.address = CBitcoinAddress(address).ToString();
                }
                else
                {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    sub.type = TransactionRecord::SendToOther;
                    sub.address = mapValue["to"];
                }

                parts.append(sub);
            }

            isminetype mine = wallet->IsMine(txout);
            if(mine)
            {
                //
                // Credit
                //

                TransactionRecord sub(hash, nTime);
                CTxDestination address;
                sub.idx = i; // vout index
                sub.asset = asset;
                sub.amount = wtx.GetOutputValueOut(i);
                sub.involvesWatchAddress = mine & ISMINE_WATCH_ONLY;
                if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*wallet, address))
                {
                    // Received by Bitcoin Address
                    sub.type = TransactionRecord::RecvWithAddress;
                    sub.address = CBitcoinAddress(address).ToString();
                }
                else
                {
                    // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                    sub.type = TransactionRecord::RecvFromOther;
                    sub.address = mapValue["from"];
                }
                if (wtx.IsCoinBase())
                {
                    // Generated
                    sub.type = TransactionRecord::Generated;
                }
                if (assets_issued_to_me_only.count(asset)) {
                    sub.type = TransactionRecord::IssuedAsset;
                }

                parts.append(sub);
            }
        }
        
        if (fAllFromMe) {
            for (const auto& tx_fee : wtx.tx->GetFee()) {
                if (!tx_fee.second) continue;
                
                TransactionRecord sub(hash, nTime);
                sub.type = TransactionRecord::Fee;
                sub.asset = tx_fee.first;
                sub.amount = -tx_fee.second;
                parts.append(sub);
            }
        }
    }
    else
    {
            //
            // Mixed debit transaction, can't break down payees
            // Just add Unknown-type entries with net differences
            //
            CAmountMap debits = wtx.GetDebit(ISMINE_ALL);
            for (const auto& credit : wtx.GetCredit(ISMINE_ALL)) {
                parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "",
                                            credit.first, credit.second - debits[credit.first]));
                parts.last().involvesWatchAddress = involvesWatchAddress;
            }
    }

    return parts;
}

void TransactionRecord::updateStatus(const CWalletTx &wtx)
{
    AssertLockHeld(cs_main);
    // Determine transaction status

    // Find the block the tx is in
    CBlockIndex* pindex = NULL;
    BlockMap::iterator mi = mapBlockIndex.find(wtx.hashBlock);
    if (mi != mapBlockIndex.end())
        pindex = (*mi).second;

    // Sort order, unrecorded transactions sort to the top
    int typesort;
    switch (type) {
    case Fee:
        typesort = 0;
        break;
    case IssuedAsset:
        typesort = 1;
        break;
    case SendToAddress:
    case SendToOther:
    case SendToSelf:
        typesort = 2;
        break;
    case RecvWithAddress:
    case RecvFromOther:
        typesort = 3;
        break;
    default:
        typesort = 10;
    }
    status.sortKey = strprintf("%010d-%01d-%010u-%03d-%d",
        (pindex ? pindex->nHeight : std::numeric_limits<int>::max()),
        (wtx.IsCoinBase() ? 1 : 0),
        wtx.nTimeReceived,
        idx,
        typesort);
    status.countsForBalance = wtx.IsTrusted() && !(wtx.GetBlocksToMaturity() > 0);
    status.depth = wtx.GetDepthInMainChain();
    status.cur_num_blocks = chainActive.Height();

    if (!CheckFinalTx(wtx))
    {
        if (wtx.tx->nLockTime < LOCKTIME_THRESHOLD)
        {
            status.status = TransactionStatus::OpenUntilBlock;
            status.open_for = wtx.tx->nLockTime - chainActive.Height();
        }
        else
        {
            status.status = TransactionStatus::OpenUntilDate;
            status.open_for = wtx.tx->nLockTime;
        }
    }
    // For generated transactions, determine maturity
    else if(type == TransactionRecord::Generated)
    {
        if (wtx.GetBlocksToMaturity() > 0)
        {
            status.status = TransactionStatus::Immature;

            if (wtx.IsInMainChain())
            {
                status.matures_in = wtx.GetBlocksToMaturity();

                // Check if the block was requested by anyone
                if (GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0)
                    status.status = TransactionStatus::MaturesWarning;
            }
            else
            {
                status.status = TransactionStatus::NotAccepted;
            }
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    else
    {
        if (status.depth < 0)
        {
            status.status = TransactionStatus::Conflicted;
        }
        else if (GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0)
        {
            status.status = TransactionStatus::Offline;
        }
        else if (status.depth == 0)
        {
            status.status = TransactionStatus::Unconfirmed;
            if (wtx.isAbandoned())
                status.status = TransactionStatus::Abandoned;
        }
        else if (status.depth < RecommendedNumConfirmations)
        {
            status.status = TransactionStatus::Confirming;
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }

}

bool TransactionRecord::statusUpdateNeeded()
{
    AssertLockHeld(cs_main);
    return status.cur_num_blocks != chainActive.Height();
}

QString TransactionRecord::getTxID() const
{
    return QString::fromStdString(hash.ToString());
}

int TransactionRecord::getOutputIndex() const
{
    return idx;
}
