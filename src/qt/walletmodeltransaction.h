// Copyright (c) 2011-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_WALLETMODELTRANSACTION_H
#define BITCOIN_QT_WALLETMODELTRANSACTION_H

#include "walletmodel.h"

#include <QObject>

class SendAssetsRecipient;

class CReserveKey;
class CWallet;
class CWalletTx;

/** Data model for a walletmodel transaction. */
class WalletModelTransaction
{
public:
    explicit WalletModelTransaction(const QList<SendAssetsRecipient> &recipients);
    ~WalletModelTransaction();

    QList<SendAssetsRecipient> getRecipients();

    CWalletTx *getTransaction();
    unsigned int getTransactionSize();

    void setTransactionFee(const CAmount& newFee);
    CAmount getTransactionFee();

    CAmountMap getTotalTransactionAmount();

    void newPossibleKeyChange(CWallet *wallet);
    std::vector<CReserveKey> *getPossibleKeyChange();

    void reassignAmounts(const std::vector<CAmount>& outAmounts, int nChangePosRet); // needed for the subtract-fee-from-amount feature

private:
    QList<SendAssetsRecipient> recipients;
    CWalletTx *walletTransaction;
    std::vector<CReserveKey> keyChange;
    CAmount fee;
};

#endif // BITCOIN_QT_WALLETMODELTRANSACTION_H
