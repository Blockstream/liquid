// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparamsbase.h"

#include "tinyformat.h"
#include "util.h"

#include <assert.h>

const std::string CBaseChainParams::MAIN = CHAINPARAMS_OLD_MAIN;
const std::string CBaseChainParams::REGTEST = CHAINPARAMS_REGTEST;
const std::string CBaseChainParams::LIQUID = CHAINPARAMS_LIQUID;
const std::string CBaseChainParams::LIQUIDV1 = CHAINPARAMS_LIQUIDV1;

void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp)
{
    strUsage += HelpMessageGroup(_("Chain selection options:"));
    strUsage += HelpMessageOpt("-chain=<chain>", strprintf(_("Use the chain <chain> (default: %s). Anything except main is allowed"), CHAINPARAMS_REGTEST));
    if (debugHelp) {
        strUsage += HelpMessageOpt("-regtest", strprintf(_("Equivalent to -chain=%s"), CHAINPARAMS_REGTEST));
    }
}

static std::unique_ptr<CBaseChainParams> globalChainBaseParams;

const CBaseChainParams& BaseParams()
{
    assert(globalChainBaseParams);
    return *globalChainBaseParams;
}

std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CBaseChainParams>(new CBaseChainParams(chain, 8332, 18332));
    else if (chain == CHAINPARAMS_LIQUID)
        return std::unique_ptr<CBaseChainParams>(new CBaseChainParams(chain, 10099, 8332));
    else if (chain == CHAINPARAMS_LIQUIDV1)
        return std::unique_ptr<CBaseChainParams>(new CBaseChainParams(chain, 7041, 8332));
    return std::unique_ptr<CBaseChainParams>(new CBaseChainParams(chain, 7040, 18331));
}

void SelectBaseParams(const std::string& chain)
{
    globalChainBaseParams = CreateBaseChainParams(chain);
}

std::string ChainNameFromCommandLine()
{
    if (GetBoolArg("-testnet", false))
        throw std::runtime_error(strprintf("%s: Invalid option -testnet: try -chain=%s instead.", __func__, CHAINPARAMS_REGTEST));
    if (GetBoolArg("-regtest", false))
        return CBaseChainParams::REGTEST;
    return GetArg("-chain", CHAINPARAMS_LIQUIDV1);
}
