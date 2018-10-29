// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2015-2017 The DAPScoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "poa.h"

#include "chain.h"
#include "chainparams.h"
#include "main.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

#include <math.h>

const uint32_t POA_BLOCK_PERIOD = 59;

bool CheckProofOfAudit(CBlock* block) {
    //block.Merkle
    uint32_t currentHeight = chainActive.Tip().nHeight();
    if (currentHeight - (POA_BLOCK_PERIOD + 1) == Params().START_POA_BLOCK()) {
        //this is the first PoA block ==> check all PoS blocks from LAST_POW_BLOCK up to currentHeight - 59 inclusive
        for (uint32_t i = Params().LAST_POW_BLOCK() + 1; i <= currentHeight - 59; i++) {
            PoSBlockSummary pos;
            pos.hash = *(chainActive[i]->GetBlockHash());
            pos.nTime = chainActive[i]->GetBlockHeader().nTime;
            pos.height = i;
            audits.push_back(pos)
        }
    } else {
        //Find the previous PoA block
        uint32_t start = currentHeight;
        while (start > Params().START_POA_BLOCK()) {
            if (chainActive[start]->GetBlockHeader().IsPoABlockByVersion()) {
                break;
            }
            start--;
        }
        if (start > Params().START_POA_BLOCK()) {
            uint256 poaHash = *(chainActive[start]->GetBlockHash());
            CBlock block;
            CBlockIndex* pblockindex = mapBlockIndex[poaHash];
            if (!ReadBlockFromDisk(block, pblockindex))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
            PoSBlockSummary back = block.posBlocksAudited.back();
            uint32_t lastAuditedHeight = back.height;
            uint32_t nextAuditHeight = lastAuditedHeight + 1;
            
            while (nextAuditHeight <= currentHeight) {
                if (chainActive[nextAuditHeight]->GetBlockHeader().IsProofOfStake()) {
                    PoSBlockSummary pos;
                    pos.hash = *(chainActive[nextAuditHeight]->GetBlockHash());
                    pos.nTime = chainActive[nextAuditHeight]->GetBlockHeader().nTime;
                    pos.height = i;
                    audits.push_back(pos)
                }
                if (audits.size() == 59) {
                    break;
                }
                nextAuditHeight++;
            }
        }
    }
}