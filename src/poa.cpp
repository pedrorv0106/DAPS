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

bool CheckPoAContainRecentHash(CBlock* block) {
    if (block->posBlocksAudited.size() < POA_BLOCK_PERIOD) {
        return false;
    }
    //block.Merkle
    int currentHeight = chainActive.Tip()->nHeight;
    bool ret = true;
    if (currentHeight - (POA_BLOCK_PERIOD + 1) == Params().START_POA_BLOCK()) {
        //this is the first PoA block ==> check all PoS blocks from LAST_POW_BLOCK up to currentHeight - POA_BLOCK_PERIOD - 1 inclusive
        int index = 0;
        for (int i = Params().LAST_POW_BLOCK() + 1; i <= currentHeight - POA_BLOCK_PERIOD; i++) {
            PoSBlockSummary pos = block->posBlocksAudited.at(index);
            if (pos.hash != chainActive[i]->GetBlockHash()
                    || pos.nTime != chainActive[i]->GetBlockTime()
                    || pos.height != chainActive[i]->nHeight) {
                ret = false;
                break;
            }
        }
    } else {
        //Find the previous PoA block
        int start = currentHeight;
        while (start > Params().START_POA_BLOCK()) {
            if (chainActive[start]->GetBlockHeader().IsPoABlockByVersion()) {
                break;
            }
            start--;
        }
        if (start > Params().START_POA_BLOCK()) {
            uint256 prevPoaHash = chainActive[start]->GetBlockHash();
            CBlock prevPoablock;
            CBlockIndex* pblockindex = chainActive[start];
            if (!ReadBlockFromDisk(prevPoablock, pblockindex))
                throw runtime_error("Can't read block from disk");
            PoSBlockSummary lastAuditedPoSBlockInfo = prevPoablock.posBlocksAudited.back();
            uint32_t lastAuditedPoSHeight = lastAuditedPoSBlockInfo.height;
            uint32_t loopIndexCheckPoS = lastAuditedPoSHeight + 1;
            uint32_t idxOfPoSInfo = 0;

            while (lastAuditedPoSHeight <= currentHeight) {
                if (chainActive[lastAuditedPoSHeight]->GetBlockHeader().IsPoABlockByVersion()
                        && chainActive[lastAuditedPoSHeight]->nHeight > Params().LAST_POW_BLOCK()) {
                    PoSBlockSummary pos = block->posBlocksAudited[idxOfPoSInfo];
                    CBlockIndex* posAudited = chainActive[lastAuditedPoSHeight];
                    if (pos.hash == *(posAudited->phashBlock)
                        && pos.height == posAudited->nHeight
                        && pos.nTime == posAudited->GetBlockTime()) {
                        idxOfPoSInfo++;
                    } else {
                        //The PoA block is not satisfied the constraint
                        ret = false;
                        break;
                    }
                }
                lastAuditedPoSHeight++;
            }
            if (idxOfPoSInfo != block->posBlocksAudited.size() - 1) {
                //Not all PoS Blocks in PoA block have been checked, not satisfied
                ret = false;
            }
        } else {
            ret = false;
        }
    }
    return ret;
}
