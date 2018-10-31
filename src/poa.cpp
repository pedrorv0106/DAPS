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

//If blockheight = -1, the to-be-checked block is not included yet in the chain, otherwise, that is the height of the poa block
bool CheckPoAContainRecentHash(CBlock* block, int blockHeight) {
    if (block->posBlocksAudited.size() < POA_BLOCK_PERIOD) {
        return false;
    }
    //block.Merkle
    int currentHeight = chainActive.Tip()->nHeight;
    if (blockHeight != - 1) {
        currentHeight = blockHeight - 1;
    }
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

bool CheckNumberOfAuditedPoSBlocks(CBlock* block) {
    if (block->posBlocksAudited.size() < POA_BLOCK_PERIOD) {
        return false;
    }
    return true;
}

//Check whether the block is successfully mined and the mined hash satisfy the difficulty
bool CheckPoABlockMinedHash(CBlock* block) {
    const uint256 minedHash = block->ComputeMinedHash();
    if (minedHash == block->minedHash) {
        //Check minedHash satisfy difficulty based on nbits
        bool fNegative;
        bool fOverflow;
        uint256 bnTarget;

        if (Params().SkipProofOfWorkCheck())
            return true;

        bnTarget.SetCompact(block->nBits, &fNegative, &fOverflow);

        // Check range
        if (fNegative || bnTarget == 0 || fOverflow || bnTarget > Params().ProofOfWorkLimit())
            return error("CheckProofOfWork() : nBits below minimum work");

        // Check proof of work matches claimed amount
        if (minedHash > bnTarget)
            return error("CheckProofOfWork() : hash doesn't match nBits");

        return true;
    }
    return false;
}

//A PoA block should contains previous PoA block hash
bool CheckPrevPoABlockHash(CBlock* block, int blockHeight) {
    uint256 blockHash = block->hashPrevPoABlock;
    int currentHeight = chainActive.Tip()->nHeight;
    if (blockHeight != - 1) {
        currentHeight = blockHeight - 1;
    }
    int start = currentHeight;
    while (start > Params().START_POA_BLOCK()) {
        if (chainActive[start]->GetBlockHeader().IsPoABlockByVersion()) {
            break;
        }
        start--;
    }
    bool ret = false;

    if (start > Params().START_POA_BLOCK()) {
        CBlockHeader header = chainActive[start]->GetBlockHeader();
        uint256 poaBlockHash = header.GetHash();
        if (poaBlockHash == block->hashPrevPoABlock) {
            ret = true;
        }
    }

    return ret;
}

//Check whether the poa merkle root is correctly computed
bool CheckPoAMerkleRoot(CBlock* block) {
    uint256 expected = block->BuildPoAMerkleTree();
    if (expected == block->hashPoAMerkleRoot) {
        return true;
    }
    return false;
}

//A PoA block cannot contain information of any PoA block information (hash, height, timestamp)
bool CheckPoABlockNotContainingPoABlockInfo(CBlock* block, int blockheight) {
    //block.Merkle
    int currentHeight = chainActive.Tip()->nHeight;
    if (blockHeight != - 1) {
        currentHeight = blockHeight - 1;
    }
    uint32_t numOfPoSBlocks = block->posBlocksAudited.size();
    for (int i = 0; i < numOfPoSBlocks; i++) {
        PoSBlockSummary pos = block->posBlocksAudited.at(i);
        uint256 hash = pos.hash;
        if (mapBlockIndex.count(hash) == 0) {
            return false;
        }
        CBlockIndex* pblockindex = mapBlockIndex[hash];
        CBlockHeader header = pblockindex->GetBlockHeader();
        if (header.IsPoABlockByVersion()) {
            return false;
        }
        if (pblockindex->nTime != block->nTime || pblockindex->nBits != block->nBits) {
            return false;
        }
    }
    return true;
}
