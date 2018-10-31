#ifndef DAPSCOIN_POW_H
#define DAPSCOIN_POW_H

#include <stdint.h>
#include <primitives/block.h>

class CBlockHeader;
class CBlockIndex;
class uint256;
class arith_uint256;
extern const uint32_t POA_BLOCK_PERIOD;
//unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckPoAContainRecentHash(CBlock* block, int blockHeight = -1);
bool CheckNumberOfAuditedPoSBlocks(CBlock* block);
bool CheckPoABlockMinedHash(CBlock* block);
bool CheckPrevPoABlockHash(CBlock* block, int blockheight = -1);
bool CheckPoAMerkleRoot(CBlock* block);

//uint256 GetBlockProof(const CBlockIndex& block);

#endif // DAPSCOIN_POW_H
