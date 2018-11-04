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

//Check PoA block header consensus rules
bool CheckPrevPoABlockHash(const CBlockHeader& block, int blockheight = -1);
bool CheckPoABlockMinedHash(const CBlockHeader& block);

bool CheckPoAMerkleRoot(const CBlock& block, bool* fMutate = false);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckPoAContainRecentHash(const CBlock& block, int blockHeight = -1);
bool CheckNumberOfAuditedPoSBlocks(const CBlock& block);
bool CheckPoABlockNotContainingPoABlockInfo(const CBlock& block, int blockheight = -1);

//uint256 GetBlockProof(const CBlockIndex& block);

#endif // DAPSCOIN_POW_H
