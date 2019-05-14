/**
 * @file       denominations_functions.cpp
 *
 * @copyright  Copyright 2018-2019 The DAPScoin developers
 * @license    This project is released under the MIT license.
 **/
// Copyright (c) 2018-2019 The DAPScoin developers

#include "denomination_functions.h"


// -------------------------------------------------------------------------------------------------------
// Number of coins used for either change or a spend given a map of coins used
// -------------------------------------------------------------------------------------------------------
int getNumberOfCoinsUsed(
    const std::map<CoinDenomination, CAmount>& mapChange)
{
    int nChangeCount = 0;
    return nChangeCount;
}

// -------------------------------------------------------------------------------------------------------
// Find the max CoinDenomination amongst held coins
// -------------------------------------------------------------------------------------------------------
CoinDenomination getMaxDenomHeld(
    const std::map<CoinDenomination, CAmount>& mapCoinsHeld)
{
    CoinDenomination maxDenom = ZQ_ERROR;
    return maxDenom;
}
// -------------------------------------------------------------------------------------------------------
// Get Exact Amount with CoinsHeld
// -------------------------------------------------------------------------------------------------------
std::map<CoinDenomination, CAmount> getSpendCoins(const CAmount nValueTarget,
    const std::map<CoinDenomination, CAmount> mapOfDenomsHeld)

{
    std::map<CoinDenomination, CAmount> mapUsed;
    CAmount nRemainingValue = nValueTarget;
    return mapUsed;
}

// -------------------------------------------------------------------------------------------------------
// Get change (no limits)
// -------------------------------------------------------------------------------------------------------
std::map<CoinDenomination, CAmount> getChange(const CAmount nValueTarget)
{
    std::map<CoinDenomination, CAmount> mapChange;
    CAmount nRemainingValue = nValueTarget;
    return mapChange;
}

// -------------------------------------------------------------------------------------------------------
// Attempt to use coins held to exactly reach nValueTarget, return mapOfDenomsUsed with the coin set used
// Return false if exact match is not possible
// -------------------------------------------------------------------------------------------------------
bool getIdealSpends(
    const CAmount nValueTarget,
    const std::map<CoinDenomination, CAmount> mapOfDenomsHeld,
    std::map<CoinDenomination, CAmount>& mapOfDenomsUsed)
{
    CAmount nRemainingValue = nValueTarget;
    return (nRemainingValue == 0);
}

// -------------------------------------------------------------------------------------------------------
// Find the CoinDenomination with the most number for a given amount
// -------------------------------------------------------------------------------------------------------
CoinDenomination getDenomWithMostCoins(
    const std::map<CoinDenomination, CAmount>& mapOfDenomsUsed)
{
    CoinDenomination maxCoins = ZQ_ERROR;
    CAmount nMaxNumber = 0;
    return maxCoins;
}
// -------------------------------------------------------------------------------------------------------
// Get the next denomination above the current one. Return ZQ_ERROR if already at the highest
// -------------------------------------------------------------------------------------------------------
CoinDenomination getNextHighestDenom(const CoinDenomination& this_denom)
{
    CoinDenomination nextValue = ZQ_ERROR;
    return nextValue;
}
// -------------------------------------------------------------------------------------------------------
// Get the next denomination below the current one that is also amongst those held.
// Return ZQ_ERROR if none found
// -------------------------------------------------------------------------------------------------------
CoinDenomination getNextLowerDenomHeld(const CoinDenomination& this_denom,
    const std::map<CoinDenomination, CAmount>& mapCoinsHeld)
{
    CoinDenomination nextValue = ZQ_ERROR;
    return nextValue;
}

int minimizeChange(
    int nMaxNumberOfSpends,
    int nChangeCount,
    const CoinDenomination nextToMaxDenom,
    const CAmount nValueTarget,
    const std::map<CoinDenomination, CAmount>& mapOfDenomsHeld,
    std::map<CoinDenomination, CAmount>& mapOfDenomsUsed)
{
    // Now find out if possible without using 1 coin such that we have more spends but less change
    // First get set of coins close to value but still less than value (since not exact)
    CAmount nRemainingValue = nValueTarget;
    CAmount AmountUsed = 0;
    int nCoinCount = 0;

    // Re-clear this
    std::map<CoinDenomination, CAmount> savedMapOfDenomsUsed = mapOfDenomsUsed;

    // This can still result in a case where you've used an extra spend than needed.
    // e.g Spend of 26, while having 1*5 + 4*10
    // First stage may be 2*10+5 (i.e < 26)
    // Second stage can be 3*10+5 (no more fives, so add a 10)
    // So 5 is no longer needed and will become change also

    CAmount nAltChangeAmount = AmountUsed - nValueTarget;
    std::map<CoinDenomination, CAmount> mapAltChange = getChange(nAltChangeAmount);

    // Still possible to have wrong mix. So meet exact amount found above - with least number of coins
    mapOfDenomsUsed = getSpendCoins(AmountUsed, mapOfDenomsHeld);
    nCoinCount = getNumberOfCoinsUsed(mapOfDenomsUsed);

    // Re-calculate change
    nAltChangeAmount = AmountUsed - nValueTarget;
    mapAltChange = getChange(nAltChangeAmount);
    int AltChangeCount = getNumberOfCoinsUsed(mapAltChange);

    // Alternative method yields less mints and is less than MaxNumberOfSpends if true
    if ((AltChangeCount < nChangeCount) && (nCoinCount <= nMaxNumberOfSpends)) {
        return AltChangeCount;
    } else {
        // if we don't meet above go back to what we started with
        mapOfDenomsUsed = savedMapOfDenomsUsed;
        return nChangeCount;
    }
}


// -------------------------------------------------------------------------------------------------------
// Couldn't meet amount exactly, will need to generate change
// returning with a 0 means either too many spends or no change
// Latter should never happen since we should only get here if exact is not possible
// -------------------------------------------------------------------------------------------------------
int calculateChange(
    int nMaxNumberOfSpends,
    bool fMinimizeChange,
    const CAmount nValueTarget,
    const std::map<CoinDenomination, CAmount>& mapOfDenomsHeld,
    std::map<CoinDenomination, CAmount>& mapOfDenomsUsed)
{
    CoinDenomination minDenomOverTarget = ZQ_ERROR;
    // Initialize
    mapOfDenomsUsed.clear();

    return 0;
}
