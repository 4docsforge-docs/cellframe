/*! @file lowmc_constants.c
 *  @brief Constants needed to implement the LowMC block cipher. 
 *
 *  This file is part of the reference implementation of the Picnic signature scheme. 
 *  See the accompanying documentation for complete details. 
 *  
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include "lowmc_constants.h"

typedef struct matrices {
    size_t nmatrices;
    size_t rows;
    size_t columns;
    const uint32_t* data;
} matrices_t;


// Parameters for security level L1
// Block/key size: 128
// Rounds: 20

static const matrices_t LMatrix_L1 =    {20, 128, 4, (uint32_t*) linearMatrices_L1};
static const matrices_t KMatrix_L1 =    {21, 128, 4, (uint32_t*) keyMatrices_L1};
static const matrices_t RConstants_L1 = {20, 1, 4, (uint32_t*) roundConstants_L1};

// Parameters for security level L3
// Block/key size: 192
// Rounds: 30

static const matrices_t LMatrix_L3 =    {30, 192, 6, (uint32_t*) linearMatrices_L3};
static const matrices_t KMatrix_L3 =    {31, 192, 6, (uint32_t*) keyMatrices_L3};
static const matrices_t RConstants_L3 = {30, 1, 6, (uint32_t*) roundConstants_L3};

// Parameters for security level L5
// Block/key size: 256
// Rounds: 38


// Functions to return individual matricies and round constants
#define ROW_SIZE(m) ((m).columns)
#define MAT_SIZE(m) ((m).rows*ROW_SIZE(m))

/* Return a pointer to the r-th matrix. The caller must know the dimensions */
#define GET_MAT(m, r) (&(m).data[(r)*MAT_SIZE(m)])


/* Return the LowMC linear matrix for this round */
const uint32_t* LMatrix(uint32_t round, paramset_t* params)
{

    if(params->stateSizeBits == 128) {
        return GET_MAT(LMatrix_L1, round);
    }
    else if(params->stateSizeBits == 192) {
        return  GET_MAT(LMatrix_L3, round);
    }
    else if(params->stateSizeBits == 256) {
        return GET_MAT(LMatrix_L5, round);
    }
    else {
        return NULL;
    }
}

/* Return the LowMC key matrix for this round */
const uint32_t* KMatrix(uint32_t round, paramset_t* params)
{
    if(params->stateSizeBits == 128) {
        return GET_MAT(KMatrix_L1, round);
    }
    else if(params->stateSizeBits == 192) {
        return GET_MAT(KMatrix_L3, round);
    }
    else if(params->stateSizeBits == 256) {
        return GET_MAT(KMatrix_L5, round);
    }
    else {
        return NULL;
    }
}

/* Return the LowMC round constant for this round */
const uint32_t* RConstant(uint32_t round, paramset_t* params)
{
    if(params->stateSizeBits == 128) {
        return GET_MAT(RConstants_L1, round);
    }
    else if(params->stateSizeBits == 192) {
        return GET_MAT(RConstants_L3, round);
    }
    else if(params->stateSizeBits == 256) {
        return GET_MAT(RConstants_L5, round);
    }
    else {
        return NULL;
    }
}