/* Microsoft Reference Implementation for TPM 2.0
 *
 *  The copyright in this software is being made available under the BSD License,
 *  included below. This software may be subject to other third party and
 *  contributor rights, including patent rights, and no such rights are granted
 *  under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
//** Description
// This file contains the entry point for the simulator.

//** Includes, Defines, Data Definitions, and Function Prototypes
#include "TpmBuildSwitches.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>

#ifdef _MSC_VER
#  pragma warning(push, 3)
#  include <windows.h>
#  include <winsock.h>
#  pragma warning(pop)
#elif defined(__unix__) || defined(__APPLE__)
#  define _strcmpi strcasecmp
typedef int SOCKET;
#else
#  error "Unsupported platform."
#endif

#include "TpmTcpProtocol.h"
#include "Manufacture_fp.h"
#include "Platform_fp.h"
#include "Simulator_fp.h"

#define PURPOSE                      \
    "TPM 2.0 Reference Simulator.\n" \
    "Copyright (c) Microsoft Corporation. All rights reserved."

#define DEFAULT_TPM_PORT 2321

int DRBG_FIXED_SEED = 0;  // random seed - set by the command line (default value = 0)

uint8_t DRBG_NistTestVector_Entropy[48];

#define DRBG_TEST_INITIATE_ENTROPY_SEED_0_tmp                                     \
    0x0d, 0x15, 0xaa, 0x80, 0xb1, 0x6c, 0x3a, 0x10, 0x90, 0x6c, 0xfe, 0xdb, 0x79, \
        0x5d, 0xae, 0x0b, 0x5b, 0x81, 0x04, 0x1c, 0x5c, 0x5b, 0xfa, 0xcb, 0x37,   \
        0x3d, 0x44, 0x40, 0xd9, 0x12, 0x0f, 0x7e, 0x3d, 0x6c, 0xf9, 0x09, 0x86,   \
        0xcf, 0x52, 0xd8, 0x5d, 0x3e, 0x94, 0x7d, 0x8c, 0x06, 0x1f, 0x91

#define DRBG_TEST_INITIATE_ENTROPY_SEED_1_tmp                                     \
    0x0e, 0x15, 0xaa, 0x80, 0xb1, 0x6c, 0x3a, 0x10, 0x90, 0x6c, 0xfe, 0xdb, 0x79, \
        0x5d, 0xae, 0x0b, 0x5b, 0x81, 0x04, 0x1c, 0x5c, 0x5b, 0xfa, 0xcb, 0x37,   \
        0x3d, 0x44, 0x40, 0xd9, 0x12, 0x0f, 0x7e, 0x3d, 0x6c, 0xf9, 0x09, 0x86,   \
        0xcf, 0x52, 0xd8, 0x5d, 0x3e, 0x94, 0x7d, 0x8c, 0x06, 0x1f, 0x91

#define DRBG_TEST_INITIATE_ENTROPY_SEED_2_tmp                                     \
    0x0f, 0x15, 0xaa, 0x80, 0xb1, 0x6c, 0x3a, 0x10, 0x90, 0x6c, 0xfe, 0xdb, 0x79, \
        0x5d, 0xae, 0x0b, 0x5b, 0x81, 0x04, 0x1c, 0x5c, 0x5b, 0xfa, 0xcb, 0x37,   \
        0x3d, 0x44, 0x40, 0xd9, 0x12, 0x0f, 0x7e, 0x3d, 0x6c, 0xf9, 0x09, 0x86,   \
        0xcf, 0x52, 0xd8, 0x5d, 0x3e, 0x94, 0x7d, 0x8c, 0x06, 0x1f, 0x91

// Information about command line arguments (does not include program name)
static uint32_t     s_ArgsMask = 0;  // Bit mask of unmatched command line args
static int          s_Argc     = 0;
static const char** s_Argv     = NULL;

//** Functions

#if DEBUG
//*** Assert()
// This function implements a run-time assertion.
// Computation of its parameters must not result in any side effects, as these
// computations will be stripped from the release builds.
static void Assert(bool cond, const char* msg)
{
    if(cond)
        return;
    fputs(msg, stderr);
    exit(2);
}
#else
#  define Assert(cond, msg)
#endif

//*** Usage()
// This function prints the proper calling sequence for the simulator.
static void Usage(const char* programName)
{
    fprintf(stderr, "%s\n\n", PURPOSE);
    fprintf(stderr,
            "Usage:  %s [PortNum] [opts]\n\n"
            "Starts the TPM server listening on TCP port PortNum (by default %d).\n\n"
            "An option can be in the short form (one letter preceded with '-' or "
            "'/')\n"
            "or in the full form (preceded with '--' or no option marker at all).\n"
            "Possible options are:\n"
            "   -h (--help) or ? - print this message\n"
            "   -m (--manufacture) - forces NV state of the TPM simulator to be "
            "(re)manufactured\n",
            programName,
            DEFAULT_TPM_PORT);
    exit(1);
}

//*** CmdLineParser_Init()
// This function initializes command line option parser.
static bool CmdLineParser_Init(int argc, char* argv[], int maxOpts)
{
    if(argc == 1)
        return false;

    if(maxOpts && (argc - 1) > maxOpts)
    {
        fprintf(stderr, "No more than %d options can be specified\n\n", maxOpts);
        Usage(argv[0]);
    }

    s_Argc     = argc - 1;
    s_Argv     = (const char**)(argv + 1);
    s_ArgsMask = (1 << s_Argc) - 1;
    return true;
}

//*** CmdLineParser_More()
// Returns true if there are unparsed options still.
static bool CmdLineParser_More(void)
{
    return s_ArgsMask != 0;
}

//*** CmdLineParser_IsOpt()
// This function determines if the given command line parameter represents a valid
// option.
static bool CmdLineParser_IsOpt(
    const char* opt,       // Command line parameter to check
    const char* optFull,   // Expected full name
    const char* optShort,  // Expected short (single letter) name
    bool        dashed     // The parameter is preceded by a single dash
)
{
    return 0 == strcmp(opt, optFull)
           || (optShort && opt[0] == optShort[0] && opt[1] == 0)
           || (dashed && opt[0] == '-' && 0 == strcmp(opt + 1, optFull));
}

//*** CmdLineParser_IsOptPresent()
// This function determines if the given command line parameter represents a valid
// option.
static bool CmdLineParser_IsOptPresent(const char* optFull, const char* optShort)
{
    int i;
    int curArgBit;
    Assert(s_Argv != NULL, "InitCmdLineOptParser(argc, argv) has not been invoked\n");
    Assert(optFull && optFull[0],
           "Full form of a command line option must be present.\n"
           "If only a short (single letter) form is supported, it must be"
           "specified as the full one.\n");
    Assert(!optShort || (optShort[0] && !optShort[1]),
           "If a short form of an option is specified, it must consist "
           "of a single letter only.\n");

    if(!CmdLineParser_More())
        return false;

    for(i = 0, curArgBit = 1; i < s_Argc; ++i, curArgBit <<= 1)
    {
        const char* opt = s_Argv[i];
        if((s_ArgsMask & curArgBit) && opt
           && (0 == strcmp(opt, optFull)
               || ((opt[0] == '/' || opt[0] == '-')
                   && CmdLineParser_IsOpt(
                       opt + 1, optFull, optShort, opt[0] == '-'))))
        {
            s_ArgsMask ^= curArgBit;
            return true;
        }
    }
    return false;
}

//*** CmdLineParser_Done()
// This function notifies the parser that no more options are needed.
static void CmdLineParser_Done(const char* programName)
{
    char delim = ':';
    int  i;
    int  curArgBit;

    if(!CmdLineParser_More())
        return;

    fprintf(stderr,
            "Command line contains unknown option%s",
            s_ArgsMask & (s_ArgsMask - 1) ? "s" : "");
    for(i = 0, curArgBit = 1; i < s_Argc; ++i, curArgBit <<= 1)
    {
        if(s_ArgsMask & curArgBit)
        {
            fprintf(stderr, "%c %s", delim, s_Argv[i]);
            delim = ',';
        }
    }
    fprintf(stderr, "\n\n");
    Usage(programName);
}

//*** main()
// This is the main entry point for the simulator.
// It registers the interface and starts listening for clients
int main(int argc, char* argv[])
{
    bool manufacture  = false;
    int  PortNum      = DEFAULT_TPM_PORT;
    int  curr_arg_idx = 0;

    // Parse command line options

    if(CmdLineParser_Init(argc, argv, 4))
    {
        if(CmdLineParser_IsOptPresent("?", "?")
           || CmdLineParser_IsOptPresent("help", "h"))
        {
            Usage(argv[0]);
        }
        if(CmdLineParser_IsOptPresent("manufacture", "m"))
        {
            manufacture = true;
        }

        if(CmdLineParser_IsOptPresent("seed", "s"))
        {
            curr_arg_idx += 1;
            for(int i = curr_arg_idx; i < argc; ++i)
            {
                if((strcmp(argv[i], "--seed") == 0) || (strcmp(argv[i], "-s") == 0))
                {
                    char* nptr      = NULL;
                    DRBG_FIXED_SEED = (int)strtol(argv[i + 1], &nptr, 10);
                    if((DRBG_FIXED_SEED == 1) || (DRBG_FIXED_SEED == 2))
                    {
                        printf("\nDRBG_FIXED_SEED = %d\n", DRBG_FIXED_SEED);
                        s_ArgsMask ^= (i + 1);
                        curr_arg_idx += 1;

                        if(DRBG_FIXED_SEED == 2)
                        {
                            uint8_t init_entropy_seed_2_tmp[] = {
                                DRBG_TEST_INITIATE_ENTROPY_SEED_2_tmp};

                            memcpy(DRBG_NistTestVector_Entropy,
                                   init_entropy_seed_2_tmp,
                                   sizeof(init_entropy_seed_2_tmp));

                            printf("\nDRBG_NistTestVector_Entropy[0]=0x%x\n\n",
                                   DRBG_NistTestVector_Entropy[0]);
                        }
                        else if(DRBG_FIXED_SEED == 1)
                        {
                            uint8_t init_entropy_seed_1_tmp[] = {
                                DRBG_TEST_INITIATE_ENTROPY_SEED_1_tmp};

                            memcpy(DRBG_NistTestVector_Entropy,
                                   init_entropy_seed_1_tmp,
                                   sizeof(init_entropy_seed_1_tmp));

                            printf("\nDRBG_NistTestVector_Entropy[0]=0x%x\n\n",
                                   DRBG_NistTestVector_Entropy[0]);
                        }
                        continue;
                    }
                    else
                    {
                        fprintf(stderr,
                                "Invalid numeric option for random seed = %d (only "
                                "random seed = 1 and 2 is allowed!)\n\n",
                                DRBG_FIXED_SEED);
                        Usage(argv[0]);
                    }
                }
            }
        }
        else
        {
            printf("\nDRBG_FIXED_SEED = %d\n", DRBG_FIXED_SEED);

            uint8_t init_entropy_seed_0_tmp[] = {
                DRBG_TEST_INITIATE_ENTROPY_SEED_0_tmp};

            memcpy(DRBG_NistTestVector_Entropy,
                   init_entropy_seed_0_tmp,
                   sizeof(init_entropy_seed_0_tmp));

            printf("\nDRBG_NistTestVector_Entropy[0]=0x%x\n\n",
                   DRBG_NistTestVector_Entropy[0]);
        }

        if(CmdLineParser_More())
        {
            int i;
            for(i = curr_arg_idx; i < s_Argc; ++i)
            {
                char* nptr    = NULL;
                int   portNum = (int)strtol(s_Argv[i], &nptr, 0);
                if(s_Argv[i] != nptr)
                {
                    // A numeric option is found
                    if(!*nptr && portNum > 0 && portNum < 65535)
                    {
                        PortNum = portNum;
                        s_ArgsMask ^= 1 << i;
                        curr_arg_idx += 1;
                        break;
                    }
                    fprintf(stderr, "Invalid numeric option %s\n\n", s_Argv[i]);
                    Usage(argv[0]);
                }
            }
        }
        CmdLineParser_Done(argv[0]);
    }
    printf("LIBRARY_COMPATIBILITY_CHECK is %s\n",
           (LIBRARY_COMPATIBILITY_CHECK ? "ON" : "OFF"));
    // Enable NV memory
    _plat__NVEnable(NULL);

    if(manufacture || _plat__NVNeedsManufacture())
    {
        printf("Manufacturing NV state...\n");
        if(TPM_Manufacture(1) != 0)
        {
            // if the manufacture didn't work, then make sure that the NV file doesn't
            // survive. This prevents manufacturing failures from being ignored the
            // next time the code is run.
            _plat__NVDisable(1);
            exit(1);
        }
        // Coverage test - repeated manufacturing attempt
        if(TPM_Manufacture(0) != 1)
        {
            exit(2);
        }
        // Coverage test - re-manufacturing
        TPM_TearDown();
        if(TPM_Manufacture(1) != 0)
        {
            exit(3);
        }
    }
    // Disable NV memory
    _plat__NVDisable(0);

    StartTcpServer(PortNum);
    return EXIT_SUCCESS;
}
