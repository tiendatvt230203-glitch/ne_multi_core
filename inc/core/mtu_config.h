#ifndef MTU_CONFIG_H
#define MTU_CONFIG_H

#define NE_MTU_PROFILE_1500 1500
#define NE_MTU_PROFILE_9000 9000

#ifndef NE_MTU_PROFILE
#define NE_MTU_PROFILE NE_MTU_PROFILE_9000
#endif

#if NE_MTU_PROFILE == NE_MTU_PROFILE_1500
#define NE_FRAME            2048u
#define NE_N_FRAMES         131072u
#define FRAG_MTU            1500u
#define FRAG_TABLE_SIZE     4096u
#elif NE_MTU_PROFILE == NE_MTU_PROFILE_9000
#define NE_FRAME            16384u
#define NE_N_FRAMES         8192u
#define FRAG_MTU            9000u
#define FRAG_TABLE_SIZE     64u
#else
#error "Unsupported NE_MTU_PROFILE"
#endif

#define FRAG_REASSEMBLY_MAX NE_FRAME

#endif
