// Shared helpers for the GameNetworkingSockets fuzz harnesses.
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <algorithm>
#include <functional>
#include <steam/steamnetworkingsockets.h>
#include <steam/isteamnetworkingutils.h>

// Starts the library once (self-signed cert, background service thread) and silences its debug spew.
static inline void GnsFuzzInit()
{
	static bool s_bInit = false;
	if ( s_bInit )
		return;
	s_bInit = true;
	SteamNetworkingErrMsg errMsg;
	if ( !GameNetworkingSockets_Init( nullptr, errMsg ) )
	{
		fprintf( stderr, "GameNetworkingSockets_Init failed: %s\n", errMsg );
		abort();
	}
	SteamNetworkingUtils()->SetDebugOutputFunction( k_ESteamNetworkingSocketsDebugOutputType_None,
		[]( ESteamNetworkingSocketsDebugOutputType, const char * ) {} );
}
