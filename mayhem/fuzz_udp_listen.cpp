// Fuzzes the pre-authentication UDP entry point of a listen socket: every datagram that arrives
// from an address with no existing connection (stray data, ChallengeRequest, ConnectRequest,
// ConnectionClosed, junk).  ConnectRequest bodies get a valid challenge patched in so the fuzzer
// can reach the connection-creation and certificate/crypto-handshake code behind the anti-spoof check.
#include <unistd.h>
#include "fuzz_common.h"
#define private public
#define protected public
#include "csteamnetworkingsockets.h"
#include "steamnetworkingsockets_udp.h"
#undef private
#undef protected

using namespace SteamNetworkingSocketsLib;

static HSteamListenSocket s_hListen = k_HSteamListenSocket_Invalid;
static CSteamNetworkListenSocketDirectUDP *s_pListen = nullptr;
static uint64 s_nIter = 0;

static void CreateListen()
{
	ISteamNetworkingSockets *pSockets = SteamNetworkingSockets();
	if ( s_hListen != k_HSteamListenSocket_Invalid )
		pSockets->CloseListenSocket( s_hListen );
	SteamNetworkingConfigValue_t opt;
	opt.SetInt32( k_ESteamNetworkingConfig_IP_AllowWithoutAuth, 2 );
	// The listen socket needs an explicit port; scan for a free one so parallel instances coexist.
	static uint16 s_nPort = 20000 + (uint16)( getpid() % 30000 );
	s_hListen = k_HSteamListenSocket_Invalid;
	for ( int i = 0; i < 200 && s_hListen == k_HSteamListenSocket_Invalid; ++i )
	{
		SteamNetworkingIPAddr addr;
		addr.Clear();
		addr.SetIPv4( 0x7f000001, s_nPort );
		s_hListen = pSockets->CreateListenSocketIP( addr, 1, &opt );
		if ( s_hListen == k_HSteamListenSocket_Invalid )
			s_nPort = s_nPort >= 59999 ? 20000 : s_nPort + 1;
	}
	if ( s_hListen == k_HSteamListenSocket_Invalid )
		abort();

	SteamNetworkingGlobalLock lock( "fuzz_udp_listen" );
	int idx = s_hListen & 0xffff;
	if ( !g_mapListenSockets.IsValidIndex( idx ) || g_mapListenSockets[ idx ]->m_hListenSocketSelf != s_hListen )
		abort();
	CSteamNetworkListenSocketBase *pBase = g_mapListenSockets[ idx ];
	s_pListen = static_cast<CSteamNetworkListenSocketDirectUDP *>( pBase );
}

extern "C" int LLVMFuzzerTestOneInput( const uint8_t *data, size_t size )
{
	GnsFuzzInit();
	if ( size > 4096 )
		return -1;

	// Start over regularly so connections created by accepted ConnectRequests don't pile up
	if ( !s_pListen || ( ++s_nIter & 0xff ) == 0 )
		CreateListen();

	SteamNetworkingSockets()->RunCallbacks();

	SteamNetworkingGlobalLock lock( "fuzz_udp_listen" );
	const SteamNetworkingMicroseconds usecNow = SteamNetworkingSockets_GetLocalTimestamp();

	netadr_t adrFrom;
	adrFrom.SetIPv4( 0x7f000001 ); adrFrom.SetPort( 9 ); // UDP discard port: replies go nowhere

	std::string patched;
	const uint8_t *pPkt = data;
	int cbPkt = (int)size;
	if ( size > 1 && data[0] == k_ESteamNetworkingUDPMsg_ConnectRequest )
	{
		CMsgSteamSockets_UDP_ConnectRequest msg;
		if ( msg.ParseFromArray( data + 1, (int)size - 1 ) )
		{
			uint16 nTime = uint16( usecNow >> 20 );
			msg.set_challenge( s_pListen->GenerateChallenge( nTime, adrFrom ) );
			patched.push_back( (char)k_ESteamNetworkingUDPMsg_ConnectRequest );
			msg.AppendToString( &patched );
			pPkt = (const uint8_t *)patched.data();
			cbPkt = (int)patched.size();
		}
	}

	RecvPktInfo_t info;
	info.m_pPkt = pPkt;
	info.m_cbPkt = cbPkt;
	info.m_usecNow = usecNow;
	info.m_adrFrom = adrFrom;
	info.m_bQueuedForOutOfOrder = false;
	info.m_tos = 0;
	info.m_pSock = nullptr;
	CSteamNetworkListenSocketDirectUDP::ReceivedFromUnknownHost( info, s_pListen );
	return 0;
}
