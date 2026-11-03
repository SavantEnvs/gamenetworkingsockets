// Fuzzes the SNP frame decoder (reliable/unreliable segments, acks, lanes, stats) on an
// established in-process connection.  Input = the decrypted payload of a data packet.
#include "fuzz_common.h"
#define private public
#define protected public
#include "steamnetworkingsockets_connections.h"
#undef private
#undef protected

using namespace SteamNetworkingSocketsLib;

static HSteamNetConnection s_hConn[2] = { k_HSteamNetConnection_Invalid, k_HSteamNetConnection_Invalid };
static int64 s_nPktNum = 0;
static RecvPacketContext_t s_ctx;

static void DrainMessages( ISteamNetworkingSockets *pSockets, HSteamNetConnection h )
{
	SteamNetworkingMessage_t *msgs[ 32 ];
	for (;;)
	{
		int n = pSockets->ReceiveMessagesOnConnection( h, msgs, 32 );
		for ( int i = 0; i < n; ++i )
			msgs[i]->Release();
		if ( n < 32 )
			break;
	}
}

extern "C" int LLVMFuzzerTestOneInput( const uint8_t *data, size_t size )
{
	GnsFuzzInit();
	ISteamNetworkingSockets *pSockets = SteamNetworkingSockets();

	if ( size > (size_t)k_cbSteamNetworkingSocketsMaxPlaintextPayloadRecv )
		return -1;

	bool bAccepted = true;
	{
		SteamNetworkingGlobalLock lock( "fuzz_snp_data" );
		ConnectionScopeLock connLock;
		CSteamNetworkConnectionBase *pConn = GetConnectionByHandle( s_hConn[0], connLock );
		if ( !pConn || pConn->GetState() != k_ESteamNetworkingConnectionState_Connected )
		{
			connLock.Unlock();
			// A decode error (the interesting, expected outcome) kills the connection; make a fresh pair.
			if ( s_hConn[0] != k_HSteamNetConnection_Invalid ) pSockets->CloseConnection( s_hConn[0], 0, nullptr, false );
			if ( s_hConn[1] != k_HSteamNetConnection_Invalid ) pSockets->CloseConnection( s_hConn[1], 0, nullptr, false );
			s_hConn[0] = s_hConn[1] = k_HSteamNetConnection_Invalid;
			if ( !pSockets->CreateSocketPair( &s_hConn[0], &s_hConn[1], false, nullptr, nullptr ) )
				abort();
			pConn = GetConnectionByHandle( s_hConn[0], connLock );
			if ( !pConn )
				abort();
			s_nPktNum = 0;
		}

		s_ctx.m_usecNow = SteamNetworkingSockets_GetLocalTimestamp();
		s_ctx.m_pTransport = pConn->m_pTransport;
		s_ctx.m_idxMultiPath = 0;
		s_ctx.m_nPktNum = ++s_nPktNum;
		s_ctx.m_pPlainText = data;
		s_ctx.m_cbPlainText = (int)size;
		bAccepted = pConn->ProcessPlainTextDataChunk( 0, s_ctx );
	}

	if ( s_hConn[0] != k_HSteamNetConnection_Invalid )
		DrainMessages( pSockets, s_hConn[0] );
	if ( s_hConn[1] != k_HSteamNetConnection_Invalid )
		DrainMessages( pSockets, s_hConn[1] );
	return bAccepted ? 0 : -1;
}
