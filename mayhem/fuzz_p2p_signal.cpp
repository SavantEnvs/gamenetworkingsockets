// Fuzzes the P2P signaling entry point (ReceivedP2PCustomSignal): the rendezvous protobuf, peer
// identity parsing, connect-request / connect-OK handling including certificate and crypt-info
// validation, and the per-connection reliable signal stream.
//
// The harness keeps one outgoing P2P connection and one P2P listen socket alive so that signals
// can target an existing connection.  Sentinel values in the input are rewritten to the live values:
// to_connection_id==1 becomes the outgoing connection's id, from_identity=="peer" becomes the identity
// that connection was opened to.
#include "fuzz_common.h"
#include <steam/steamnetworkingcustomsignaling.h>
#include "steamnetworkingsockets_messages.pb.h"

static const char k_szPeer[] = "str:fuzzpeer";

static std::atomic<uint32_t> s_nOutgoingConnId( 0 );

struct RecordingSignaling : ISteamNetworkingConnectionSignaling
{
	bool SendSignal( HSteamNetConnection, const SteamNetConnectionInfo_t &, const void *pMsg, int cbMsg ) override
	{
		CMsgSteamNetworkingP2PRendezvous msg;
		if ( msg.ParseFromArray( pMsg, cbMsg ) && msg.has_from_connection_id() )
			s_nOutgoingConnId = msg.from_connection_id();
		return true;
	}
	void Release() override {}
};

struct DiscardingSignaling : ISteamNetworkingConnectionSignaling
{
	bool SendSignal( HSteamNetConnection, const SteamNetConnectionInfo_t &, const void *, int ) override { return true; }
	void Release() override {}
};

static RecordingSignaling s_outSignaling;
static DiscardingSignaling s_inSignaling;
static std::vector<HSteamNetConnection> s_vecIncoming;

struct RecvContext : ISteamNetworkingSignalingRecvContext
{
	ISteamNetworkingConnectionSignaling *OnConnectRequest( HSteamNetConnection hConn, const SteamNetworkingIdentity &, int ) override
	{
		s_vecIncoming.push_back( hConn );
		SteamNetworkingSockets()->AcceptConnection( hConn );
		return &s_inSignaling;
	}
	void SendRejectionSignal( const SteamNetworkingIdentity &, const void *, int ) override {}
};

static HSteamListenSocket s_hListen = k_HSteamListenSocket_Invalid;
static HSteamNetConnection s_hOutgoing = k_HSteamNetConnection_Invalid;
static uint64_t s_nIter = 0;

static void EnsureConnections( ISteamNetworkingSockets *pSockets )
{
	if ( s_hListen == k_HSteamListenSocket_Invalid )
		s_hListen = pSockets->CreateListenSocketP2P( 0, 0, nullptr );

	if ( ( ++s_nIter & 0x7f ) == 0 )
	{
		for ( HSteamNetConnection h : s_vecIncoming )
			pSockets->CloseConnection( h, 0, nullptr, false );
		s_vecIncoming.clear();
	}

	bool bAlive = false;
	if ( s_hOutgoing != k_HSteamNetConnection_Invalid )
	{
		SteamNetConnectionInfo_t info;
		if ( pSockets->GetConnectionInfo( s_hOutgoing, &info ) )
		{
			bAlive = info.m_eState == k_ESteamNetworkingConnectionState_Connecting
				|| info.m_eState == k_ESteamNetworkingConnectionState_FindingRoute
				|| info.m_eState == k_ESteamNetworkingConnectionState_Connected;
		}
		if ( !bAlive )
			pSockets->CloseConnection( s_hOutgoing, 0, nullptr, false );
	}
	if ( !bAlive )
	{
		SteamNetworkingIdentity peer;
		peer.ParseString( k_szPeer );
		s_nOutgoingConnId = 0;
		s_hOutgoing = pSockets->ConnectP2PCustomSignaling( &s_outSignaling, &peer, 0, 0, nullptr );
	}
}

extern "C" int LLVMFuzzerTestOneInput( const uint8_t *data, size_t size )
{
	GnsFuzzInit();
	if ( size > 8192 )
		return -1;
	ISteamNetworkingSockets *pSockets = SteamNetworkingSockets();
	EnsureConnections( pSockets );
	pSockets->RunCallbacks();

	std::string patched;
	const void *pMsg = data;
	int cbMsg = (int)size;
	CMsgSteamNetworkingP2PRendezvous msg;
	if ( msg.ParseFromArray( data, (int)size ) )
	{
		bool bChanged = false;
		if ( msg.has_to_connection_id() && msg.to_connection_id() == 1 && s_nOutgoingConnId != 0 )
		{
			msg.set_to_connection_id( s_nOutgoingConnId );
			bChanged = true;
		}
		if ( msg.from_identity() == "peer" )
		{
			msg.set_from_identity( k_szPeer );
			bChanged = true;
		}
		if ( bChanged && msg.SerializeToString( &patched ) )
		{
			pMsg = patched.data();
			cbMsg = (int)patched.size();
		}
	}

	RecvContext ctx;
	return pSockets->ReceivedP2PCustomSignal( pMsg, cbMsg, &ctx ) ? 0 : -1;
}
