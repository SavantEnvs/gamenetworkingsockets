// Known-answer probe for the test oracle: prints "PROBE <name> OK" per passing check.
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <string>
#include <steam/steamnetworkingsockets.h>
#include <steam/isteamnetworkingutils.h>
#include <crypto.h>

static int g_nFail = 0, g_nPass = 0;

static void Check( const char *pszName, bool bOK )
{
	if ( bOK ) { ++g_nPass; printf( "PROBE %s OK\n", pszName ); }
	else { ++g_nFail; printf( "PROBE %s FAIL\n", pszName ); }
}

static std::string Hex( const uint8 *p, size_t cb )
{
	std::string s;
	char b[3];
	for ( size_t i = 0; i < cb; ++i ) { snprintf( b, sizeof(b), "%02x", p[i] ); s += b; }
	return s;
}

static bool IdentityRoundTrip( const char *pszIn, SteamNetworkingIdentity *pOut )
{
	if ( !pOut->ParseString( pszIn ) ) return false;
	char buf[ SteamNetworkingIdentity::k_cchMaxString ];
	pOut->ToString( buf, sizeof(buf) );
	return strcmp( buf, pszIn ) == 0;
}

int main()
{
	SHA256Digest_t d;
	CCrypto::GenerateSHA256Digest( "abc", 3, &d );
	Check( "sha256_abc", Hex( d, sizeof(d) ) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" );

	uint8 key[20]; memset( key, 0x0b, sizeof(key) );
	CCrypto::GenerateHMAC256( (const uint8 *)"Hi There", 8, key, sizeof(key), &d );
	Check( "hmac_sha256_rfc4231_1", Hex( d, sizeof(d) ) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" );

	SteamNetworkingIdentity id;
	Check( "identity_ip", IdentityRoundTrip( "ip:192.0.2.7:27015", &id ) && id.m_eType == k_ESteamNetworkingIdentityType_IPAddress && id.GetIPAddr()->m_port == 27015 );
	Check( "identity_str", IdentityRoundTrip( "str:hello", &id ) && id.m_eType == k_ESteamNetworkingIdentityType_GenericString && strcmp( id.GetGenericString(), "hello" ) == 0 );
	Check( "identity_steamid", IdentityRoundTrip( "steamid:76561197960287930", &id ) && id.GetSteamID64() == 76561197960287930ull );
	Check( "identity_reject", !id.ParseString( "steamid:abc" ) );

	SteamNetworkingIPAddr addr;
	Check( "ip_v6", addr.ParseString( "[::1]:99" ) && addr.m_port == 99 && addr.IsLocalHost() );
	Check( "ip_v4_default_port", addr.ParseString( "10.1.2.3" ) && addr.m_port == 0 && !addr.IsIPv6AllZeros() );
	Check( "ip_reject", !addr.ParseString( "not-an-ip" ) );

	SteamDatagramErrMsg err;
	if ( !GameNetworkingSockets_Init( nullptr, err ) )
	{
		printf( "init failed: %s\n", err );
		return 2;
	}
	ISteamNetworkingSockets *pSockets = SteamNetworkingSockets();
	HSteamNetConnection a, b;
	bool bPair = pSockets->CreateSocketPair( &a, &b, false, nullptr, nullptr );
	Check( "pipe_create", bPair );
	if ( bPair )
	{
		const char msg[] = "known-answer payload 0123456789";
		EResult r = pSockets->SendMessageToConnection( a, msg, sizeof(msg), k_nSteamNetworkingSend_Reliable | k_nSteamNetworkingSend_NoNagle, nullptr );
		Check( "pipe_send", r == k_EResultOK );
		SteamNetworkingMessage_t *pMsg[4];
		int n = 0;
		for ( int i = 0; i < 300 && n == 0; ++i )
		{
			n = pSockets->ReceiveMessagesOnConnection( b, pMsg, 4 );
			if ( n == 0 ) usleep( 10000 );
		}
		bool bMatch = n == 1 && pMsg[0]->m_cbSize == (int)sizeof(msg) && memcmp( pMsg[0]->m_pData, msg, sizeof(msg) ) == 0;
		Check( "pipe_payload_roundtrip", bMatch );
		for ( int i = 0; i < n; ++i ) pMsg[i]->Release();
		pSockets->CloseConnection( a, 0, nullptr, false );
		pSockets->CloseConnection( b, 0, nullptr, false );
	}
	GameNetworkingSockets_Kill();

	printf( "PROBE SUMMARY pass=%d fail=%d\n", g_nPass, g_nFail );
	return g_nFail ? 1 : 0;
}
