// Fuzzes the stateless text/binary parsers: identity strings, IP address strings,
// PEM and base64 certificates, binary signed certificates and legacy binary identities.
// The first input byte selects the parser; the rest is its payload.
#include "fuzz_common.h"
#include "steamnetworkingsockets_internal.h"

using namespace SteamNetworkingSocketsLib;

extern "C" int LLVMFuzzerTestOneInput( const uint8_t *data, size_t size )
{
	GnsFuzzInit();
	if ( size < 1 || size > 16384 )
		return -1;
	const int nMode = data[0] % 6;
	const uint8_t *pPayload = data + 1;
	const size_t cbPayload = size - 1;
	const std::string sPayload( (const char *)pPayload, cbPayload ); // NUL-terminated copy for the string parsers
	SteamNetworkingErrMsg errMsg;
	bool bParsed = false;

	switch ( nMode )
	{
		case 0:
		{
			SteamNetworkingIdentity identity;
			if ( identity.ParseString( sPayload.c_str() ) )
			{
				bParsed = true;
				SteamNetworkingIdentityRender rendered( identity );
				SteamNetworkingIdentity again;
				again.ParseString( rendered.c_str() );
			}
			break;
		}
		case 1:
		{
			SteamNetworkingIPAddr addr;
			if ( addr.ParseString( sPayload.c_str() ) )
			{
				bParsed = true;
				char buf[ SteamNetworkingIPAddr::k_cchMaxString ];
				addr.ToString( buf, sizeof(buf), true );
				SteamNetworkingIPAddr again;
				again.ParseString( buf );
			}
			break;
		}
		case 2:
		{
			CMsgSteamDatagramCertificateSigned cert;
			if ( ParseCertFromPEM( pPayload, cbPayload, cert, errMsg ) )
			{
				bParsed = true;
				SteamNetworkingIdentity identity;
				SteamNetworkingIdentityFromSignedCert( identity, cert, errMsg );
			}
			break;
		}
		case 3:
		{
			CMsgSteamDatagramCertificateSigned cert;
			bParsed = ParseCertFromBase64( sPayload.c_str(), cbPayload, cert, errMsg );
			break;
		}
		case 4:
		{
			bParsed = SteamNetworkingSockets()->SetCertificate( pPayload, (int)cbPayload, errMsg );
			break;
		}
		case 5:
		{
			SteamNetworkingIdentity identity;
			bParsed = BSteamNetworkingIdentityFromLegacyBinaryProtobuf( identity, std::string( (const char *)pPayload, cbPayload ), errMsg );
			break;
		}
	}
	return bParsed ? 0 : -1;
}
