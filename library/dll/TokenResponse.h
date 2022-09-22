#pragma once
#include <TokenResponse.g.h>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct TokenResponse : TokenResponseT<TokenResponse>
    {
        winrt::hstring AccessToken();
        winrt::hstring TokenType();
        double ExpiresIn();
        winrt::hstring RefreshToken();
        winrt::hstring Scope();
        collections::IMapView<winrt::hstring, json::IJsonValue> AdditionalParams();

    private:

        winrt::hstring m_accessToken;
        winrt::hstring m_tokenType;
        double m_expiresIn;
        winrt::hstring m_refreshToken;
        winrt::hstring m_scope;
        collections::IMapView<winrt::hstring, json::IJsonValue> m_additionalParams;
    };
}
