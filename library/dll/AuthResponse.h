#pragma once
#include <AuthResponse.g.h>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct AuthResponse : AuthResponseT<AuthResponse>
    {
        AuthResponse(const foundation::Uri& responseUri);

        winrt::hstring State();
        winrt::hstring Code();
        winrt::hstring AccessToken();
        winrt::hstring TokenType();
        winrt::hstring ExpiresIn();
        winrt::hstring Scope();
        collections::IMapView<winrt::hstring, winrt::hstring> AdditionalParams();

    private:

        winrt::hstring m_state;
        winrt::hstring m_code;
        winrt::hstring m_accessToken;
        winrt::hstring m_tokenType;
        winrt::hstring m_expiresIn;
        winrt::hstring m_scope;
        collections::IMapView<winrt::hstring, winrt::hstring> m_additionalParams;
    };
}
