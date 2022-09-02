#pragma once
#include <AuthResponse.g.h>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct AuthResponse : AuthResponseT<AuthResponse>
    {
        winrt::Windows::Foundation::Uri ResponseUri();
        winrt::hstring TokenType();
        winrt::hstring Code();
        winrt::hstring AccessToken();
        winrt::hstring State();
        winrt::hstring ExpiresIn();
        winrt::hstring Scope();
        winrt::Windows::Foundation::Collections::IMap<winrt::hstring, winrt::hstring> AdditionalParams();
    };
}
