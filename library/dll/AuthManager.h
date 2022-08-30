#pragma once
#include <AuthManager.g.h>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct AuthManager
    {
        static void InitiateAuthRequest(const winrt::Windows::Foundation::Uri& authEndpoint,
            const winrt::Microsoft::Security::Authentication::OAuth::AuthRequestParams& params);
        static void InitiateAuthRequest(const winrt::Windows::Foundation::Uri& authEndpoint,
            const winrt::Microsoft::Security::Authentication::OAuth::AuthRequestParams& params,
            const hstring& clientSecret);
    };
}

namespace winrt::Microsoft::Security::Authentication::OAuth::factory_implementation
{
    struct AuthManager : AuthManagerT<AuthManager, implementation::AuthManager>
    {
    };
}
