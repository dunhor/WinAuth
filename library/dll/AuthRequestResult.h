#pragma once
#include <AuthRequestResult.g.h>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct AuthRequestResult : AuthRequestResultT<AuthRequestResult>
    {
        foundation::Uri ResponseUri();
        oauth::AuthResponse Response();
        oauth::AuthFailure Failure();

    private:

        foundation::Uri m_responseUri;
        oauth::AuthResponse m_response{ nullptr };
        oauth::AuthFailure m_failure{ nullptr };
    };
}
