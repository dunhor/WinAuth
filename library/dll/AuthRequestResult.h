#pragma once
#include <AuthRequestResult.g.h>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct AuthRequestResult : AuthRequestResultT<AuthRequestResult>
    {
        winrt::Microsoft::Security::Authentication::OAuth::AuthResponse Response();
        winrt::Microsoft::Security::Authentication::OAuth::AuthFailure Failure();
    };
}
