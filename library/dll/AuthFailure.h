#pragma once
#include <AuthFailure.g.h>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct AuthFailure : AuthFailureT<AuthFailure>
    {
        winrt::Windows::Foundation::Uri ResponseUri();
    };
}
