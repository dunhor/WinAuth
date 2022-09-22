#pragma once
#include <TokenRequestResult.g.h>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct TokenRequestResult : TokenRequestResultT<TokenRequestResult>
    {
        oauth::TokenResponse Response();
        oauth::TokenFailure Failure();

    private:

        oauth::TokenResponse m_response;
        oauth::TokenFailure m_failure;
    };
}
