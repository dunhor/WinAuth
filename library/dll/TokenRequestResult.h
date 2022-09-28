#pragma once
#include <TokenRequestResult.g.h>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct TokenRequestResult : TokenRequestResultT<TokenRequestResult>
    {
        TokenRequestResult(http::HttpResponseMessage responseMessage, const json::JsonObject& obj);

        http::HttpResponseMessage ResponseMessage();
        oauth::TokenResponse Response();
        oauth::TokenFailure Failure();

    private:
        http::HttpResponseMessage m_responseMessage;
        oauth::TokenResponse m_response{ nullptr };
        oauth::TokenFailure m_failure{ nullptr };
    };
}
