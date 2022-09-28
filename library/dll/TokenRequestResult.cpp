#include "TokenRequestResult.h"
#include "pch.h"
#include <TokenRequestResult.g.cpp>

#include "TokenFailure.h"
#include "TokenResponse.h"

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Data::Json;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;
using namespace winrt::Windows::Web::Http;

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    TokenRequestResult::TokenRequestResult(HttpResponseMessage responseMessage, const JsonObject& jsonObj) :
        m_responseMessage(std::move(responseMessage))
    {
        // NOTE: Every successful response should have a "token" and "token_type", and every failure should have
        // "error". If none of these are present, we have to pick one or the other (or throw). We look for the presence
        // of "error" here since that is the more "general" code path
        if (jsonObj.HasKey(L"error"))
        {
            m_failure = winrt::make<TokenFailure>(jsonObj);
        }
        else
        {
            m_response = winrt::make<TokenResponse>(jsonObj);
        }
    }

    HttpResponseMessage TokenRequestResult::ResponseMessage()
    {
        return m_responseMessage;
    }

    oauth::TokenResponse TokenRequestResult::Response()
    {
        return m_response;
    }

    oauth::TokenFailure TokenRequestResult::Failure()
    {
        return m_failure;
    }
}
