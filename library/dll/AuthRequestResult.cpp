#include "pch.h"

#include "AuthRequestResult.h"
#include <AuthRequestResult.g.cpp>

#include "AuthFailure.h"
#include "AuthResponse.h"

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    AuthRequestResult::AuthRequestResult(AuthRequestParams* params, const Uri& responseUri) : m_responseUri(responseUri)
    {
        // We first need to figure out if this is a success or failure response
        bool isError = false;
        bool isSuccess = false;
        for (auto&& entry : m_responseUri.QueryParsed())
        {
            auto name = entry.Name();
            if ((name == L"code") || (name == L"access_token"))
            {
                isSuccess = true;
                break;
            }
            else if (name == L"error")
            {
                isError = true;
                break;
            }
        }

        if (!isError && !isSuccess)
        {
            // TODO: May also need to check the fragment
        }

        // If we don't recognize the response as an error, interpret it as success. The application may be using an
        // extension that we don't recognize
        if (isError)
        {
            m_failure = winrt::make<AuthFailure>(m_responseUri);
        }
        else
        {
            m_response = winrt::make<AuthResponse>(params, m_responseUri);
        }
    }

    Uri AuthRequestResult::ResponseUri()
    {
        return m_responseUri;
    }

    oauth::AuthResponse AuthRequestResult::Response()
    {
        return m_response;
    }

    oauth::AuthFailure AuthRequestResult::Failure()
    {
        return m_failure;
    }
}
