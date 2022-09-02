#include "pch.h"
#include "AuthManager.h"
#include <AuthManager.g.cpp>

#include "AuthRequestParams.h"

#include <random> // TODO: Should probably use Windows APIs directly

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;
using namespace winrt::Windows::System;

namespace winrt::Microsoft::Security::Authentication::OAuth::factory_implementation
{
    IAsyncOperation<AuthRequestResult> AuthManager::InitiateAuthRequestAsync(const Uri& authEndpoint,
        const OAuth::AuthRequestParams& params)
    {
        return InitiateAuthRequestAsync(authEndpoint, params, winrt::hstring{});
    }

    IAsyncOperation<AuthRequestResult> AuthManager::InitiateAuthRequestAsync(const Uri& authEndpoint,
        const OAuth::AuthRequestParams& params, const winrt::hstring& clientSecret)
    {
        winrt::com_ptr<AuthRequestAsyncOperation> result{ nullptr };
        auto paramsImpl = winrt::get_self<implementation::AuthRequestParams>(params);

        {
            std::lock_guard guard{ m_mutex };
            paramsImpl->finalize();

            result = winrt::make_self<AuthRequestAsyncOperation>();
            m_pendingAuthRequests.push_back(AuthRequestState{ paramsImpl->State(), result });
        }

        try
        {
            auto query = paramsImpl->query_string();
            if (!clientSecret.empty())
            {
                query += L"&client_secret=";
                query += Uri::EscapeComponent(clientSecret);
            }

            // TODO: Should probably not just fire and forget
            Launcher::LaunchUriAsync(authEndpoint.CombineUri(query));
        }
        catch (...)
        {
            std::lock_guard guard{ m_mutex };
            m_pendingAuthRequests.erase(std::find_if(m_pendingAuthRequests.rbegin(), m_pendingAuthRequests.rend(), [&](auto&& request) {
                return request.state == paramsImpl->State();
            }).base());
        }

        return *result;
    }

    bool AuthManager::CompleteAuthRequest(const Uri& responseUri)
    {
        throw hresult_not_implemented(); // TODO
    }

    std::wstring AuthManager::generate_unique_state()
    {
        std::wstring result;
        result.reserve(32);

        // TODO: We should switch to a more Windows-ey way of generating random things
        std::random_device eng;
        std::uniform_int_distribution dist(0, 26 * 2 + 10 - 1); // Upper/lowercase and
        while (true)
        {
            result.clear();
            for (int i = 0; i < 32; ++i)
            {
                auto val = dist(eng);
                if (val < 26)
                {
                    result.push_back(static_cast<char>('A' + val));
                }
                else if (val -= 26; val < 26)
                {
                    result.push_back(static_cast<char>('a' + val));
                }
                else
                {
                    val -= 26;
                    assert(val < 10);
                    result.push_back(static_cast<char>('0' + val));
                }
            }

            // Ensure that the state string is unique
            auto itr = std::find_if(m_pendingAuthRequests.begin(), m_pendingAuthRequests.end(), [&](auto&& request) {
                return request.state == result;
            });
            if (itr == m_pendingAuthRequests.end())
            {
                return result;
            }
        }
    }
}
