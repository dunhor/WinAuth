#pragma once
#include <AuthManager.g.h>

#include "AuthRequestAsyncOperation.h"

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct AuthManager;
}

namespace winrt::Microsoft::Security::Authentication::OAuth::factory_implementation
{
    struct AuthRequestState
    {
        winrt::hstring state;
        winrt::com_ptr<AuthRequestAsyncOperation> async_op;
    };

    struct AuthManager : AuthManagerT<AuthManager, implementation::AuthManager, winrt::static_lifetime>
    {
        foundation::IAsyncOperation<oauth::AuthRequestResult> InitiateAuthRequestAsync(foundation::Uri authEndpoint,
            oauth::AuthRequestParams params);
        bool CompleteAuthRequest(const foundation::Uri& responseUri);
        foundation::IAsyncOperation<oauth::TokenRequestResult> RequestTokenAsync(foundation::Uri tokenEndpoint,
            oauth::TokenRequestParams params);

        // Private functions
        std::wstring generate_unique_state();

    private:
        std::shared_mutex m_mutex;
        std::vector<AuthRequestState> m_pendingAuthRequests;
    };
}

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct AuthManager
    {
        static foundation::IAsyncOperation<oauth::AuthRequestResult> InitiateAuthRequestAsync(
            foundation::Uri authEndpoint, oauth::AuthRequestParams params)
        {
            return winrt::make_self<factory_implementation::AuthManager>()->InitiateAuthRequestAsync(authEndpoint,
                params);
        }

        static bool CompleteAuthRequest(const foundation::Uri& responseUri)
        {
            return winrt::make_self<factory_implementation::AuthManager>()->CompleteAuthRequest(responseUri);
        }

        static foundation::IAsyncOperation<oauth::TokenRequestResult> RequestTokenAsync(foundation::Uri tokenEndpoint,
            oauth::TokenRequestParams params)
        {
            return winrt::make_self<factory_implementation::AuthManager>()->RequestTokenAsync(tokenEndpoint, params);
        }
    };
}
