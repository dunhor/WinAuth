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
        winrt::Windows::Foundation::IAsyncOperation<
            winrt::Microsoft::Security::Authentication::OAuth::AuthRequestResult>
        InitiateAuthRequestAsync(const winrt::Windows::Foundation::Uri& authEndpoint,
            const winrt::Microsoft::Security::Authentication::OAuth::AuthRequestParams& params);
        winrt::Windows::Foundation::IAsyncOperation<
            winrt::Microsoft::Security::Authentication::OAuth::AuthRequestResult>
        InitiateAuthRequestAsync(const winrt::Windows::Foundation::Uri& authEndpoint,
            const winrt::Microsoft::Security::Authentication::OAuth::AuthRequestParams& params,
            const winrt::hstring& clientSecret);
        bool CompleteAuthRequest(const winrt::Windows::Foundation::Uri& responseUri);

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
        static winrt::Windows::Foundation::IAsyncOperation<
            winrt::Microsoft::Security::Authentication::OAuth::AuthRequestResult>
        InitiateAuthRequestAsync(const winrt::Windows::Foundation::Uri& authEndpoint,
            const winrt::Microsoft::Security::Authentication::OAuth::AuthRequestParams& params)
        {
            return winrt::make_self<factory_implementation::AuthManager>()->InitiateAuthRequestAsync(authEndpoint,
                params);
        }

        static winrt::Windows::Foundation::IAsyncOperation<
            winrt::Microsoft::Security::Authentication::OAuth::AuthRequestResult>
        InitiateAuthRequestAsync(const winrt::Windows::Foundation::Uri& authEndpoint,
            const winrt::Microsoft::Security::Authentication::OAuth::AuthRequestParams& params,
            const winrt::hstring& clientSecret)
        {
            return winrt::make_self<factory_implementation::AuthManager>()->InitiateAuthRequestAsync(authEndpoint,
                params, clientSecret);
        }

        static bool CompleteAuthRequest(const winrt::Windows::Foundation::Uri& responseUri)
        {
            return winrt::make_self<factory_implementation::AuthManager>()->CompleteAuthRequest(responseUri);
        }
    };
}
