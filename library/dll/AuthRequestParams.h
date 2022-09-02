#pragma once
#include <AuthRequestParams.g.h>

#include <atomic>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct AuthRequestParams : AuthRequestParamsT<AuthRequestParams>
    {
        AuthRequestParams(const winrt::hstring& clientId, const winrt::hstring& responseType);
        AuthRequestParams(const winrt::hstring& clientId, const winrt::hstring& responseType,
            const winrt::Windows::Foundation::Uri& redirectUri);

        // Interface functions
        winrt::hstring ResponseType();
        void ResponseType(const winrt::hstring& value);
        winrt::hstring ClientId();
        void ClientId(const winrt::hstring& value);
        winrt::Windows::Foundation::Uri RedirectUri();
        void RedirectUri(const winrt::Windows::Foundation::Uri& value);
        winrt::hstring Scope();
        void Scope(const winrt::hstring& value);
        winrt::hstring State();
        void State(const winrt::hstring& value);
        winrt::hstring CodeVerifier();
        void CodeVerifier(const winrt::hstring& value);
        winrt::Microsoft::Security::Authentication::OAuth::CodeChallengeMethodKind CodeChallengeMethod();
        void CodeChallengeMethod(winrt::Microsoft::Security::Authentication::OAuth::CodeChallengeMethodKind value);
        winrt::Windows::Foundation::Collections::IMap<hstring, winrt::hstring> AdditionalParams();
        void AdditionalParams(const winrt::Windows::Foundation::Collections::IMap<hstring, winrt::hstring>& value);

        // Implementation functions
        void finalize();
        std::wstring query_string();

    private:
        void check_not_finalized()
        {
            // NOTE: Lock should be held when calling
            if (m_finalized)
            {
                throw winrt::hresult_illegal_method_call(L"AuthRequestParams object cannot be modified after being used to initiate a request");
            }
        }

        std::shared_mutex m_mutex;
        bool m_finalized = false;
        winrt::hstring m_responseType = L"code";
        winrt::hstring m_clientId;
        winrt::Windows::Foundation::Uri m_redirectUri{ nullptr };
        winrt::hstring m_scope;
        winrt::hstring m_state;
        winrt::hstring m_codeVerifier;
        winrt::Microsoft::Security::Authentication::OAuth::CodeChallengeMethodKind m_codeChallengeMethod =
            winrt::Microsoft::Security::Authentication::OAuth::CodeChallengeMethodKind::S256;
        winrt::Windows::Foundation::Collections::IMap<winrt::hstring, winrt::hstring> m_additionalParams =
            winrt::multi_threaded_map<winrt::hstring, winrt::hstring>();
    };
}

namespace winrt::Microsoft::Security::Authentication::OAuth::factory_implementation
{
    struct AuthRequestParams : AuthRequestParamsT<AuthRequestParams, implementation::AuthRequestParams>
    {
    };
}
