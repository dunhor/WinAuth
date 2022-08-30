#pragma once

#include <AuthRequestParams.g.h>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct AuthRequestParams : AuthRequestParamsT<AuthRequestParams>
    {
        AuthRequestParams(hstring const& clientId, hstring const& responseType);
        AuthRequestParams(hstring const& clientId, hstring const& responseType,
            winrt::Windows::Foundation::Uri const& redirectUri);

        hstring ResponseType();
        void ResponseType(hstring const& value);
        hstring ClientId();
        void ClientId(hstring const& value);
        winrt::Windows::Foundation::Uri RedirectUri();
        void RedirectUri(winrt::Windows::Foundation::Uri const& value);
        hstring Scope();
        void Scope(hstring const& value);
        hstring State();
        void State(hstring const& value);
        hstring CodeChallenge();
        void CodeChallenge(hstring const& value);
        winrt::Microsoft::Security::Authentication::OAuth::CodeChallengeMethodKind CodeChallengeMethod();
        void CodeChallengeMethod(
            winrt::Microsoft::Security::Authentication::OAuth::CodeChallengeMethodKind const& value);
        winrt::Windows::Foundation::Collections::IMap<hstring, hstring> AdditionalParams();
        void AdditionalParams(winrt::Windows::Foundation::Collections::IMap<hstring, hstring> const& value);

    private:
        winrt::hstring m_responseType;
        winrt::hstring m_clientId;
        winrt::Windows::Foundation::Uri m_redirectUri{ nullptr };
        winrt::hstring m_scope;
        winrt::hstring m_state;
        winrt::hstring m_codeChallenge;
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
