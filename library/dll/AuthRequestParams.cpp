#include "pch.h"

#include "AuthRequestParams.h"
#include <AuthRequestParams.g.cpp>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    AuthRequestParams::AuthRequestParams(hstring const& clientId, hstring const& responseType)
    {
        throw hresult_not_implemented();
    }

    AuthRequestParams::AuthRequestParams(hstring const& clientId, hstring const& responseType,
        winrt::Windows::Foundation::Uri const& redirectUri)
    {
        throw hresult_not_implemented();
    }

    hstring AuthRequestParams::ResponseType()
    {
        return m_responseType;
    }

    void AuthRequestParams::ResponseType(hstring const& value)
    {
        m_responseType = value;
    }

    hstring AuthRequestParams::ClientId()
    {
        return m_clientId;
    }

    void AuthRequestParams::ClientId(hstring const& value)
    {
        m_clientId = value;
    }

    winrt::Windows::Foundation::Uri AuthRequestParams::RedirectUri()
    {
        return m_redirectUri;
    }

    void AuthRequestParams::RedirectUri(winrt::Windows::Foundation::Uri const& value)
    {
        m_redirectUri = value;
    }

    hstring AuthRequestParams::Scope()
    {
        return m_scope;
    }

    void AuthRequestParams::Scope(hstring const& value)
    {
        m_scope = value;
    }

    hstring AuthRequestParams::State()
    {
        return m_state;
    }

    void AuthRequestParams::State(hstring const& value)
    {
        m_state = value;
    }

    hstring AuthRequestParams::CodeChallenge()
    {
        return m_codeChallenge;
    }

    void AuthRequestParams::CodeChallenge(hstring const& value)
    {
        m_codeChallenge = value;
    }

    winrt::Microsoft::Security::Authentication::OAuth::CodeChallengeMethodKind AuthRequestParams::CodeChallengeMethod()
    {
        return m_codeChallengeMethod;
    }

    void AuthRequestParams::CodeChallengeMethod(
        winrt::Microsoft::Security::Authentication::OAuth::CodeChallengeMethodKind const& value)
    {
        m_codeChallengeMethod = value;
    }

    winrt::Windows::Foundation::Collections::IMap<hstring, hstring> AuthRequestParams::AdditionalParams()
    {
        return m_additionalParams;
    }

    void AuthRequestParams::AdditionalParams(
        winrt::Windows::Foundation::Collections::IMap<hstring, hstring> const& value)
    {
        m_additionalParams = value;
    }
}
