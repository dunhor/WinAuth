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
        winrt::hstring CodeChallenge();
        void CodeChallenge(const winrt::hstring& value);
        winrt::Microsoft::Security::Authentication::OAuth::CodeChallengeMethodKind CodeChallengeMethod();
        void CodeChallengeMethod(winrt::Microsoft::Security::Authentication::OAuth::CodeChallengeMethodKind value);
        winrt::Windows::Foundation::Collections::IMap<hstring, winrt::hstring> AdditionalParams();
        void AdditionalParams(const winrt::Windows::Foundation::Collections::IMap<hstring, winrt::hstring>& value);

        // Implementation functions
        void Finalize();

    private:
        struct revert_guard_on_exit
        {
            AuthRequestParams* target;

            ~revert_guard_on_exit()
            {
                target->m_guard.store(0);
            }
        };

        template <typename Func>
        auto modify_op(Func&& callback)
        {
            std::uint8_t expect = 0;
            if (!m_guard.compare_exchange_strong(expect, 1))
            {
                if (expect == 1)
                {
                    throw winrt::hresult_changed_state(L"Concurrent modification of AuthRequestParams is not allowed");
                }
                else
                {
                    throw winrt::hresult_illegal_method_call(
                        L"Cannot modify AuthRequestParams object after it has been used to initiate an auth request");
                }
            }

            revert_guard_on_exit guard{ this };
            return callback();
        }

        template <typename Func>
        auto read_op(Func&& callback)
        {
            std::uint8_t expect = 0;
            if (!m_guard.compare_exchange_strong(expect, 1))
            {
                if (expect == 1)
                {
                    throw winrt::hresult_changed_state(L"Concurrent access of AuthRequestParams is not allowed");
                }

                // Otherwise the params are finalized, just make the callback and we're done
                return callback();
            }

            revert_guard_on_exit guard{ this };
            return callback();
        }

        std::atomic_uint8_t m_guard{ 0 };
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
