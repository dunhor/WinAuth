#include "pch.h"

#include "AuthRequestAsyncOperation.h"

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

winrt::hresult AuthRequestAsyncOperation::ErrorCode()
{
    std::shared_lock guard{ m_mutex };
    return m_error;
}

uint32_t AuthRequestAsyncOperation::Id()
{
    return 1; // NOTE: This is copying the C++/WinRT implementation
}

winrt::Windows::Foundation::AsyncStatus AuthRequestAsyncOperation::Status()
{
    std::shared_lock guard{ m_mutex };
    return m_status;
}

void AuthRequestAsyncOperation::Cancel()
{
    // TODO
}

void AuthRequestAsyncOperation::Close()
{
    // TODO? C++/WinRT does a noop here
}

AuthRequestAsyncOperation::handler_type AuthRequestAsyncOperation::Completed()
{
    std::shared_lock guard{ m_mutex };
    return m_handler;
}

void AuthRequestAsyncOperation::Completed(const handler_type& handler)
{
    std::lock_guard guard{ m_mutex };
    if (m_handlerSet)
    {
        throw winrt::hresult_illegal_delegate_assignment();
    }

    m_handlerSet = true;
    if (!handler)
    {
        WINRT_ASSERT(!m_handler);
        return;
    }

    if (m_status != AsyncStatus::Started)
    {
        invoke_completed(handler);
        return;
    }

    if (handler.try_as<::IAgileObject>())
    {
        m_handler = handler;
    }
    else
    {
        try
        {
            auto ref = winrt::make_agile(handler);
            m_handler = [ref = std::move(ref)](const IAsyncOperation<result_type>& op, AsyncStatus status) {
                ref.get()(op, status);
            };
        }
        catch (...)
        {
            m_handler = handler;
        }
    }
}

AuthRequestAsyncOperation::result_type AuthRequestAsyncOperation::GetResults()
{
    std::shared_lock guard{ m_mutex };
    if (m_status == AsyncStatus::Completed)
    {
        return m_result;
    }
    else if (m_error < 0)
    {
        throw winrt::hresult_error(m_error);
    }

    WINRT_ASSERT(m_status == AsyncStatus::Started);
    throw winrt::hresult_illegal_method_call();
}

void AuthRequestAsyncOperation::invoke_completed(const handler_type& handler)
{
    try
    {
        handler(*this, m_status);
    }
    catch (...)
    {
        // Just eat exceptions as they're not relevant to the caller at all
    }
}
