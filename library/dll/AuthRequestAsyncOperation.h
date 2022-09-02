#pragma once

struct AuthRequestAsyncOperation : winrt::implements<AuthRequestAsyncOperation,
    winrt::Windows::Foundation::IAsyncOperation<winrt::Microsoft::Security::Authentication::OAuth::AuthRequestResult>,
    winrt::Windows::Foundation::IAsyncInfo>
{
    using result_type = winrt::Microsoft::Security::Authentication::OAuth::AuthRequestResult;
    using handler_type = winrt::Windows::Foundation::AsyncOperationCompletedHandler<result_type>;

    AuthRequestAsyncOperation() = default; // TODO

    // IAsyncInfo
    winrt::hresult ErrorCode();
    uint32_t Id();
    winrt::Windows::Foundation::AsyncStatus Status();
    void Cancel();
    void Close();

    // IAsyncOperation
    handler_type Completed();
    void Completed(const handler_type& handler);
    result_type GetResults();

private:

    void invoke_completed(const handler_type& handler);

    std::shared_mutex m_mutex;
    result_type m_result{ nullptr };
    bool m_handlerSet = false;
    handler_type m_handler;
    winrt::Windows::Foundation::AsyncStatus m_status = winrt::Windows::Foundation::AsyncStatus::Started;
    winrt::hresult m_error = {};
};
