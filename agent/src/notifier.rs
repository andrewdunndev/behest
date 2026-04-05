use crate::PendingRequest;

pub fn notify_new_request(request: &PendingRequest) {
    let title = format!("behest: {}", request.service);
    let body = format!("{}\n{}", request.message, request.hint);

    match notify_rust::Notification::new()
        .summary(&title)
        .body(&body)
        .timeout(notify_rust::Timeout::Milliseconds(10_000))
        .show()
    {
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "failed to show desktop notification");
        }
    }
}
