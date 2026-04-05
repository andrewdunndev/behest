use std::sync::{Arc, Mutex};
use std::time::Duration;

use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tokio::sync::mpsc as tokio_mpsc;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder};
use tracing::{error, info, warn};

use crate::{
    fetch_pending, fulfill_request, notifier, try_hook,
    AgentConfig, PendingRequest,
};

/// Messages from the async worker to the UI thread.
#[derive(Debug)]
enum UiMessage {
    NewRequests(Vec<PendingRequest>),
    Fulfilled(String),
    PollError(String),
}

/// Messages from the UI thread to the async worker.
#[derive(Debug)]
enum WorkerCommand {
    Quit,
}

/// Custom event type for the tao event loop. Used to wake the loop.
enum UserEvent {
    Wake,
}

fn load_icon() -> Icon {
    // 16x16 RGBA icon — solid circle placeholder for menu bar
    // Template icon: white pixels on transparent, macOS will adapt to theme
    let mut rgba = vec![0u8; 16 * 16 * 4];
    for y in 0..16u32 {
        for x in 0..16u32 {
            let dx = x as f32 - 7.5;
            let dy = y as f32 - 7.5;
            if dx * dx + dy * dy <= 36.0 {
                let idx = ((y * 16 + x) * 4) as usize;
                rgba[idx] = 255;     // R
                rgba[idx + 1] = 255; // G
                rgba[idx + 2] = 255; // B
                rgba[idx + 3] = 255; // A
            }
        }
    }
    Icon::from_rgba(rgba, 16, 16).expect("failed to create icon")
}

/// Run the agent in GUI mode.
/// Main thread: tao event loop (AppKit)
/// Background: tokio runtime for HTTP polling and hook execution
pub fn run(config: AgentConfig) -> anyhow::Result<()> {
    // Build tokio runtime on background threads (NOT the main thread)
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // Channels: async worker -> UI (std::sync for non-blocking try_recv)
    let (ui_tx, ui_rx) = std::sync::mpsc::channel::<UiMessage>();
    // Channels: UI -> async worker (tokio for async recv)
    let (cmd_tx, cmd_rx) = tokio_mpsc::unbounded_channel::<WorkerCommand>();

    // Spawn the async polling worker on the tokio runtime
    let worker_config = config.clone();
    rt.spawn(async move {
        async_worker(worker_config, ui_tx, cmd_rx).await;
    });

    // Build the tao event loop on the main thread
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();

    // Forward tray and menu events into the event loop
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |_e| {
        // Wake the event loop so it drains messages
        let _ = proxy.send_event(UserEvent::Wake);
    }));

    let pending: Arc<Mutex<Vec<PendingRequest>>> = Arc::new(Mutex::new(Vec::new()));

    // Menu items (created before the event loop takes over)
    let status_item = MenuItem::new("behest: waiting...", false, None);
    let quit_item = MenuItem::new("Quit", true, None);
    let quit_id = quit_item.id().clone();

    let menu = Menu::new();
    menu.append(&status_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&quit_item)?;

    let mut _tray_icon: Option<tray_icon::TrayIcon> = None;

    // Periodic timer to drain async messages
    let proxy2 = event_loop.create_proxy();
    rt.spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            // Wake the event loop to check for new messages
            if proxy2.send_event(UserEvent::Wake).is_err()
            {
                break;
            }
        }
    });

    event_loop.run(move |event, _event_loop, control_flow| {
        *control_flow = ControlFlow::Wait;

        // Drain messages from the async worker
        while let Ok(msg) = ui_rx.try_recv() {
            match msg {
                UiMessage::NewRequests(requests) => {
                    for req in &requests {
                        notifier::notify_new_request(req);
                    }

                    let mut p = pending.lock().unwrap();
                    p.extend(requests);
                    let count = p.len();
                    if count > 0 {
                        status_item.set_text(format!("behest: {} pending", count));
                    }
                }
                UiMessage::Fulfilled(id) => {
                    let mut p = pending.lock().unwrap();
                    p.retain(|r| r.id != id);
                    let count = p.len();
                    if count == 0 {
                        status_item.set_text("behest: waiting...");
                    } else {
                        status_item.set_text(format!("behest: {} pending", count));
                    }
                }
                UiMessage::PollError(e) => {
                    if !e.is_empty() {
                        warn!(error = %e, "poll error");
                    }
                }
            }
        }

        // Drain menu events
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == quit_id {
                let _ = cmd_tx.send(WorkerCommand::Quit);
                _tray_icon.take(); // drop to remove from menu bar
                *control_flow = ControlFlow::Exit;
                return;
            }
        }

        match event {
            Event::NewEvents(StartCause::Init) => {
                // Create tray icon AFTER event loop is running (macOS requirement)
                _tray_icon = Some(
                    TrayIconBuilder::new()
                        .with_menu(Box::new(menu.clone()))
                        .with_tooltip("behest agent")
                        .with_icon(load_icon())
                        .with_icon_as_template(true)
                        .with_menu_on_left_click(true)
                        .build()
                        .expect("failed to build tray icon"),
                );
                info!("tray icon created");
            }
            _ => {}
        }
    });
}

/// Async worker: polls the broker, runs hooks, fulfills requests.
/// Runs entirely on the tokio runtime (background threads).
async fn async_worker(
    config: AgentConfig,
    ui_tx: std::sync::mpsc::Sender<UiMessage>,
    mut cmd_rx: tokio_mpsc::UnboundedReceiver<WorkerCommand>,
) {
    let client = reqwest::Client::new();
    let interval = Duration::from_secs(config.poll_interval_secs);
    let mut known_ids = std::collections::HashSet::<String>::new();
    let mut poll_interval = tokio::time::interval(interval);

    loop {
        tokio::select! {
            _ = poll_interval.tick() => {
                match fetch_pending(&client, &config.broker_url).await {
                    Ok(requests) => {
                        // Prune known_ids: remove IDs no longer pending
                        let active_ids: std::collections::HashSet<&str> =
                            requests.iter().map(|r| r.id.as_str()).collect();
                        known_ids.retain(|id| active_ids.contains(id.as_str()));

                        let new = requests
                            .into_iter()
                            .filter(|r: &PendingRequest| !known_ids.contains(&r.id))
                            .collect::<Vec<PendingRequest>>();

                        for r in &new {
                            known_ids.insert(r.id.clone());
                        }

                        if !new.is_empty() {
                            // Try hooks for each new request
                            let mut hook_fulfilled = Vec::new();
                            for req in &new {
                                if let Some(credential) = try_hook(&config, req).await {
                                    match fulfill_request(
                                        &client,
                                        &config.broker_url,
                                        &req.id,
                                        credential.as_bytes(),
                                        &req.public_key,
                                    ).await {
                                        Ok(()) => {
                                            hook_fulfilled.push(req.id.clone());
                                        }
                                        Err(e) => {
                                            error!(error = %e, request_id = %req.id, "auto-fulfill failed");
                                        }
                                    }
                                }
                            }

                            // Only send unfulfilled requests to the UI
                            let pending_for_ui: Vec<PendingRequest> = new
                                .into_iter()
                                .filter(|r| !hook_fulfilled.contains(&r.id))
                                .collect();

                            if !pending_for_ui.is_empty() {
                                let _ = ui_tx.send(UiMessage::NewRequests(pending_for_ui));
                            }
                            for id in hook_fulfilled {
                                let _ = ui_tx.send(UiMessage::Fulfilled(id));
                            }
                        }
                    }
                    Err(e) => {
                        let _ = ui_tx.send(UiMessage::PollError(e.to_string()));
                    }
                }
            }
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    WorkerCommand::Quit => {
                        info!("worker shutting down");
                        return;
                    }
                }
            }
        }
    }
}
