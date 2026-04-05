use std::sync::{Arc, Mutex};
use std::time::Duration;

use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tokio::sync::mpsc as tokio_mpsc;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder};
use tracing::{error, info, warn};

use crate::broker::BrokerClient;
use crate::{notifier, try_hook, AgentConfig, PendingRequest};

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

/// A clickable pending request in the tray menu.
struct RequestMenuItem {
    menu_item: MenuItem,
    request_id: String,
}

fn load_icon() -> Icon {
    // 16x16 RGBA template icon — white circle, macOS adapts to theme
    let mut rgba = vec![0u8; 16 * 16 * 4];
    for y in 0..16u32 {
        for x in 0..16u32 {
            let dx = x as f32 - 7.5;
            let dy = y as f32 - 7.5;
            if dx * dx + dy * dy <= 36.0 {
                let idx = ((y * 16 + x) * 4) as usize;
                rgba[idx] = 255;
                rgba[idx + 1] = 255;
                rgba[idx + 2] = 255;
                rgba[idx + 3] = 255;
            }
        }
    }
    Icon::from_rgba(rgba, 16, 16).expect("failed to create icon")
}

/// Open Terminal.app with `behest-agent fulfill <id>`.
fn open_terminal_fulfill(request_id: &str) {
    let agent_bin = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("behest-agent"));
    let script = format!(
        "tell application \"Terminal\"\n\
         activate\n\
         do script \"{} fulfill {}\"\n\
         end tell",
        agent_bin.display(),
        request_id
    );

    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .spawn();
}

/// Run the agent in GUI mode.
/// Main thread: tao event loop (AppKit)
/// Background: tokio runtime for HTTP polling and hook execution
pub fn run(config: AgentConfig) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let (ui_tx, ui_rx) = std::sync::mpsc::channel::<UiMessage>();
    let (cmd_tx, cmd_rx) = tokio_mpsc::unbounded_channel::<WorkerCommand>();

    let worker_config = config.clone();
    rt.spawn(async move {
        async_worker(worker_config, ui_tx, cmd_rx).await;
    });

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();

    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |_e| {
        let _ = proxy.send_event(UserEvent::Wake);
    }));

    let pending: Arc<Mutex<Vec<PendingRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let request_menu_items: Arc<Mutex<Vec<RequestMenuItem>>> =
        Arc::new(Mutex::new(Vec::new()));

    // Static menu items
    let status_item = MenuItem::new("behest: waiting...", false, None);
    let quit_item = MenuItem::new("Quit", true, None);
    let quit_id = quit_item.id().clone();

    let menu = Menu::new();
    menu.append(&status_item).unwrap();
    menu.append(&PredefinedMenuItem::separator()).unwrap();
    menu.append(&quit_item).unwrap();

    let mut _tray_icon: Option<tray_icon::TrayIcon> = None;

    // Wake the event loop periodically
    let proxy2 = event_loop.create_proxy();
    rt.spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if proxy2.send_event(UserEvent::Wake).is_err() {
                break;
            }
        }
    });

    event_loop.run(move |event, _event_loop, control_flow| {
        *control_flow = ControlFlow::Wait;

        while let Ok(msg) = ui_rx.try_recv() {
            match msg {
                UiMessage::NewRequests(requests) => {
                    for req in &requests {
                        notifier::notify_new_request(req);

                        // Add a clickable menu item for this request
                        let label = format!("  {} — {}", req.service, req.message);
                        let item = MenuItem::new(
                            if label.len() > 60 {
                                format!("{}...", &label[..57])
                            } else {
                                label
                            },
                            true,
                            None,
                        );
                        // Insert before the separator (index 1)
                        let _ = menu.insert(&item, 1);
                        let mut items = request_menu_items.lock().unwrap();
                        items.push(RequestMenuItem {
                            menu_item: item,
                            request_id: req.id.clone(),
                        });
                    }

                    let mut p = pending.lock().unwrap();
                    p.extend(requests);
                    let count = p.len();
                    if count > 0 {
                        status_item.set_text(format!("behest: {} pending", count));
                    }
                }
                UiMessage::Fulfilled(id) => {
                    // Remove the menu item for this request
                    let mut items = request_menu_items.lock().unwrap();
                    if let Some(pos) = items.iter().position(|i| i.request_id == id) {
                        let item = items.remove(pos);
                        let _ = menu.remove(&item.menu_item);
                    }

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

        // Handle menu clicks
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == quit_id {
                let _ = cmd_tx.send(WorkerCommand::Quit);
                _tray_icon.take();
                *control_flow = ControlFlow::Exit;
                return;
            }

            // Check if it's a request item click
            let items = request_menu_items.lock().unwrap();
            if let Some(req_item) = items.iter().find(|i| *i.menu_item.id() == event.id) {
                open_terminal_fulfill(&req_item.request_id);
            }
        }

        if let Event::NewEvents(StartCause::Init) = event {
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
    });
}

/// Async worker: polls the broker, runs hooks, fulfills requests.
async fn async_worker(
    config: AgentConfig,
    ui_tx: std::sync::mpsc::Sender<UiMessage>,
    mut cmd_rx: tokio_mpsc::UnboundedReceiver<WorkerCommand>,
) {
    let client = BrokerClient::new(&config);
    let interval = Duration::from_secs(config.poll_interval_secs);
    let mut known_ids = std::collections::HashSet::<String>::new();
    let mut poll_interval = tokio::time::interval(interval);

    loop {
        tokio::select! {
            _ = poll_interval.tick() => {
                match client.fetch_pending().await {
                    Ok(requests) => {
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
                            let mut hook_fulfilled = Vec::new();
                            for req in &new {
                                if let Some(credential) = try_hook(&config, req).await {
                                    match client.fulfill(
                                        &req.id,
                                        credential.as_bytes(),
                                        &req.public_key,
                                    ).await {
                                        Ok(()) => hook_fulfilled.push(req.id.clone()),
                                        Err(e) => error!(error = %e, request_id = %req.id, "auto-fulfill failed"),
                                    }
                                }
                            }

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
