use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIconBuilder};
use tracing::{error, info};

use crate::{
    fulfill_request, notifier, try_hook, AgentConfig, AgentEvent, PendingRequest,
};

fn load_icon() -> Icon {
    // 16x16 RGBA icon (simple key shape placeholder)
    // In production, load from an embedded PNG
    let rgba = vec![0u8; 16 * 16 * 4]; // transparent placeholder
    Icon::from_rgba(rgba, 16, 16).expect("failed to create icon")
}

pub async fn run(
    config: AgentConfig,
    event_tx: mpsc::Sender<AgentEvent>,
    mut event_rx: mpsc::Receiver<AgentEvent>,
) -> anyhow::Result<()> {
    let pending: Arc<Mutex<Vec<PendingRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let client = reqwest::Client::new();

    // Build the tray menu
    let menu = Menu::new();
    let status_item = MenuItem::new("behest: waiting...", false, None);
    let quit_item = MenuItem::new("Quit", true, None);
    menu.append(&status_item)?;
    menu.append(&quit_item)?;

    let _tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("behest agent")
        .with_icon(load_icon())
        .build()?;

    let quit_id = quit_item.id().clone();

    // Spawn menu event handler
    let tx_clone = event_tx.clone();
    tokio::spawn(async move {
        loop {
            if let Ok(event) = MenuEvent::receiver().try_recv() {
                if event.id == quit_id {
                    let _ = tx_clone.send(AgentEvent::Quit).await;
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });

    // Main event loop
    while let Some(event) = event_rx.recv().await {
        match event {
            AgentEvent::NewRequests(requests) => {
                for req in &requests {
                    notifier::notify_new_request(req);

                    // Try hook first
                    if let Some(credential) = try_hook(&config, req).await {
                        if let Err(e) = fulfill_request(
                            &client,
                            &config.broker_url,
                            &req.id,
                            credential.as_bytes(),
                            &req.public_key,
                        )
                        .await
                        {
                            error!(error = %e, request_id = %req.id, "auto-fulfill failed");
                        }
                        continue;
                    }

                    // No hook or hook failed: request stays pending
                    // The desktop notification already alerted the user
                    // They can fulfill via the CLI or a future GUI
                    info!(
                        request_id = %req.id,
                        service = %req.service,
                        "request awaiting manual fulfillment"
                    );
                }

                let mut p = pending.lock().unwrap();
                p.extend(requests);

                let count = p.len();
                status_item.set_text(format!("behest: {} pending", count));
            }
            AgentEvent::FulfillRequest { id, credential } => {
                let pub_key = {
                    let p = pending.lock().unwrap();
                    p.iter().find(|r| r.id == id).map(|r| r.public_key.clone())
                };

                if let Some(pub_key) = pub_key {
                    if let Err(e) = fulfill_request(
                        &client,
                        &config.broker_url,
                        &id,
                        credential.as_bytes(),
                        &pub_key,
                    )
                    .await
                    {
                        error!(error = %e, "fulfillment failed");
                    } else {
                        let mut p = pending.lock().unwrap();
                        p.retain(|r| r.id != id);
                        let count = p.len();
                        if count == 0 {
                            status_item.set_text("behest: waiting...");
                        } else {
                            status_item.set_text(format!("behest: {} pending", count));
                        }
                    }
                }
            }
            AgentEvent::Quit => {
                info!("quitting");
                break;
            }
        }
    }

    Ok(())
}
