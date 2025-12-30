use sqlx::{Pool, Sqlite};
use chrono::Utc;
use tokio::time::{sleep, Duration};
use cron::Schedule;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, error, warn};

use crate::types::{MissionEvent, ScanRequest, ScheduledScan}; 

use tokio::sync::broadcast;


pub struct Scheduler {
    db: Pool<Sqlite>,
    tx: broadcast::Sender<MissionEvent>, 
    registry: Arc<crate::ScanRegistry>,
}

impl Scheduler {
    pub fn new(db: Pool<Sqlite>, tx: broadcast::Sender<MissionEvent>, registry: Arc<crate::ScanRegistry>) -> Self {
        Self { db, tx, registry }
    }

    pub async fn start(&self) {
        let db = self.db.clone();
        let tx = self.tx.clone();
        let registry = self.registry.clone();
        
        tokio::spawn(async move {
            info!("🕒 Scheduler started");
            loop {
                sleep(Duration::from_secs(60)).await;
                if let Err(e) = Self::process_schedules(&db, &tx, &registry).await {
                    error!("Scheduler error: {}", e);
                }
            }
        });
    }

    async fn process_schedules(db: &Pool<Sqlite>, _tx: &broadcast::Sender<MissionEvent>, registry: &Arc<crate::ScanRegistry>) -> Result<(), Box<dyn std::error::Error>> {
        let now = Utc::now().timestamp();
        
        let tasks: Vec<ScheduledScan> = sqlx::query_as::<_, ScheduledScan>(
            "SELECT * FROM schedules WHERE active = 1 AND next_run <= ?"
        )
        .bind(now)
        .fetch_all(db)
        .await?;

        for task in tasks {
            info!("🚀 Triggering scheduled scan for target: {}", task.target);
            
            let tx_clone = _tx.clone();
            let registry_clone = Arc::clone(registry);
            let webhook_url = task.webhook_url.clone();
            let target = task.target.clone();
            let profile = task.profile.clone();
            
            tokio::spawn(async move {
                let scan_req = ScanRequest {
                    target: target.clone(),
                    mission_id: Some(format!("scheduled-{}", target)),
                    profile: profile.clone(),
                    lang: "en".into(),
                    custom_ports: None,
                    enable_udp: false,
                    enable_shodan: false,
                    enable_virustotal: false,
                    enable_censys: false,
                    enable_alienvault: false,
                    timing: 3,
                    auto_exploit: false,
                    patches: vec![],
                    attacker_point: None,
                    webhook_url,
                    proxy_url: None,
                };
                
                if let Err(e) = crate::run_scan_internal(scan_req, tx_clone, registry_clone).await {
                    error!("Scheduled scan failed for {}: {:?}", target, e);
                }
            });
            let next_ts = match Schedule::from_str(&task.cron_expression) {
                Ok(schedule) => {
                    if let Some(next) = schedule.upcoming(Utc).next() {
                        next.timestamp()
                    } else {
                        now + 86400 
                    }
                },
                Err(_) => {
                    warn!("Invalid cron for task {}: {}", task.id, task.cron_expression);
                    now + 86400 
                }
            };

            sqlx::query("UPDATE schedules SET last_run = ?, next_run = ? WHERE id = ?")
                .bind(now)
                .bind(next_ts)
                .bind(&task.id)
                .execute(db)
                .await?;
            
            info!("Task {} updated. Next run: {}", task.id, next_ts);
        }

        Ok(())
    }
}
