use chrono::Timelike;

#[derive(Default)]
pub struct BehaviorProfile {
    avg_messages_per_session: f64,
    avg_session_duration_secs: u64,
    active_hours: [u32; 24],
    sessions_counted: u32,
    current_session_messages: u32,
    current_session_start: Option<std::time::Instant>,
}

#[derive(Debug, Clone)]
pub enum AnomalyType {
    HighMessageVolume { current: u32, expected: f64 },
    UnusualActiveHour { hour: u8 },
    ExtendedSession { duration_secs: u64, expected: u64 },
    RapidCommands { commands_per_min: u32 },
}

impl BehaviorProfile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start_session(&mut self) {
        self.current_session_messages = 0;
        self.current_session_start = Some(std::time::Instant::now());

        let hour = chrono::Local::now().hour() as usize;
        if hour < 24 {
            self.active_hours[hour] += 1;
        }
    }

    pub fn record_message(&mut self) {
        self.current_session_messages += 1;
    }

    pub fn end_session(&mut self) {
        if self.sessions_counted > 0 {
            let total_messages = self.avg_messages_per_session * self.sessions_counted as f64;
            self.avg_messages_per_session =
                (total_messages + self.current_session_messages as f64) / (self.sessions_counted + 1) as f64;

            if let Some(start) = self.current_session_start {
                let duration = start.elapsed().as_secs();
                let total_duration = self.avg_session_duration_secs * self.sessions_counted as u64;
                self.avg_session_duration_secs =
                    (total_duration + duration) / (self.sessions_counted + 1) as u64;
            }
        } else {
            self.avg_messages_per_session = self.current_session_messages as f64;
            if let Some(start) = self.current_session_start {
                self.avg_session_duration_secs = start.elapsed().as_secs();
            }
        }
        self.sessions_counted += 1;
    }

    pub fn check_anomalies(&self) -> Vec<AnomalyType> {
        let mut anomalies = Vec::new();

        if self.sessions_counted >= 5 {
            let expected = self.avg_messages_per_session * 3.0;
            if self.current_session_messages as f64 > expected {
                anomalies.push(AnomalyType::HighMessageVolume {
                    current: self.current_session_messages,
                    expected: self.avg_messages_per_session,
                });
            }
        }

        let current_hour = chrono::Local::now().hour() as usize;
        if current_hour < 24 && self.sessions_counted >= 10 {
            let hour_activity = self.active_hours[current_hour];
            let avg_activity: u32 = self.active_hours.iter().sum::<u32>() / 24;
            if hour_activity == 0 && avg_activity > 2 {
                anomalies.push(AnomalyType::UnusualActiveHour {
                    hour: current_hour as u8,
                });
            }
        }

        if let Some(start) = self.current_session_start {
            let duration = start.elapsed().as_secs();
            if self.sessions_counted >= 5 && duration > self.avg_session_duration_secs * 3 {
                anomalies.push(AnomalyType::ExtendedSession {
                    duration_secs: duration,
                    expected: self.avg_session_duration_secs,
                });
            }
        }

        anomalies
    }
}
