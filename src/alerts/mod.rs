#[derive(Debug, Clone)]
pub struct Alert {
    pub message: String,
}

impl Alert {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}