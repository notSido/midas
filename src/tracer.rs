//! Execution tracer for debugging infinite loops

use std::collections::{HashMap, HashSet};

/// Tracks execution patterns to detect loops
pub struct ExecutionTracer {
    /// Unique addresses executed
    unique_addresses: HashSet<u64>,
    /// Address execution frequency
    address_counts: HashMap<u64, u64>,
    /// Last N addresses (for pattern detection)
    recent_addresses: Vec<u64>,
    /// Max recent addresses to track
    recent_limit: usize,
}

impl ExecutionTracer {
    pub fn new() -> Self {
        Self {
            unique_addresses: HashSet::new(),
            address_counts: HashMap::new(),
            recent_addresses: Vec::new(),
            recent_limit: 1000,
        }
    }
    
    /// Record an executed address
    pub fn record(&mut self, addr: u64) {
        self.unique_addresses.insert(addr);
        *self.address_counts.entry(addr).or_insert(0) += 1;
        
        self.recent_addresses.push(addr);
        if self.recent_addresses.len() > self.recent_limit {
            self.recent_addresses.remove(0);
        }
    }
    
    /// Get number of unique addresses
    pub fn unique_count(&self) -> usize {
        self.unique_addresses.len()
    }
    
    /// Get hottest addresses (most executed)
    pub fn get_hot_addresses(&self, count: usize) -> Vec<(u64, u64)> {
        let mut counts: Vec<(u64, u64)> = self.address_counts.iter()
            .map(|(addr, count)| (*addr, *count))
            .collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1));
        counts.truncate(count);
        counts
    }
    
    /// Check if execution appears stuck in a loop
    pub fn is_looping(&self) -> bool {
        // If we have very few unique addresses relative to total executions
        if self.unique_addresses.len() < 100 {
            let total_executions: u64 = self.address_counts.values().sum();
            if total_executions > 100000 {
                return true;
            }
        }
        false
    }
    
    /// Check if execution just broke out of a loop (OEP transition)
    /// Returns true if unique address count increased dramatically
    pub fn detect_breakout(&self, last_unique_count: usize) -> bool {
        let current = self.unique_count();
        
        // If unique addresses increased by 100x or more, we broke out!
        if last_unique_count > 0 && last_unique_count < 1000 {
            let increase_factor = current / last_unique_count;
            if increase_factor >= 100 {
                return true;
            }
        }
        
        // Or if we jumped from <1000 to >100000 unique addresses
        if last_unique_count < 1000 && current > 100000 {
            return true;
        }
        
        false
    }
    
    /// Get execution statistics
    pub fn stats(&self) -> String {
        let total: u64 = self.address_counts.values().sum();
        let hot = self.get_hot_addresses(5);
        let hot_str: Vec<String> = hot.iter()
            .map(|(addr, count)| format!("0x{:x} ({}x)", addr, count))
            .collect();
        
        format!(
            "Unique addrs: {}, Total executions: {}, Hottest: [{}]",
            self.unique_count(),
            total,
            hot_str.join(", ")
        )
    }
}

impl Default for ExecutionTracer {
    fn default() -> Self {
        Self::new()
    }
}
