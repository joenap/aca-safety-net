//! Configuration loading and merging.

use regex::Regex;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors that can occur when loading configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse TOML: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("invalid regex pattern '{pattern}': {source}")]
    Regex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

/// Main configuration structure.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    /// Regex patterns matching sensitive file paths.
    pub sensitive_files: Vec<String>,

    /// Regex matching commands that read file content.
    pub read_commands: Option<String>,

    /// Explicit deny rules.
    pub deny: Vec<DenyRule>,

    /// Custom user-defined rules.
    #[serde(default)]
    pub rules: Vec<CustomRule>,

    /// Paranoid mode configuration.
    #[serde(default)]
    pub paranoid: ParanoidConfig,

    /// Git-specific settings.
    #[serde(default)]
    pub git: GitConfig,

    /// rm-specific settings.
    #[serde(default)]
    pub rm: RmConfig,

    /// Audit logging settings.
    #[serde(default)]
    pub audit: AuditConfig,
}

/// Explicit deny rule.
#[derive(Debug, Clone, Deserialize)]
pub struct DenyRule {
    /// Tool name to match (e.g., "Bash", "Read").
    pub tool: String,
    /// Regex pattern to match against command/path.
    pub pattern: String,
    /// Human-readable reason for blocking.
    pub reason: String,
}

/// Custom user-defined rule.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomRule {
    /// Rule name for logging.
    pub name: String,
    /// Tool name to match.
    pub tool: String,
    /// Regex pattern to match.
    pub pattern: String,
    /// Action: "block" or "allow".
    #[serde(default = "default_action")]
    pub action: String,
    /// Reason (for blocks).
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_action() -> String {
    "block".to_string()
}

/// Paranoid mode configuration.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ParanoidConfig {
    /// Enable paranoid mode (block ANY mention of sensitive files).
    pub enabled: bool,
    /// Additional patterns for paranoid mode only.
    pub extra_patterns: Vec<String>,
}

/// Git-specific configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GitConfig {
    /// Block destructive git commands.
    pub block_destructive: bool,
    /// Block git add on sensitive files.
    pub block_add_sensitive: bool,
    /// Allowed branches for force push (empty = block all).
    pub force_push_allowed_branches: Vec<String>,
}

impl Default for GitConfig {
    fn default() -> Self {
        Self {
            block_destructive: true,
            block_add_sensitive: true,
            force_push_allowed_branches: vec![],
        }
    }
}

/// rm-specific configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RmConfig {
    /// Block rm -rf outside cwd.
    pub block_outside_cwd: bool,
    /// Allowed paths for rm -rf (in addition to cwd).
    pub allowed_paths: Vec<String>,
}

impl Default for RmConfig {
    fn default() -> Self {
        Self {
            block_outside_cwd: true,
            allowed_paths: vec!["/tmp".to_string(), "/var/tmp".to_string()],
        }
    }
}

/// Audit logging configuration.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AuditConfig {
    /// Enable audit logging.
    pub enabled: bool,
    /// Path to audit log file.
    pub path: Option<String>,
}

/// Compiled configuration with pre-built regexes.
pub struct CompiledConfig {
    /// The raw config.
    pub raw: Config,
    /// Compiled sensitive file patterns.
    pub sensitive_patterns: Vec<Regex>,
    /// Compiled read commands pattern.
    pub read_commands_re: Option<Regex>,
    /// Compiled deny rules.
    pub deny_patterns: Vec<(DenyRule, Regex)>,
    /// Compiled paranoid patterns.
    pub paranoid_patterns: Vec<Regex>,
}

impl Config {
    /// Load configuration, merging user and project configs.
    pub fn load(cwd: Option<&Path>) -> Result<Self, ConfigError> {
        let mut config = Config::default();

        // Load user config (~/.claude/security-hook.toml)
        if let Some(user_config) = Self::load_user_config()? {
            config = user_config;
        }

        // Load and merge project config (.security-hook.toml in cwd)
        if let Some(cwd) = cwd {
            if let Some(project_config) = Self::load_project_config(cwd)? {
                config.merge(project_config);
            }
        }

        Ok(config)
    }

    /// Load user-level config from ~/.claude/security-hook.toml
    fn load_user_config() -> Result<Option<Self>, ConfigError> {
        let path = Self::user_config_path();
        if let Some(path) = path {
            if path.exists() {
                let content = fs::read_to_string(&path)?;
                return Ok(Some(toml::from_str(&content)?));
            }
        }
        Ok(None)
    }

    /// Load project-level config from .security-hook.toml
    fn load_project_config(cwd: &Path) -> Result<Option<Self>, ConfigError> {
        let path = cwd.join(".security-hook.toml");
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            return Ok(Some(toml::from_str(&content)?));
        }
        Ok(None)
    }

    /// Get user config path.
    /// Respects ACO_SAFETY_NET_CONFIG env var for testing.
    fn user_config_path() -> Option<PathBuf> {
        // Check for override env var first (useful for testing)
        if let Ok(path) = std::env::var("ACO_SAFETY_NET_CONFIG") {
            return Some(PathBuf::from(path));
        }
        dirs::home_dir().map(|h| h.join(".claude/security-hook.toml"))
    }

    /// Merge another config into this one (other takes precedence for scalars).
    fn merge(&mut self, other: Config) {
        // Extend arrays
        self.sensitive_files.extend(other.sensitive_files);
        self.deny.extend(other.deny);
        self.rules.extend(other.rules);
        self.paranoid.extra_patterns.extend(other.paranoid.extra_patterns);
        self.rm.allowed_paths.extend(other.rm.allowed_paths);
        self.git
            .force_push_allowed_branches
            .extend(other.git.force_push_allowed_branches);

        // Override scalars if set in project config
        if other.read_commands.is_some() {
            self.read_commands = other.read_commands;
        }
        if other.paranoid.enabled {
            self.paranoid.enabled = true;
        }
        if other.audit.enabled {
            self.audit.enabled = true;
            if other.audit.path.is_some() {
                self.audit.path = other.audit.path;
            }
        }
    }

    /// Compile all regex patterns for faster matching.
    pub fn compile(self) -> Result<CompiledConfig, ConfigError> {
        let sensitive_patterns = self
            .sensitive_files
            .iter()
            .map(|p| {
                Regex::new(p).map_err(|e| ConfigError::Regex {
                    pattern: p.clone(),
                    source: e,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let read_commands_re = self
            .read_commands
            .as_ref()
            .map(|p| {
                Regex::new(p).map_err(|e| ConfigError::Regex {
                    pattern: p.clone(),
                    source: e,
                })
            })
            .transpose()?;

        let deny_patterns = self
            .deny
            .iter()
            .map(|rule| {
                let re = Regex::new(&rule.pattern).map_err(|e| ConfigError::Regex {
                    pattern: rule.pattern.clone(),
                    source: e,
                })?;
                Ok((rule.clone(), re))
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        let mut paranoid_patterns = sensitive_patterns.clone();
        for p in &self.paranoid.extra_patterns {
            paranoid_patterns.push(Regex::new(p).map_err(|e| ConfigError::Regex {
                pattern: p.clone(),
                source: e,
            })?);
        }

        Ok(CompiledConfig {
            raw: self,
            sensitive_patterns,
            read_commands_re,
            deny_patterns,
            paranoid_patterns,
        })
    }
}

impl CompiledConfig {
    /// Check if a path matches any sensitive file pattern.
    pub fn is_sensitive_path(&self, path: &str) -> Option<&str> {
        for (i, re) in self.sensitive_patterns.iter().enumerate() {
            if re.is_match(path) {
                return Some(&self.raw.sensitive_files[i]);
            }
        }
        None
    }

    /// Check if a command is a read command.
    pub fn is_read_command(&self, command: &str) -> bool {
        self.read_commands_re
            .as_ref()
            .map(|re| re.is_match(command))
            .unwrap_or(false)
    }

    /// Check if text matches any paranoid pattern.
    pub fn matches_paranoid(&self, text: &str) -> Option<&str> {
        if !self.raw.paranoid.enabled {
            return None;
        }
        for (i, re) in self.paranoid_patterns.iter().enumerate() {
            if re.is_match(text) {
                if i < self.raw.sensitive_files.len() {
                    return Some(&self.raw.sensitive_files[i]);
                } else {
                    let extra_idx = i - self.raw.sensitive_files.len();
                    return Some(&self.raw.paranoid.extra_patterns[extra_idx]);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.sensitive_files.is_empty());
        assert!(!config.paranoid.enabled);
    }

    #[test]
    fn test_compile_config() {
        let config = Config {
            sensitive_files: vec![r"\.env\b".to_string()],
            read_commands: Some(r"\b(cat|head)\b".to_string()),
            ..Default::default()
        };
        let compiled = config.compile().unwrap();
        assert!(compiled.is_sensitive_path(".env").is_some());
        assert!(compiled.is_sensitive_path("environment").is_none());
        assert!(compiled.is_read_command("cat file"));
        assert!(!compiled.is_read_command("ls file"));
    }

    #[test]
    fn test_invalid_regex() {
        let config = Config {
            sensitive_files: vec!["[invalid".to_string()],
            ..Default::default()
        };
        assert!(config.compile().is_err());
    }

    #[test]
    fn test_paranoid_mode() {
        let config = Config {
            sensitive_files: vec![r"\.env\b".to_string()],
            paranoid: ParanoidConfig {
                enabled: true,
                extra_patterns: vec![r"secret".to_string()],
            },
            ..Default::default()
        };
        let compiled = config.compile().unwrap();
        assert!(compiled.matches_paranoid("cat .env").is_some());
        assert!(compiled.matches_paranoid("echo secret").is_some());
        assert!(compiled.matches_paranoid("ls").is_none());
    }
}
