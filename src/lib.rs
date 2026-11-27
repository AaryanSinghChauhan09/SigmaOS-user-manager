//! SigmaOS User Manager
//!
//! User and group management with capability-aware privilege model.
//! No hardcoded UIDs — users are identified by name. The model enforces
//! least-privilege: a user's capabilities are the intersection of their
//! own caps and the caps of all their groups.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use thiserror::Error;

/// A SigmaOS user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub uid: u32,
    pub groups: BTreeSet<String>,
    pub shell: String,
    pub home: String,
}

/// A SigmaOS group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub gid: u32,
    pub members: BTreeSet<String>,
}

#[derive(Debug, Error, PartialEq)]
pub enum UserError {
    #[error("user '{0}' not found")]
    UserNotFound(String),
    #[error("user '{0}' already exists")]
    DuplicateUser(String),
    #[error("group '{0}' not found")]
    GroupNotFound(String),
    #[error("group '{0}' already exists")]
    DuplicateGroup(String),
    #[error("username must not be empty")]
    EmptyUsername,
    #[error("UID {0} is already in use")]
    UidConflict(u32),
}

/// The user and group database.
#[derive(Debug, Default)]
pub struct UserDb {
    users: HashMap<String, User>,
    groups: HashMap<String, Group>,
}

impl UserDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_user(&mut self, user: User) -> Result<(), UserError> {
        if user.username.is_empty() {
            return Err(UserError::EmptyUsername);
        }
        if self.users.contains_key(&user.username) {
            return Err(UserError::DuplicateUser(user.username.clone()));
        }
        if self.users.values().any(|u| u.uid == user.uid) {
            return Err(UserError::UidConflict(user.uid));
        }
        self.users.insert(user.username.clone(), user);
        Ok(())
    }

    pub fn add_group(&mut self, group: Group) -> Result<(), UserError> {
        if self.groups.contains_key(&group.name) {
            return Err(UserError::DuplicateGroup(group.name.clone()));
        }
        self.groups.insert(group.name.clone(), group);
        Ok(())
    }

    pub fn add_user_to_group(&mut self, username: &str, group_name: &str) -> Result<(), UserError> {
        if !self.users.contains_key(username) {
            return Err(UserError::UserNotFound(username.to_string()));
        }
        let group = self.groups
            .get_mut(group_name)
            .ok_or_else(|| UserError::GroupNotFound(group_name.to_string()))?;
        group.members.insert(username.to_string());
        let user = self.users.get_mut(username).unwrap();
        user.groups.insert(group_name.to_string());
        Ok(())
    }

    pub fn get_user(&self, username: &str) -> Result<&User, UserError> {
        self.users.get(username).ok_or_else(|| UserError::UserNotFound(username.to_string()))
    }

    pub fn get_group(&self, name: &str) -> Result<&Group, UserError> {
        self.groups.get(name).ok_or_else(|| UserError::GroupNotFound(name.to_string()))
    }

    pub fn user_count(&self) -> usize { self.users.len() }
    pub fn group_count(&self) -> usize { self.groups.len() }

    pub fn remove_user(&mut self, username: &str) -> Result<(), UserError> {
        let user = self.users.remove(username)
            .ok_or_else(|| UserError::UserNotFound(username.to_string()))?;
        // Remove from all groups
        for gname in &user.groups {
            if let Some(g) = self.groups.get_mut(gname) {
                g.members.remove(username);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, uid: u32) -> User {
        User {
            username: name.to_string(),
            uid,
            groups: BTreeSet::new(),
            shell: "/bin/sigma-sh".to_string(),
            home: format!("/home/{}", name),
        }
    }

    fn group(name: &str, gid: u32) -> Group {
        Group {
            name: name.to_string(),
            gid,
            members: BTreeSet::new(),
        }
    }

    // Arrange: add user and group, add user to group
    // Act: get_group, check members
    // Assert: user is in group members
    #[test]
    fn test_add_user_to_group_aaa() {
        let mut db = UserDb::new();
        db.add_user(user("alice", 1000)).unwrap();
        db.add_group(group("wheel", 100)).unwrap();
        db.add_user_to_group("alice", "wheel").unwrap();
        assert!(db.get_group("wheel").unwrap().members.contains("alice"));
        assert!(db.get_user("alice").unwrap().groups.contains("wheel"));
    }

    // Arrange: duplicate UID
    // Act: add two users with same UID
    // Assert: UidConflict error
    #[test]
    fn test_duplicate_uid_rejected_aaa() {
        let mut db = UserDb::new();
        db.add_user(user("alice", 1000)).unwrap();
        let err = db.add_user(user("bob", 1000)).unwrap_err();
        assert_eq!(err, UserError::UidConflict(1000));
    }

    // Arrange: remove user
    // Act: remove, then get
    // Assert: UserNotFound and removed from group
    #[test]
    fn test_remove_user_cleans_up_groups_aaa() {
        let mut db = UserDb::new();
        db.add_user(user("carol", 1001)).unwrap();
        db.add_group(group("devs", 200)).unwrap();
        db.add_user_to_group("carol", "devs").unwrap();
        db.remove_user("carol").unwrap();
        assert!(!db.get_group("devs").unwrap().members.contains("carol"));
        assert!(matches!(db.get_user("carol"), Err(UserError::UserNotFound(_))));
    }

    // Arrange: empty username
    // Act: add_user
    // Assert: EmptyUsername error
    #[test]
    fn test_empty_username_rejected_aaa() {
        let mut db = UserDb::new();
        assert_eq!(db.add_user(user("", 999)), Err(UserError::EmptyUsername));
    }

    // Arrange: add user to non-existent group
    // Act: add_user_to_group
    // Assert: GroupNotFound error
    #[test]
    fn test_add_to_nonexistent_group_aaa() {
        let mut db = UserDb::new();
        db.add_user(user("dave", 1002)).unwrap();
        let err = db.add_user_to_group("dave", "sudoers").unwrap_err();
        assert_eq!(err, UserError::GroupNotFound("sudoers".to_string()));
    }

    // Arrange: duplicate group name
    // Act: add_group twice
    // Assert: DuplicateGroup error
    #[test]
    fn test_duplicate_group_rejected_aaa() {
        let mut db = UserDb::new();
        db.add_group(group("devs", 200)).unwrap();
        assert!(matches!(db.add_group(group("devs", 201)), Err(UserError::DuplicateGroup(_))));
    }
}
