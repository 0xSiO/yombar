use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use fuser::FUSE_ROOT_ID;

use super::Inode;

#[derive(Debug, Default)]
struct Node {
    name: OsString,
    parent: Option<Inode>,
    children: BTreeMap<OsString, Inode>,
}

#[derive(Debug)]
pub(crate) struct DirTree {
    nodes: BTreeMap<Inode, Node>,
    next_inode: AtomicU64,
}

impl DirTree {
    pub(crate) fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(FUSE_ROOT_ID, Default::default());

        Self {
            nodes,
            next_inode: AtomicU64::new(FUSE_ROOT_ID + 1),
        }
    }

    pub(crate) fn get_path(&self, inode: Inode) -> Option<PathBuf> {
        match self.nodes.get(&inode) {
            Some(node) => match node.parent {
                // We're going to assume the parent node exists
                Some(p) => Some(self.get_path(p).unwrap().join(&node.name)),
                None => Some(PathBuf::new()),
            },
            None => None,
        }
    }

    pub(crate) fn insert_path(&mut self, path: impl AsRef<Path>) -> Inode {
        let mut inode = FUSE_ROOT_ID;
        for component in path.as_ref().components() {
            let name: &OsStr = component.as_ref();

            // Should be okay to unwrap, we control what inodes are searched
            let node = self.nodes.get_mut(&inode).unwrap();
            match node.children.get(name) {
                Some(&child) => inode = child,
                None => {
                    let child = Node {
                        parent: Some(inode),
                        name: name.to_owned(),
                        children: BTreeMap::new(),
                    };

                    inode = self.next_inode.fetch_add(1, Ordering::SeqCst);
                    node.children.insert(name.to_owned(), inode);
                    self.nodes.insert(inode, child);
                }
            }
        }

        inode
    }

    pub(crate) fn rename(
        &mut self,
        old_parent: Inode,
        old_name: impl AsRef<OsStr>,
        new_parent: Inode,
        new_name: impl AsRef<OsStr>,
    ) {
        let inode = match self
            .nodes
            .get_mut(&old_parent)
            .and_then(|p| p.children.remove(old_name.as_ref()))
        {
            Some(inode) => inode,
            None => return,
        };

        let new_name = new_name.as_ref().to_os_string();
        if let Some(node) = self.nodes.get_mut(&inode) {
            node.name.clone_from(&new_name);
            node.parent = Some(new_parent);
        }

        if let Some(new_parent_node) = self.nodes.get_mut(&new_parent) {
            new_parent_node.children.insert(new_name, inode);
        }
    }

    pub(crate) fn remove(&mut self, parent: Inode, name: impl AsRef<OsStr>) {
        if let Some(node) = self.nodes.get_mut(&parent)
            && let Some(inode) = node.children.remove(name.as_ref())
        {
            self.nodes.remove(&inode);
        }
    }

    pub(crate) fn forget(&mut self, inode: Inode) {
        if let Some(node) = self.nodes.remove(&inode)
            && let Some(parent) = node.parent
            && let Some(parent_node) = self.nodes.get_mut(&parent)
        {
            parent_node.children.remove(&node.name);
        }
    }
}
