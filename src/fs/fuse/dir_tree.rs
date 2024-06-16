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
    inode: Inode,
    name: OsString,
    parent: Option<Inode>,
    children: BTreeMap<OsString, Inode>,
}

// TODO: Look into inode reuse if desired
#[derive(Debug)]
pub struct DirTree {
    nodes: Vec<Node>,
    next_inode: AtomicU64,
}

impl DirTree {
    pub fn new() -> Self {
        let root = Node {
            inode: FUSE_ROOT_ID,
            ..Default::default()
        };

        Self {
            nodes: vec![root],
            next_inode: AtomicU64::new(FUSE_ROOT_ID + 1),
        }
    }

    pub fn get_path(&self, inode: Inode) -> Option<PathBuf> {
        match self.nodes.get(inode as usize - 1) {
            Some(node) => match node.parent {
                // Ok to unwrap, I think - items should never be removed from self.nodes, so parent
                // indexes should always correspond to the same values.
                Some(p) => Some(self.get_path(p).unwrap().join(&node.name)),
                None => Some(PathBuf::new()),
            },
            None => None,
        }
    }

    pub fn insert_path(&mut self, path: impl AsRef<Path>) -> Inode {
        let mut inode = FUSE_ROOT_ID;
        for component in path.as_ref().components() {
            let name: &OsStr = component.as_ref();

            // Ok to index into self.nodes, inodes that we track should always stay valid
            let node = &mut self.nodes[inode as usize - 1];
            match node.children.get(name) {
                Some(&child) => inode = child,
                None => {
                    let child = Node {
                        inode: self.next_inode.fetch_add(1, Ordering::SeqCst),
                        parent: Some(inode),
                        name: name.to_owned(),
                        children: BTreeMap::new(),
                    };

                    node.children.insert(name.to_owned(), child.inode);
                    inode = child.inode;
                    self.nodes.push(child);
                }
            }
        }

        inode
    }

    pub fn rename(
        &mut self,
        old_parent: Inode,
        old_name: impl AsRef<OsStr>,
        new_parent: Inode,
        new_name: impl AsRef<OsStr>,
    ) {
        let inode = match self
            .nodes
            .get_mut(old_parent as usize - 1)
            .and_then(|p| p.children.remove(old_name.as_ref()))
        {
            Some(inode) => inode,
            None => return,
        };

        let new_name = new_name.as_ref().to_os_string();
        if let Some(node) = self.nodes.get_mut(inode as usize - 1) {
            node.name.clone_from(&new_name);
            node.parent = Some(new_parent);
        }

        if let Some(new_parent_node) = self.nodes.get_mut(new_parent as usize - 1) {
            new_parent_node.children.insert(new_name, inode);
        }
    }
}
