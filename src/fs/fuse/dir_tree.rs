use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use dashmap::DashMap;
use fuser::INodeNo;

#[derive(Debug, Default)]
struct Node {
    name: OsString,
    parent: Option<INodeNo>,
    children: DashMap<OsString, INodeNo>,
}

#[derive(Debug)]
pub(crate) struct DirTree {
    nodes: DashMap<INodeNo, Node>,
    next_inode: AtomicU64,
}

impl DirTree {
    pub(crate) fn new() -> Self {
        let nodes = DashMap::new();
        nodes.insert(INodeNo::ROOT, Default::default());

        Self {
            nodes,
            next_inode: AtomicU64::new(INodeNo::ROOT.0 + 1),
        }
    }

    pub(crate) fn get_path(&self, inode: INodeNo) -> Option<PathBuf> {
        match self.nodes.get(&inode) {
            Some(node) => match node.parent {
                // We're going to assume the parent node exists
                Some(p) => Some(self.get_path(p).unwrap().join(&node.name)),
                None => Some(PathBuf::new()),
            },
            None => None,
        }
    }

    pub(crate) fn insert_path(&self, path: impl AsRef<Path>) -> INodeNo {
        let mut inode = INodeNo::ROOT;
        for component in path.as_ref().components() {
            let name: &OsStr = component.as_ref();

            // Should be okay to unwrap, we control what inodes are searched
            let node = self.nodes.get_mut(&inode).unwrap();
            match node.children.get(name) {
                Some(child) => inode = *child,
                None => {
                    let child = Node {
                        parent: Some(inode),
                        name: name.to_owned(),
                        children: DashMap::new(),
                    };

                    inode = INodeNo(self.next_inode.fetch_add(1, Ordering::SeqCst));
                    node.children.insert(name.to_owned(), inode);
                    self.nodes.insert(inode, child);
                }
            }
        }

        inode
    }

    pub(crate) fn rename(
        &self,
        old_parent: INodeNo,
        old_name: impl AsRef<OsStr>,
        new_parent: INodeNo,
        new_name: impl AsRef<OsStr>,
    ) {
        let inode = match self
            .nodes
            .get_mut(&old_parent)
            .and_then(|p| p.children.remove(old_name.as_ref()))
        {
            Some((_, inode)) => inode,
            None => return,
        };

        let new_name = new_name.as_ref().to_os_string();
        self.nodes.alter(&inode, |_, mut node| {
            node.name.clone_from(&new_name);
            node.parent = Some(new_parent);
            node
        });
        self.nodes.alter(&new_parent, |_, node| {
            node.children.insert(new_name, inode);
            node
        });
    }

    pub(crate) fn remove(&self, parent: INodeNo, name: impl AsRef<OsStr>) {
        if let Some(node) = self.nodes.get_mut(&parent)
            && let Some((_, inode)) = node.children.remove(name.as_ref())
        {
            self.nodes.remove(&inode);
        }
    }

    pub(crate) fn forget(&self, inode: INodeNo) {
        if let Some((_, node)) = self.nodes.remove(&inode)
            && let Some(parent) = node.parent
            && let Some(parent_node) = self.nodes.get_mut(&parent)
        {
            parent_node.children.remove(&node.name);
        }
    }
}
