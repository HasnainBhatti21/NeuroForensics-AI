//! ProcessCollector - running processes, relationships and loaded modules.
//!
//! The collector only records evidence. It never labels any process as
//! malicious and never terminates or modifies anything.

use std::collections::HashMap;

use serde_json::{json, Value};

use super::{Availability, CollectContext, CollectorError, CollectorId, ICollector};
use crate::win;

/// Maximum number of processes for which module lists are attempted
/// (module enumeration is comparatively expensive and access-limited).
const MODULE_ENUM_PROCESS_LIMIT: usize = 400;

#[derive(Default)]
pub struct ProcessCollector {}

impl ICollector for ProcessCollector {
    fn id(&self) -> CollectorId {
        CollectorId::Processes
    }

    fn name(&self) -> &'static str {
        "Processes"
    }

    fn check_availability(&self) -> Availability {
        Availability::Available
    }

    fn collect(&mut self, ctx: &mut CollectContext) -> Result<(), CollectorError> {
        let mut sys = sysinfo::System::new();
        sys.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            sysinfo::ProcessRefreshKind::nothing().with_user(sysinfo::UpdateKind::Always),
        );

        // UID -> username mapping (best effort).
        let users = sysinfo::Users::new_with_refreshed_list();
        let user_names: HashMap<String, String> = users
            .list()
            .iter()
            .map(|u| (format!("{:?}", u.id()), u.name().to_string()))
            .collect();

        // Thread counts via a single Toolhelp snapshot.
        let thread_counts = win::processes::thread_counts();

        let mut process_list: Vec<Value> = Vec::new();
        let mut exe_paths: Vec<String> = Vec::new();
        let mut modules_by_pid: HashMap<u32, Vec<Value>> = HashMap::new();
        let mut accessible_module_pids = 0usize;
        let mut inaccessible_module_pids = 0usize;

        let mut pids: Vec<sysinfo::Pid> = sys.processes().keys().copied().collect();
        pids.sort();

        for pid in pids {
            ctx.check_cancel()?;
            let Some(process) = sys.processes().get(&pid) else {
                continue;
            };

            let exe_path = process.exe().map(|p| p.to_string_lossy().into_owned());
            if let Some(path) = &exe_path {
                if !exe_paths.contains(path) {
                    exe_paths.push(path.clone());
                }
            }

            let uid_key = process.user_id().map(|u| format!("{:?}", u));
            let username = uid_key.as_ref().and_then(|k| user_names.get(k).cloned());

            let pid_u32 = pid.as_u32();
            let integrity = win::processes::integrity_level(pid_u32);
            let handles = win::processes::handle_count(pid_u32);
            let threads = thread_counts.get(&pid_u32).copied();

            // Module enumeration for a bounded number of processes; failures
            // are expected for protected processes and are recorded as such.
            if accessible_module_pids + inaccessible_module_pids < MODULE_ENUM_PROCESS_LIMIT {
                match win::processes::process_modules(pid_u32, 256) {
                    Some(modules) => {
                        accessible_module_pids += 1;
                        modules_by_pid.insert(
                            pid_u32,
                            modules
                                .into_iter()
                                .map(|m| json!({ "name": m.name, "path": m.path }))
                                .collect(),
                        );
                    }
                    None => {
                        inaccessible_module_pids += 1;
                    }
                }
            }

            let start_time = process.start_time();
            process_list.push(json!({
                "pid": pid_u32,
                "parent_pid": process.parent().map(|p| p.as_u32()),
                "name": process.name().to_string_lossy(),
                "executable_path": exe_path,
                "command_line": process
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" "),
                "user": username,
                "start_time_unix": start_time,
                "start_time_rfc3339": chrono::DateTime::from_timestamp(start_time as i64, 0)
                    .map(|d| d.to_rfc3339()),
                "run_time_seconds": process.run_time(),
                "cpu_usage_percent": process.cpu_usage(),
                "memory_bytes": process.memory(),
                "virtual_memory_bytes": process.virtual_memory(),
                "thread_count": threads,
                "handle_count": handles,
                "integrity_level": integrity,
                "status": format!("{:?}", process.status()),
            }));
        }

        ctx.add_json(
            "processes/process_list.json",
            "sysinfo + Toolhelp + process tokens",
            Some(format!(
                "Module enumeration attempted for {} processes ({} accessible, {} inaccessible)",
                accessible_module_pids + inaccessible_module_pids,
                accessible_module_pids,
                inaccessible_module_pids
            )),
            &process_list,
        )?;

        // --- Process tree ---------------------------------------------------
        let tree = build_process_tree(&process_list);
        ctx.add_json(
            "processes/process_tree.json",
            "derived from process parent/child relationships",
            None,
            &tree,
        )?;

        // --- Modules --------------------------------------------------------
        let modules_doc = json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "enumeration_limit": MODULE_ENUM_PROCESS_LIMIT,
            "accessible_processes": accessible_module_pids,
            "inaccessible_processes": inaccessible_module_pids,
            "note": "Modules are readable only for processes the operator token can open (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ). Protected and higher-privilege processes are recorded as inaccessible, never faked.",
            "processes": modules_by_pid,
        });
        ctx.add_json("processes/modules.json", "PSAPI EnumProcessModulesEx", None, &modules_doc)?;

        // --- Executable list (consumed by the HashCollector) -----------------
        exe_paths.sort();
        ctx.add_json(
            "processes/executable_paths.json",
            "unique executable paths of observed processes",
            None,
            &exe_paths,
        )?;

        Ok(())
    }
}

/// Build a nested process tree from the flat process list.
fn build_process_tree(process_list: &[Value]) -> Value {
    #[derive(Clone)]
    struct Node {
        pid: u32,
        name: String,
        parent: Option<u32>,
        children: Vec<u32>,
    }

    let mut nodes: HashMap<u32, Node> = HashMap::new();
    let mut roots: Vec<u32> = Vec::new();

    for p in process_list {
        let pid = p["pid"].as_u64().unwrap_or(0) as u32;
        let parent = p["parent_pid"].as_u64().map(|v| v as u32);
        nodes.insert(
            pid,
            Node {
                pid,
                name: p["name"].as_str().unwrap_or("").to_string(),
                parent,
                children: Vec::new(),
            },
        );
    }

    let pids: Vec<u32> = nodes.keys().copied().collect();
    for pid in pids {
        let parent = nodes[&pid].parent;
        match parent {
            Some(ppid) if ppid != pid && nodes.contains_key(&ppid) => {
                nodes.get_mut(&ppid).unwrap().children.push(pid);
            }
            _ => roots.push(pid),
        }
    }
    roots.sort();

    fn render(nodes: &HashMap<u32, Node>, pid: u32, depth: usize) -> Value {
        let node = &nodes[&pid];
        let mut children = node.children.clone();
        children.sort();
        let children_json: Vec<Value> = if depth < 12 {
            children
                .into_iter()
                .map(|c| render(nodes, c, depth + 1))
                .collect()
        } else {
            Vec::new()
        };
        json!({
            "pid": node.pid,
            "name": node.name,
            "children": children_json,
        })
    }

    let roots_json: Vec<Value> = roots.into_iter().map(|r| render(&nodes, r, 0)).collect();
    json!({
        "generated_at": chrono::Local::now().to_rfc3339(),
        "root_count": roots_json.len(),
        "tree": roots_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_tree_groups_children() {
        let list = vec![
            json!({"pid": 4, "parent_pid": null, "name": "System"}),
            json!({"pid": 100, "parent_pid": 4, "name": "services.exe"}),
            json!({"pid": 200, "parent_pid": 100, "name": "svchost.exe"}),
        ];
        let tree = build_process_tree(&list);
        let roots = tree["tree"].as_array().unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0]["name"], "System");
        assert_eq!(roots[0]["children"][0]["name"], "services.exe");
        assert_eq!(roots[0]["children"][0]["children"][0]["name"], "svchost.exe");
    }
}
