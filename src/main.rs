use std::error::Error;
use std::io;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use chrono::{DateTime, FixedOffset};
use regex::Regex;

struct ServerData {
    is_running: bool,
    pid: u32,
    is_ready: bool,
}

#[derive(Debug)]
struct ScreenSession {
    pid: u32,
    name: String,
    started_at: Option<DateTime<FixedOffset>>,
    attached: bool,
}

fn check_syntax() -> Result<(String, String), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.len() {
        3 => Ok((args[1].clone(), args[2].clone())),
        _ => Err(format!("{} <start/stop/console> <server_folder>", args[0]).into()),
    }
}

fn get_active_screens() -> io::Result<Vec<ScreenSession>> {
    let screens_available = Command::new("screen")
        .arg("-ls")
        .output()
        .map_err(|_| io::Error::new(ErrorKind::Unsupported, "Screen is not available on this host as this user"))?;

    if screens_available.status.code().unwrap() == 1 {
        return Ok(Vec::new());
    }

    if !screens_available.status.success() {
        return Err(io::Error::new(ErrorKind::Unsupported, "Couldn't run `screen -ls` to query active screens."));
    }

    let screens_available = String::from_utf8(screens_available.stdout)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "The output of `screen -ls` returned garbled output."))?;
    let screens_available: Vec<&str> = screens_available.lines().skip(1).collect();
    if screens_available.is_empty() || screens_available[0].trim().is_empty() {
        return Ok(Vec::new());
    }

    let re = Regex::new(
        r"\s*(?P<pid>\d+)\.(?P<name>\w+)\s*(?:\((?P<starttime>\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\))?\s+\((?P<attached>[^)]+)\)"
    ).unwrap();


    let screens = screens_available.iter().filter_map(|&line| {
        let caps = re.captures(line);
        if caps.is_none() { return None; }

        let caps = caps.unwrap();

        let pid = caps.name("pid");
        let name = caps.name("name");
        let start_time = caps.name("starttime");
        let attached = caps.name("attached");

        if pid.is_none() || name.is_none() || attached.is_none() {
            return None;
        }

        let pid: u32 = match pid.unwrap().as_str().parse() {
            Ok(pid) => pid,
            Err(_) => return None
        };

        let start_time = start_time.and_then(|start_time|
            match DateTime::parse_from_str(
                start_time.as_str(),
                "%d/%m/%y %H:%M:%S",
            ) {
                Ok(start_time) => Some(start_time),
                Err(_) => return None
            }
        );

        Some(ScreenSession {
            pid,
            name: String::from(name.unwrap().as_str()),
            started_at: start_time,
            attached: attached.unwrap().as_str() == "Attached",
        })
    }).collect();

    Ok(screens)
}

fn get_server_data(folder: &str) -> io::Result<ServerData> {
    let run_sh = Path::new(folder).join("run.sh");
    let mut is_ready = run_sh.exists() && run_sh.is_file();
    is_ready = is_ready && match run_sh.metadata() {
        Ok(metadata) => metadata.permissions().mode() & 0o100 != 0,
        Err(_) => false
    };

    let screens = get_active_screens();
    println!("{:?}", screens);
    Err(io::Error::new(ErrorKind::Other, "Nothing much else for now"))
}

fn start_server(folder: &str) -> Result<(), Box<dyn Error>> {
    let data = get_server_data(folder);
    Ok(())
}

fn stop_server(folder: &str) -> Result<(), Box<dyn Error>> {
    let data = get_server_data(folder);
    Ok(())
}

fn show_console(folder: &str) -> Result<(), Box<dyn Error>> {
    let data = get_server_data(folder);
    Ok(())
}

fn real_main() -> Result<(), Box<dyn Error>> {
    let (action, folder) = check_syntax()?;

    match action.as_str() {
        "start" => start_server(&folder),
        "stop" => stop_server(&folder),
        "console" => show_console(&folder),
        _ => Err(String::new().into())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    match real_main() {
        Err(e) => {
            eprintln!("Error: {}", e);
            Ok(())
        }
        Ok(()) => Ok(())
    }
}
