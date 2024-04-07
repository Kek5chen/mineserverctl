use std::error::Error;
use std::io;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use chrono::{DateTime, FixedOffset};
use colored::{Color, Colorize};
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use sysinfo::{Pid, System};

#[derive(Debug)]
struct ServerData {
    exists: bool,
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
        _ => Err(format!("{} <status/start/stop/console> <server_folder>", args[0]).into()),
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

fn get_proc_cwd(pid: u32) -> Option<PathBuf> {
    let proc_path = Path::new("/proc").join(pid.to_string()).join("cwd");
    if !proc_path.exists() || proc_path.is_file() || !proc_path.is_symlink() {
        return None;
    }

    let link_path = match proc_path.read_link() {
        Ok(link_path) => link_path.canonicalize().unwrap(),
        Err(_) => return None,
    };
    if !link_path.exists() {
        return None;
    }

    Some(link_path)
}

fn get_server_data(folder: &str) -> io::Result<ServerData> {
    let folder_path = Path::new(folder);
    if !folder_path.exists() {
        return Ok(ServerData {
            exists: false,
            is_running: false,
            pid: 0,
            is_ready: false,
        });
    }

    let run_sh = folder_path.join("run.sh");
    let mut is_ready = run_sh.exists() && run_sh.is_file();
    is_ready = is_ready && match run_sh.metadata() {
        Ok(metadata) => metadata.permissions().mode() & 0o100 != 0,
        Err(_) => false
    };

    let screens = get_active_screens()?;
    for screen in screens {
        let cwd = get_proc_cwd(screen.pid);
        if cwd.is_none() { continue; }

        if Path::new(folder).canonicalize()? == cwd.unwrap().canonicalize()? {
            return Ok(ServerData {
                exists: true,
                is_running: true,
                pid: screen.pid,
                is_ready,
            });
        }
    }
    return Ok(ServerData {
        exists: true,
        is_running: false,
        pid: 0,
        is_ready,
    });
}

fn check_server(server_data: &ServerData, needs_ready: bool, needs_running: bool) -> bool {
    if !server_data.exists {
        eprintln!("{}",
                  "[X] The specified server does not exist."
                      .bold()
                      .color(Color::BrightRed));
    } else if needs_ready && !server_data.is_ready {
        eprintln!("{}",
                  "[X] The specified server is not ready yet. Please add a run.sh file which will start the server."
                      .bold()
                      .color(Color::BrightRed))
    } else if needs_running && !server_data.is_running {
        eprintln!("{}",
                  "[X] The specified server is not running. Please start it first."
                      .bold()
                      .color(Color::BrightRed))
    } else {
        return true;
    }
    return false;
}

fn start_server(folder: &str) -> Result<(), Box<dyn Error>> {
    let data = get_server_data(folder)?;
    if !check_server(&data, true, false) { return Ok(()); }

    if data.is_running {
        println!("{}",
                 "[O] The specified server is already running."
                     .bold()
                     .color(Color::BrightYellow));
        return Ok(());
    }

    let server_path = Path::new(folder).canonicalize().unwrap();
    match Command::new("screen")
        .arg("-dmS")
        .arg(server_path.file_name().unwrap())
        .arg(server_path.join("run.sh").to_str().unwrap())
        .current_dir(server_path)
        .spawn() {
        Ok(mut spawn_info) => {
            spawn_info.wait()?;
            println!("{} {}",
                     "[Y] Started server on "
                         .bold()
                         .color(Color::BrightGreen),
                     spawn_info.id());
        }
        Err(e) => println!("{} {}",
                           "[X] Server could not be started. Reason: "
                               .bold()
                               .color(Color::BrightRed),
                           e)
    }
    Ok(())
}

fn stop_server(folder: &str) -> Result<(), Box<dyn Error>> {
    let data = get_server_data(folder)?;
    if !check_server(&data, false, true) { return Ok(()); }

    if !data.is_running {
        println!("{}",
                 "[O] The specified server is already stopped."
                     .bold()
                     .color(Color::BrightYellow));
        return Ok(());
    }

    let server_path = Path::new(folder).canonicalize().unwrap();
    match Command::new("screen")
        .arg("-S")
        .arg(data.pid.to_string())
        .arg("-X")
        .arg("quit")
        .current_dir(server_path)
        .spawn() {
        Err(e) => println!("{} {}",
                           "[X] Server could not be started. Reason: "
                               .bold()
                               .color(Color::BrightRed),
                           e),
        _ => {}
    }
    let proc_pid = Pid::from_u32(data.pid);
    let mut system = System::new_all();

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::default_spinner()
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
        .template("{spinner:.blue} {msg}")?);

    spinner.set_message(format!("{} {}",
                                "[O] Stopping server on"
                                    .bold()
                                    .color(Color::BrightYellow),
                                data.pid));

    loop {
        system.refresh_process(proc_pid);
        if let None = system.process(proc_pid) {
            break;
        }
        spinner.inc(1);
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    spinner.finish_with_message(format!("{} {}",
                                        "[Y] Stopped server on "
                                            .bold()
                                            .color(Color::BrightGreen),
                                        data.pid));
    Ok(())
}

fn show_console(folder: &str) -> Result<(), Box<dyn Error>> {
    let data = get_server_data(folder)?;
    if !check_server(&data, false, true) { return Ok(()); }

    print!("{}", "[!] You will be able to exit the console using Ctrl+A + Ctrl+D. Ready? [y/n] "
        .bold()
        .color(Color::BrightYellow));
    io::stdout().flush()?;
    let mut char: [u8; 1] = [0];
    if io::stdin().read_exact(&mut char).is_ok() && char[0].to_ascii_lowercase() as char != 'y' {
        println!("{}", "[Y] Exiting..."
            .bold()
            .color(Color::BrightGreen));
        return Ok(());
    }
    let server_path = Path::new(folder).canonicalize().unwrap();
    match Command::new("screen")
        .arg("-xr")
        .arg(data.pid.to_string())
        .current_dir(server_path)
        .spawn() {
        Err(e) => println!("{} {}",
                           "[X] Could not join server console. Reason: "
                               .bold()
                               .color(Color::BrightRed),
                           e),
        Ok(mut spawn_info) => {
            spawn_info.wait()?;
            println!("{}",
                     "[Y] Left server console. Welcome Back!"
                         .bold()
                         .color(Color::BrightGreen));
        }
    }
    Ok(())
}

fn show_all_status() -> Result<(), Box<dyn Error>> {
    let screens = get_active_screens()?;

    let mut first_server = true;
    for screen in screens {
        let server_path = get_proc_cwd(screen.pid);
        if server_path.is_none() { continue; }
        let server_path = server_path.unwrap();

        if !server_path.join("run.sh").exists() {
            continue;
        } else if first_server {
            first_server = false;
            println!("{}", "[Y] Servers currently running:"
                .bold()
                .color(Color::BrightGreen));
        }

        let server_path = server_path.to_str().unwrap();
        let server_path = server_path.split('/').last().unwrap();

        let status = match screen.attached {
            true => "Attached".to_string(),
            false => "Detached".to_string()
        };

        println!("{} {} {} <{}>",
                 server_path.bold(),
                 "is running on".bold(),
                 screen.pid,
                 status.color(Color::BrightYellow));
    }
    if first_server {
        println!("{}", "[O] No servers are currently running."
            .bold()
            .color(Color::BrightYellow));
    }
    Ok(())
}

fn real_main() -> Result<(), Box<dyn Error>> {
    let (action, folder) = check_syntax()?;

    match action.as_str() {
        "start" => start_server(&folder),
        "stop" => stop_server(&folder),
        "console" => show_console(&folder),
        "status" => show_all_status(),
        s => Err(format!("`{}` {}", s, "not found as a valid action"
            .bold()
            .color(Color::BrightRed)).into())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    match real_main() {
        Err(e) => {
            eprintln!("{} {}", "Error:".bold().color(Color::BrightRed), e);
            Ok(())
        }
        Ok(()) => Ok(())
    }
}
