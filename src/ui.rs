use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/share/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/share/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
        *cm::HIDE_CM.lock().unwrap() = crate::ipc::get_config("hide_cm")
            .ok()
            .flatten()
            .unwrap_or_default()
            == "true";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    let hide_cm = *cm::HIDE_CM.lock().unwrap();
    if !args.is_empty() && args[0] == "--cm" && hide_cm {
        // run_app calls expand(show) + run_loop, we use collapse(hide) + run_loop instead to create a hidden window
        frame.collapse(true);
        frame.run_loop();
        return;
    }
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn install_options(&self) -> String {
        install_options()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn verify_login(&self, raw: String, id: String) -> bool {
        crate::verify_login(&raw, &id)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn install_options();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
        fn verify_login(String, String);
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAEr2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4KPHg6eG1wbWV0YSB4bWxuczp4PSdhZG9iZTpuczptZXRhLyc+CjxyZGY6UkRGIHhtbG5zOnJkZj0naHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyc+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpBdHRyaWI9J2h0dHA6Ly9ucy5hdHRyaWJ1dGlvbi5jb20vYWRzLzEuMC8nPgogIDxBdHRyaWI6QWRzPgogICA8cmRmOlNlcT4KICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0nUmVzb3VyY2UnPgogICAgIDxBdHRyaWI6Q3JlYXRlZD4yMDI1LTA4LTA4PC9BdHRyaWI6Q3JlYXRlZD4KICAgICA8QXR0cmliOkV4dElkPjU4ZTg1ZGJlLWI0Y2EtNDY5Zi1iZDljLTg5MzU3ZjdhNzY0MTwvQXR0cmliOkV4dElkPgogICAgIDxBdHRyaWI6RmJJZD41MjUyNjU5MTQxNzk1ODA8L0F0dHJpYjpGYklkPgogICAgIDxBdHRyaWI6VG91Y2hUeXBlPjI8L0F0dHJpYjpUb3VjaFR5cGU+CiAgICA8L3JkZjpsaT4KICAgPC9yZGY6U2VxPgogIDwvQXR0cmliOkFkcz4KIDwvcmRmOkRlc2NyaXB0aW9uPgoKIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PScnCiAgeG1sbnM6ZGM9J2h0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvJz4KICA8ZGM6dGl0bGU+CiAgIDxyZGY6QWx0PgogICAgPHJkZjpsaSB4bWw6bGFuZz0neC1kZWZhdWx0Jz5VbnRpdGxlZCBkZXNpZ24gLSAxPC9yZGY6bGk+CiAgIDwvcmRmOkFsdD4KICA8L2RjOnRpdGxlPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlv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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAEr2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4KPHg6eG1wbWV0YSB4bWxuczp4PSdhZG9iZTpuczptZXRhLyc+CjxyZGY6UkRGIHhtbG5zOnJkZj0naHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyc+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpBdHRyaWI9J2h0dHA6Ly9ucy5hdHRyaWJ1dGlvbi5jb20vYWRzLzEuMC8nPgogIDxBdHRyaWI6QWRzPgogICA8cmRmOlNlcT4KICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0nUmVzb3VyY2UnPgogICAgIDxBdHRyaWI6Q3JlYXRlZD4yMDI1LTA4LTA4PC9BdHRyaWI6Q3JlYXRlZD4KICAgICA8QXR0cmliOkV4dElkPjU4ZTg1ZGJlLWI0Y2EtNDY5Zi1iZDljLTg5MzU3ZjdhNzY0MTwvQXR0cmliOkV4dElkPgogICAgIDxBdHRyaWI6RmJJZD41MjUyNjU5MTQxNzk1ODA8L0F0dHJpYjpGYklkPgogICAgIDxBdHRyaWI6VG91Y2hUeXBlPjI8L0F0dHJpYjpUb3VjaFR5cGU+CiAgICA8L3JkZjpsaT4KICAgPC9yZGY6U2VxPgogIDwvQXR0cmliOkFkcz4KIDwvcmRmOkRlc2NyaXB0aW9uPgoKIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PScnCiAgeG1sbnM6ZGM9J2h0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvJz4KICA8ZGM6dGl0bGU+CiAgIDxyZGY6QWx0PgogICAgPHJkZjpsaSB4bWw6bGFuZz0neC1kZWZhdWx0Jz5VbnRpdGxlZCBkZXNpZ24gLSAxPC9yZGY6bGk+CiAgIDwvcmRmOkFsdD4KICA8L2RjOnRpdGxlPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlv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".into()
    }
}
