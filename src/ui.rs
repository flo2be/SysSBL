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
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAEumlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4KPHg6eG1wbWV0YSB4bWxuczp4PSdhZG9iZTpuczptZXRhLyc+CjxyZGY6UkRGIHhtbG5zOnJkZj0naHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyc+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpBdHRyaWI9J2h0dHA6Ly9ucy5hdHRyaWJ1dGlvbi5jb20vYWRzLzEuMC8nPgogIDxBdHRyaWI6QWRzPgogICA8cmRmOlNlcT4KICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0nUmVzb3VyY2UnPgogICAgIDxBdHRyaWI6Q3JlYXRlZD4yMDI1LTA4LTA5PC9BdHRyaWI6Q3JlYXRlZD4KICAgICA8QXR0cmliOkV4dElkPjVhMzNhODQwLTE3NWQtNDZmZS05YTc4LTk4NDlhMzU4MmM0NTwvQXR0cmliOkV4dElkPgogICAgIDxBdHRyaWI6RmJJZD41MjUyNjU5MTQxNzk1ODA8L0F0dHJpYjpGYklkPgogICAgIDxBdHRyaWI6VG91Y2hUeXBlPjI8L0F0dHJpYjpUb3VjaFR5cGU+CiAgICA8L3JkZjpsaT4KICAgPC9yZGY6U2VxPgogIDwvQXR0cmliOkFkcz4KIDwvcmRmOkRlc2NyaXB0aW9uPgoKIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PScnCiAgeG1sbnM6ZGM9J2h0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvJz4KICA8ZGM6dGl0bGU+CiAgIDxyZGY6QWx0PgogICAgPHJkZjpsaSB4bWw6bGFuZz0neC1kZWZhdWx0Jz5VbnRpdGxlZCBkZXNpZ24gLSAxPC9yZGY6bGk+CiAgIDwvcmRmOkFsdD4KICA8L2RjOnRpdGxlPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlv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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAEumlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4KPHg6eG1wbWV0YSB4bWxuczp4PSdhZG9iZTpuczptZXRhLyc+CjxyZGY6UkRGIHhtbG5zOnJkZj0naHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyc+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpBdHRyaWI9J2h0dHA6Ly9ucy5hdHRyaWJ1dGlvbi5jb20vYWRzLzEuMC8nPgogIDxBdHRyaWI6QWRzPgogICA8cmRmOlNlcT4KICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0nUmVzb3VyY2UnPgogICAgIDxBdHRyaWI6Q3JlYXRlZD4yMDI1LTA4LTA5PC9BdHRyaWI6Q3JlYXRlZD4KICAgICA8QXR0cmliOkV4dElkPjVhMzNhODQwLTE3NWQtNDZmZS05YTc4LTk4NDlhMzU4MmM0NTwvQXR0cmliOkV4dElkPgogICAgIDxBdHRyaWI6RmJJZD41MjUyNjU5MTQxNzk1ODA8L0F0dHJpYjpGYklkPgogICAgIDxBdHRyaWI6VG91Y2hUeXBlPjI8L0F0dHJpYjpUb3VjaFR5cGU+CiAgICA8L3JkZjpsaT4KICAgPC9yZGY6U2VxPgogIDwvQXR0cmliOkFkcz4KIDwvcmRmOkRlc2NyaXB0aW9uPgoKIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PScnCiAgeG1sbnM6ZGM9J2h0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvJz4KICA8ZGM6dGl0bGU+CiAgIDxyZGY6QWx0PgogICAgPHJkZjpsaSB4bWw6bGFuZz0neC1kZWZhdWx0Jz5VbnRpdGxlZCBkZXNpZ24gLSAxPC9yZGY6bGk+CiAgIDwvcmRmOkFsdD4KICA8L2RjOnRpdGxlPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpwZGY9J2h0dHA6Ly9ucy5hZG9iZS5jb20vcGRmLzEuMy8nPgogIDxwZGY6QXV0aG9yPkZpY2t5IFJpemtpPC9wZGY6QXV0aG9yPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczp4bXA9J2h0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8nPgogIDx4bXA6Q3JlYXRvclRvb2w+Q2FudmEgZG9jPURBR3ZkTlgtcnVFIHVzZXI9VUFHQzhiQ3BzOVkgYnJhbmQ9U2FuZ2dhIEJ1bWkmIzM5O3MgVGVhbSB0ZW1wbGF0ZT08L3htcDpDcmVhdG9yVG9vbD4KIDwvcmRmOkRlc2NyaXB0aW9uPgo8L3JkZjpSREY+CjwveDp4bXBtZXRhPgo8P3hwYWNrZXQgZW5kPSdyJz8+tuq3kAAAIABJREFUeJztfQmYXFWV/33v3VdVnQ77IuMug7giIDCIQBLS3VWvXlV3JyAEAVdkWLN0V71X3ekACsENBXRkHPGPDo4jAyoiy/gpoigI419FwBncHRXwj8qqmK07yf9s971bnQ7prqW7s9zvu191KlWv3rvn3LP+zrlK7Rq7xo463EKsdBApXcQZK68YOV4Asxi5mmYsrzKD2IH3HP58FT+v3CCe6cfYNZ5vZHqBWPlB5QPBmHBEWA9edaYUednFQ8rtGVBeISKCAgPQNEwh3yFG8QJkEpiFqnLzy1WuXHP8MIJrxRo+4wkD0XVUV22mH30nHv0XG2LibvX8MPbckz4K/67KjmfC+qVIZfpqyula7nmFuAO+szd85iD43uHw/8fA57rgdSF8503w3qHAAAfC3NPLV3Oq6zw3W64pYIDkeiQR8pGaUx5CxtAeMkWI71dmekV2juERMZjoHeXYcQu8e4EBlO69EBlgLhDyECDYyfD+EMxPwrwV5o9hPgrzLzDXwRyFuQk+txlecW6U99bCe/iZ38P8AcyvwL//CV4rMPvcIDrY6Y5yuRIzBjFEWFWZsOaShEAGhPfn9I3M9FLtOMMPKiiaiehZJL6I72wpVk4h2h/+RmJ/xC9Gd8DrH5mQTFggEszYnptkbpS5tX9b34kMk+BcD/N3MG+GeSkwQNEJq3OBAeieXFAd8B1SQZ4wJkqhXaOB4RRi1uewu1wheoZ19Yvh73Ng3gLzKSJ2yFOItnFLIsYWEe2/x02L2FthnE1bXo8ky7/BPMXNV/YgaQQqw8mTTYIqwsFn2TW2MdD4IqudjTkvW5bdDrsLdvpe8N5pMG8SMW4RJhr1i0wYQ0CQBmNAhCdEjH8Z3r8SXkdgDsL7Z8Pr20VyhLBTS0g8mO+Az50r4n4VTBT9X4X5AMxnWGXgtesYbdT8W5jhDzD/D1wzDwygjd2AhiR6Huq4ZTO9zLNv+Cg++8BSLw0gE7iZUg3dNBDxZOS9CRbx0zD/nxDW7MYNJN7Njg6jp+H/74L5UZhvg3kEuG+7qxOWO2zIWda+bfmPn2H6dwa+kysNKSdYDhIo3gfuBYzG6ExhjP+C+ZyRPuk9GWYghvgFXO8yeJa/J3shQKO05uEz5kq7JEIyUEeiqPeLNRelADAAEqIA793OYjnZcet9EfUiypEpPgdziVOs7tdZXllHaHTpnJ5Ble1FV47dQp70t5mu9bcHv6vN54ABvI7SsHKDQeUGFmPAPfat/AxKqpcIQ6BUetqSDhYz0H0+R1IhqB7il2JLIlQdNCB3yuECodwiTUeTnw2LwoGa4+Dvb1gG3CgtZjHZVY/DvBb+XgQ7ao+M6FsX1MZjn9+ohNBEWM+4bkFjbpor/j6LcTJCgUkjDxjAU13LE2mSKeN9V18gkueLpKJS4xOZdpOoh1FRDywRiuQxkOeAcQd83eEH+dSlKj88LmSBxS4uCizOjVoIDZ/DhdtoGVp3oo52i5V9dBgnOzwrFrfLriEtot/GyJ3fO0xunzAGRg3BVjGRQ7b64dnQSB2Aeb9lq2wQmwGfZQ3MK7ygcgA+uzphKUnAbHEHVwt+CV0kJHzV8Tlap1QQ5eD1fbAAf6NdU+SFkt2O/vp1sNhv6igOs5tFuyYWnxt3/sy7WBJVNAEpl/6NhF2wEN8P4VluSyQaPBOrCWJq8GCiaPPmzeDZiMdgGGlHZIZMWUQeiGOfH7QP5s91atitl4VBX/saWMhX+bwwak5x2OEFqjp6FotKsfopfKx63kWSIsPG7Anwf3dbEmGt5bXcB890OK5JRziEbq7ro8EYzDxzNz2IswOMq1eQ+BojeW4wMJeNNzHuirgYxqKPvgRi/LXoGXi8CKTPne3NWOpaSXYHhorBm3FJRfRRsOh0mL9KGKEojMCRyIjsoIBiHV5nMDTTT9HccMUHxh2R7R12xJhCV+qXsgCs53kBHgQG6CGPAAkf1thvXrRyph+j6eEUiPCev0hUQ3dlDvz7IlZxtAnWWdHGW5xCdV/cNMAM2ikae2M7UwmSesXpOrD7/TLp8OVm1wPR11ic/z4VULYNXUIXReBM338rRyZE17FKIl2TaqiK4Vt9Lbx+0wosrRUmeBTWbT5Kg1xpyMFIIhm+4XaiEvxibBjAc9BIyw/68FDXiyGEkbv18qAPwyIchZazKrAR5C+sqVzXkMrsgDl4N2Dvx6UMJjO8xzmEpWgECyOYjYGzil6TKsUSJ4mImWb18Is1YQAKpqCfjyHce1NRlzzcNcAYWVwQeE+7lFWDuZMkTjSsE0pHvzTikN4vRAfBmnxHPCGJHdBafXqfBavI+/EYvDJ71YFXxgge7X4tAZiXwN8PS0TM5uzzDegCd31mJwyLUvCKACgV0vWo8/c/8TJcj08Yrwi9IVmzr6ugknUClqqexDtm1aCIXJjufPD1Xw2vv5cH+Ju8Pgnvn+BzKNTVJnizvVn4LRwdfatM+Bpsg2UUZoa/LzBeAjCKsQvuUl0jGQc9qiD2kHnc4ixBJGXCqqBmEuK/Hl6fSHY+i7L/BnF/IBoyhKQxQI5ZEMiZ6ZFiD6tOFsS8uIInwfpsGreGd6lgeQajp6AyXbfI8LUZHX5YoegexsgpuBPEr4Ib/ZPk59eIHvu2E8adhOYB4nf07iL6+EEMgJshQHRRLBspWgDr9zfJiayVoNFdqnso67BLLfmOGWICyttzaBcjdKLzo0clwrVGfNtb1bwKplPZyi8hQmbn0/mTHqjbTxggKSn5jiOAwE+mbiKphe+ofNV32SZw2d2eZjVqYtZAfBBFFbjxFTkK5vCNmp1/2+5dFypHEj/IqeTy7RrbHHN6U5UKG+sN8PqMqIO1srG+mANm2XzjA6I+phmUyqnSqqOKZ6uO4oV4s7eK4bJGQrp3qmMudB1OqbL7sgP69u0a2VJFSarbx3UDq/9ozCJK+HidbLAPo+GNKXCVHyBY/LSMOb3AbT0EdvTE8r+CY/lJEONBJz8wB+HTGNXjnb9L7091ZIorVaY0THESTWnmKK9TVBRiCzZ7DJNLpUW77QFMwfpizGnOi79Ddv4GIf6fgVtf7gmujzB9u3Z+w6PzxPepPU96b2oTFKOzZL1HjYsN771GilU8Ngrb5B5S1YwYcxLnPwz+HmUrlQGT8P/zDEeSvz/dxsmOOBYsBRurgjECT6KsH2EpEJlM4v1q3jJQA1TG5rj5dmURT1hJP6C6QZwvrGJ8/yEx+tZxsKJ6jiF+lgondhG/VYOrjyJH9ZyvOnqHcI2/LsipNRIoupJiLCWwBxRiL1qsctHl2O3t5xCYUUqlrjJGnxgk15JBUqq5urCL8K0eXopWJsSRU4j3pkgr51hGyfAOolCirJ4uSf1iq4Zrx6GL0fxxeuhnqivqEBClM1M7H20NLcWdsBgOYgP9oAl9iIicIC0oRSibNijiMKpHFgdVxgWSHz/cuoeyhp/C17VXtI3ChA6/A/trD8k6OqpV+YLMoogqa9UCMOaOi0X0G0s0Rkv0OLYNjK8//Ra/JKEIm4ceCoeaOaw6ldiDDgcpuinpbBd3097hCJV8eWn1cV39gDaVxfCZ7OIRY7C5tA49A619TrivPfMXYwKJ7YGQXEEMDpnA26exngJRSGrhMIXpmxqYqNHlqrgZtMDDktoV3RNfhSgeXKjcSbhI05+g0FZZOIm9nmEXGGA3zUzpGhTxtsbcvhFiIFxcJ59U9Ki54ZBy8pUcMMDLBLa+CBYeK4sQBr4YZhfsvL9389WOTN+wyYuo3Omnk4+OUjHT3ULDLFyBYWNHIXGDKAu/9Yv6DRmfILTysoXBJn+sb7nU25M793J48L9atXH/q/KV3RDMQTfUPRPET3Uj5sw78/TgX8bkE2IRJGLpmV06fjjBEAW1EKTBNQVVjq0viLE66Uj43nthfk1zQajJzNXVEMpEQ/gxjH7CXAnXOVr3cKbPDUQvk1qqNu0ZsUGYSlz4vSLZAsXIuOL3+IuGVPbUi1VT9liGdlMVq3DdLKNSPq8tqx8W6FQWh7H2wOr3pjnMa5CzRHzg9P1O/wj+/SWrPOshMJb2MiBLkQj8XVQNCFiF7yGDIBP7bDu8Av59qeZ6wImqi7kmsBiPwevYhIWoKVN8H+ZSpxjtTVKBM6CeB9LFL8RNZUKTOspS1WWoffQfAiYxHtlpmuM1ntd3ceOLbHa/7IbE8MNSbL8MD9E75Oh8lcAg0zkM2hgjjS7s+s2bUW9Ht0it4KgFO/shiOdO7goSe56kULUpIukdcYgpUGUUo0vg+8+aki5hIoy44UTs4qZkhtbf6eQeA8kaJfh/LGFbDQywN0qYTLkmbWiay+T5fZWUPgEV1jyX3nf0E1UY8FQw2Lg3gIZUJgRDinXoTcblkIU9mqN8QICe6bX6SUwzAwDxq+rAf6SFuJkWm8rIpIo3jU7e4/UM5rBE2zPqwDBAmXzqt7GIT1TbBk3VxUxon4tPtyg3Hz+15O8tJhnTYqHL+4/APEOjtDTZUZREDdpN1P2kXzKH7Jqvluc2qurd8qxeQz+Qphqjo8zuF913IyYqkDkUWM0T6dZ2Da+YuGWOAvH9qrcS2vg2n4tIN/DCx0lk0uf38J6/q7pXZiSJBTsDrPPCcmSGL2mrfAt3sUXMbRJ9q8yQ/D5LBqx4suyGG8GtNvaJRkjcnEWNZ/OweYZXIBDJ/sAEfzbSB679sOpequE5CXo2paF7VlAps18i1OpnRfeb3X+kMbxUsLzhG5/q0EHS4Mk56ORhgU/F12mL+OkO5GYOQoQN2iBqQgSiDhKARbp6fFLCqussgjVM+C2lQowSZBMTn2wG6V4S/xYY4BBjQ2GBaWZxY56CN6+WGrpstFrR2eitDUkBdF0YiUpG0XO0G3gRbyacewjEL9SmLdbvScUMEj/XHzsZdrWu0In7kxJ/nEhOmED08XeAabNuHtyjQ45Rmd6VpN4krLpB1IBhoNYwAauRTfL7m/he6P6e9bBRlSTXECjTKPZfp8WxB1gAEio76+wdUnuceOGkXGEehRXkv4ruXyW73xhVXU3plQaHw3h6Lgzl+7pEiDU2EfHrdmDCBMkz3JLthx3XW3OwaEV10+65R7Nxu4FfW8sE6b2YxlRJ9O45sLUOs93VRrwDpxxzmJ6vc6VsjA1iv8znwhKw54JJRCldhGwhPr+35sOXf+anPXXudYvDZLRMa5XK/HMVAh4y3NgBH3BAcuIbn4/4E0iCTcmiFKOPmvoFhFsDc+2DYll26ag2enwSxt/UpAFK0shIA8MEjzOcrspWfYM2lfEIBJGNUmZMrv8pVOUZ7E6S34Yt0BGknAhcWR63c841vqVz7PQwQK4vUrv3DxNQUhpInGEZeRu3RfxxTGBex8QgWyVRu4y4UofptFhzTEAuLWUAoxI0Sxjapby28Z2dpYras7yM8i6NbDANLl+mNOTAJISW9ex/cIrxnpzPiZ3nvwgGREogKjjw81lpcYKc+wTMF4goef6LtGiQOCzFiZsDBCoYi30qxJ+ACTaK9NgM1zxbpEpOmKCv/jeiKf3G1NWBeCr8OzEbhZjNA2nQQJVUagxSn0T72kv8yahuNrZQJMa7I+f4rBfxAp83rp87DW6fF9RMwMaI/deKMcq7k0OfUyaMTsWvYSBMo3ZRUCaMcz5Dr86UxXte+6I1TFDHzGuAAQ9KPKwTpx4fwNiN01OFGSH9HrOe+wb0erIl7MO0FcM9kx+2xf9ibWHPtAn7ToPxpyVah7h3Lp+K9oXf/bU8yGgiRhv30w0TGB35DDzvQR7H7DMMdae2comI9pv7vedlyHHr/GVsFYMFIqqBTJ5ITRO8+6xEBvE3ngKvbn+PPbuJJbjHXS6N9X+1NjVqYfSEG1b3xcwglio3S+BtDePuKTBYXnDKRXgvd8libUhEchO6WdsRvtQQ+4nqqnR6hYraq3dAFjO+S74zKm5iyxnAMGRiqPLzHZNIgQaGpQZO1Fb0Fgh/ktnEujBBzAFdEQezR/kK5vx/RjfHi3QTduwAS5J8zXYPFGGZcuLufcz0DhJjaVNLCMHBmfHRwv88YP7FqAqoc5cbVPcxYtSSFu2RAka68XrfkA25AZbTQJzFdDRnz4ZL9ISxrvYJtYW1hRNc15QawTwcvoB6aSyx/iVs2QL6bnVQj5zeyIKdRef7bdTF42MEIl0uEE+nw2MG7Bef2ricrWHACaWAUU3xc14hfgmFdwtTN7gp4QSbVaK4X0kymlif2b3M0+BS64kYSyfFndF52vjZID6Ao15nWr20gtAT3nSQNHg0Rt+8Ziz+qey+cb/xKOyO/aXlvC/59itEBZgm1O0xCPm6xhY437jcat7UQ8QWLZfpNGayDtvxES3Hq3I0DjLFmpspcuzf6n/7G1WoZp2gxSDDcQOLSFDvo9EHYg9F1yPtFr3jRbCfBoC+povYravmqjzslEMHUPV93w/rbIZ2xAdMKptC7llqVUvAlCmvp07T+G+2GKDemA8stBC1HwkqKltYgeHE/9bp4txAiYre2GlX1i/bP6JUD/x2ecjlcqjoRtGJG9q12FvMcda4h2qPg2JZCdMeOl4StTpKyOFn8xvxY7Ap5hK2sYF1N1gDj935P8oz4r1/yOdyMq3sDCFGiDxu3XqApoYOkWnWuDL5wrzzWkh287vUQJmu7zPxz0rFbZJEaTsDyG+RKhDm+yuCLIT4GUk+XWgzSaujhOyZyLMyQ76xUW8AN7R72geU10fJrm9aG/qrHeVh1dk7Ul9RbOX+F4rrYETGYt1G/9+Of8PE3gJJ9zDZCe3f/clMpYDslvtU8SwHsQMHnflBRR09i9EP5f7G2hEllOuZtX9Lo2vPMY3Epf+Ydf1fgpeXcQrVepVuGQ3npAZgtB4+9Mp2GYD+YtPr5jD10lM/ir99j9xk2/Ts8y++5RWkAI6rsNOnxgARe0jHm5iAld1roWdSZwgONuN9WTQ9W6d9h9bogHoZUwqZP9kzRPF2qfi5zLK+HweLeI4n7VpbOahvcJnBEOLvV+ty8tNM/HEEMIEZsxM5BQ5MwK3tY8YhyNE0rVRRdQmiML6E6yuBAXpXN8AA1Egb17ZbJ/jEeCO4t8eY9DB9EMUFIn8znAD6nLUYP3C6B1xq89pqBggHxVJFZG70cvj7L/KbkoCZTtE/IRPYYv4h1b1Cq9efqRQDSDFx9IvkMymkrAWT1JAxfi+X/IunGjAE6XxEjqoerNOOY2jgnlynWlDEf+/iR9S+fRR2vZNuhIEEN2FcOocGYgvz/9QfP+DDlSQnf0O7/ewGdqLlFcScqeNdk5OqofdYBmHL1IBm6WMY4EpmgFq9yzZ5BlB4qpqTJ8Tznw0DwFxRp1ow4OCE4BKEg1jz9qAVA/gU3gBKB6eFLqDLu98Ua5THRftmnPhmJ/qh7ZZFT4PV/EKynIN3w3oNdug0QbWxZSqrmCCbcQNemqiABmD3WpDPMDG0/1OLAS5lBgDPLr/MtCkbBBeQHurRFM8ef9Dn2LFWXS2UAFhneDRw9CuWITb+R34iSmfH7k+lgMC3QhOjjz+RIXxCnNE2XI4DSC2RAtoAVphQZzXjgRGz9lyg1LGn4zXuTaVM9AkE1CLCio6s0UWDtq2iqHjWT484GWrGCt3aoJImDv2eymKURH/L4VetkgSWTbAeLOiDLXQynln4RyMFdJO/pVPjU3ZqfJQEdBrLCuIBlsURUOHD+Pft1sb+AvYPwFPZEPuBx7I5eDQbzD3hx/9i/GFtECotZABcvDknXkRVtIYrtYR7Z8ry3/aOJElgOqG8lz2COCtS4DL53GjT3kCxDub2G1DLWTesNIy/pCN1SpGTYc/l81bV0G3Zcqw6evmwy6SuXhcwbBjbEmCk5QyQFDTG3Um8YVbp/omYoC4w9XNQh5m5bzXl6PHrGO8fGcOxiWKSOgPwU6huYLpugwWeaADC9z3x7q62mPruf/jQdUotWC4MkFbYjlcBFxvMeiuI7yIkCVy/DBsgN8qijdqib1bOYqIGSDf7AqzIUNdTWtxvysKONaoGdKpqOPYQUkSWfflGTw4p1sV3VvtpfOcBlV/hOVwYK21KCzQ74Y0/CRoWP7jaN3mAQvONCHXql2JH0b/KzWyajaJ/y1kH474JE2RgHPs+q4Ehsd5HG2bkYl3m8weZMz+oHPVKqmBueLx5gAx4Afiutn7nfoXlcbLxOWvE4APwAuJHLQYwmSOv2XYjeywasXP9daDLdmDtWj11XaYuesINKnthAY08TyE50bRBoKqgnkzt5XnJus9vosMIF/d6kmG9PKFrGN2nwjMdL1zG9oX4mjizMH+jE46Pr5QyMGCA5mr/+djUBKz4r3b+faaJO0kJkOL2WD0GSHynWMHDHCSD2ogbOx6QEv9WFapz8eDpps8EANc+G9ZMDeTHLQnwnYPCD8H/v5sTQhgHcArAaXmqln3A4szPGEPEazIQRM2bemLldmEn7PgBE5fePsR/ulP9FD94EdkB5ZrrdtOROD+3CTn5a9oRxzpImucuOaOpNUcGypRqboahYddZz3FrBjyAbP8QYw1IDxx2mupcRAWE37Y+eHMOvjxHDnNu6maKBFJUThDhkXFPmsXaHsT/OCYQOyD+AurWDlib/UJSb3fI/49Nhfjj4OkPqWMv8NSCQYV9D5odSNyORcMqx30Fb7Oe4V9NjYfHRiA+SOTk2F+8yfIXvzvvF9eQMdEsGoiCTXSOHh2Z9ngju2Wmp+bIoHH5vrXvkkh1njiERab4fLfYDDKZa1lqxUT+FjE+Agy07hVNMwARFyV717kIabuPfpuN1SvRE8tghBHb+mCrcUw4+FIPYOMBnWBFFk/PnhBFOiUGwAOSB2EOYFerX22PDGDvcJSU+588ouYurgED0Mb5qp9g+iZ1LQt8Qte7PQdEyQYVxwH3zc03zwC06YC2QF8O8YdJLmDLAJ9OwQNDVoDmOTeo7seNB5sDhDA3DoKdsQJ/50F7MbeXKfEK4wregkWYHX3DTkc/idivTfaZOORdV572HOjrg+T8YNdrUa9fbmxJEgUBIMmhXd5EVV6Wi3a6YQAfAxtBdJTpBdTczQADvGaF6jxlKLEzNOfStx8bgANChgG+kAUG2BPsJtVdQQTuDybN1FsCUAcEgKozQa1lp5/rFBl8bFKHCEyMSGHpPexaHzbokfhoMU4MGuaMLbilgYFn3GClS5bVzLWyWKN64jZss3JKbf8GAY1+2Ke2eFeDiK3tAWv2ROLZbHP31xmT9x7wnkvUydfeqNxCReUKrWkz6/MRfgZtZVrM4+/+FVT6/qj2qZ2sGYQe4WggHvT4tJ/6u2lOutBEK7j+99I1uEQ5HrHy3tuNBBhnsL1HpyH0Q/Uk6hd0cbzPT52+XyXIY7eVx754PVTm70kU8ArrHh7y51c8v7tafzo5GXndy5U6/izHiDP5wk051HWlYafZg4l00sEiyksAyEQBZz0T6GIdCBT7ChzPDaRpGnTQ2NYYwAKcbrIifmf6YZzE66fcyet5BvUpLl4Ou3yIUV7c4wF/83ru71irr/NAHz2T4gI/bbmCj7j5SgeKp2ZdQcaoVbHxMkqZJ8xueL5dM2tmfSj4UZCUu6ke6shBhSzy/oSRTVP2pW20cRh9hiUrFoBWVKtPT9VYIMqIIGutY8Z4MLRNq/nnp1+gYEHScDA6R3Qzx+qL0RG6iXJl66YQXuYIk33ZLNpslwCpz56UbX0Wd274T6sRb4dxDVNBvJXIpoUs4s/9WBVXZDBUi3qYTl1r8bDqPEyNpZzogo2tKSG3JS0tQ/CNYsywvgvx2PfW4AIsb+MUW2zOcilgpWqpPX4o4Vp8jvnWAm+R2NJpxZGxEf4Gi//qtCtYtekYyxYDzyNOK6yHLWn+FEjffZL+C1sQB43Ankg5C6sSrEm+eDN3mRpymr1ZPj59EHMPmHr+rdk5MwkDn4QEEAJGvHsPGAGJGbuywJ+1cYF13wuTFjBJEgkW/hTZZHISWOv7LCKB931LTXX20e98y3qOr2XKQyrH5WJbftEtcm9gSR9eI+ILv/hnN4j39ibTZWobwykPp8fMGu4sxhtmuhZgqzOVTpKsqZ5HBCwP4Kmp+4EUeFpSrBvtWkGrCZRd6TPCvYFjTx35CqVL7TncydhaMF+qOUspLn01SiR5sHTLLwpHGxEtgM0k+1VfTNDMDYLe4xusYO+fPxkpMOuYIO3cYYy/J0Ff760WnG7E/4VJHt+0nUm/Z/S+gXhdnwlh9xVXOZgTcYPWniSSjGAl05Dv7yzblgO180axC7Zuy5lqEpcbDz9ltU3/d9Mi1m3ycMJcuTKuCwgbSLJgswYgIoEfQvqIHh9B6ehSrj56ocRL6nMaxg7gTWOaUoLRV8u5UmPZzrN+UTr5pcjhErboNp2q8fupuntbVV4+He9ec6Ri54tCfCQMuBLV/bE3sG9HkBocyGSdJ9aUBCq+LTdpziKYcQaQUm0bBnYvRtcyvUOeLpsmWvhZi3HriJ+0gv01bibP4PuKkzu+puF1TRiMYHfPpeLfUj/bApqkyN0kL7BeAhdnG7CC32RMwA3SBcG2JTrFCI6lOnSGiD8uYsdFoNHhflI/EWEr1nXpZxOGNcQ3Fv9zGvsbcrsZT1P3lfYdrOFg8+5UslYtL2sUDPzXTTqnQ8AN7CnbU91DSxpR9PPduy+uqT1PjtH/bepmkRszgnuTc3GTJJSxB/xpRgvbUUkhvmkpez7uWpCMvvRJvimVWJEdJdyc4gUoyZOXI220L9D7dg60LVT+TKWOORJ/00Z23ZHrrVHmclLILjktyxgSV5nO0yJKjmtFUAhHNoTdMH85ARd99jxqaXMKykZKFG06pIFNxLSVrKZjZEh0ZkQtDqS73PT8Nend2LSWTZJomP/opDz/NHRXlXMdNcYp6g34d2ppQTupC/m9K9BIcbmrZPVwCWYYnXZjVlqOYgfvZgd+KH6iAAAOC0lEQVR2qnC5PN0R0XWJTjtzjqVBlrYygU1EFt9MyEsJExnGpnuqOTfJ9gwsiZG0gj8X4yVgM3mIzVdhe89Tws2Dxl2uPORky4RO+k9r9//BCaK9zKGek76oh4cPBrGT5c7Vt1sVvGPgwr1eWo42LQWSI2DowIOqIxw8YBaaG0ZYTZlaygh1u96uykHxfR6L/dgV6/3vdFoNPDaO+EmUEGaNvaWq5wbTc5KaX1hFul3qO482u1+e61I6U5jstil6HlZMoNcYg1Ile50vF1XFEToCrZlhLGOPAlGJB1KC9x+3DJkxs0v9CUKuU5pWIaoQ3hwBh9f+o0bdXRI4/Iv7QE0txXUwKKb1ExB/TDyG9+G6ZMtIDHPSepv1PrrsPTXstuJiwaeWHIsEof7iYTuYwG4HM6WLx2rfJcNqj5Mo43WfXJiMNCDWG+TkK9dbONL0gwijkX/sU/UwHYWOx59cn3bgIGt8zK7Bm4qRKMbaZkt3J4QXXXkLzBdpsYGwJ0IWFi7Llr8pZrHDwnaU72NYYJvpJUPLMQzQ7iEnnJrEz7GaS9eMJLuCOrCVap46qgGIuQ6HbSnQL7p5vaQVb5Ajz1zUP34LOJ1wg8VBNSfgKiLp3o3irQj//rEYiMZiHzVSwZSW16mKVGWkProQXdcf5YbzQXy+HO0gblE/px/1KsLYqyiVzEllp1lMMOqn4JBPZsS984pyiHSbdz4Ot1AjCYDnEGa5RvEbVlXXs14YvZhVahPhezqOtfci1RGuwh+4WxaOsWwBpRppwVqFY8MhJ31SLSGdEYTXftPFaB+8A4j5IzZKbSgZPfSYNJQepYLTZFI0DnfERvvzmnEId8I8SR3xTiJarhftEE7ymPy8gyCNfNXyr+N3JPYJE//jGTLClgrxW99Qa6KBiTss59Ppie5L5L7WCd7gMjlQGzbwJY3/kKBeXAIR0uFD5vxA4rLvzVk0qDpOXYml5cpt4emhdCwsglAKdDqoh0fY4q7ad9FFeE/omayCeQfMpyUStznFF0bWTCx6nHig4v+FuRqe5ZCOUswgl3nn0UI6eayPrG0hzbBwFpkgI4cyGUkA8/24yC889QMSgWtDandr43g658hRPXhvEcK+BWrPgBW4j70k1dxc1JZ2dh599Vp6CAGLYj6dMogGhAM1WcvNHFY8wXADPLk7FkaMPVW4QBnVkC0PY2dTDLPOAyK/C40wmP+i+Ri4W+H1epj/DP+HOPgT4XsvP3TJ5UqeQ80pg+tJqgbr+7Zx/mGeFholg/FU3qjIa6Ed7xgbZjoGhpUz/REeKeNpjvlfLrt/rUhmckM1eCJ+b7Onh+Mo0/EtDhLYZSPpSQtjhj96sMd+JjUzcNu0EG64XIodIhTTHpayuUXTqIGZgppakQhHBqEOW8pPDMyITh/z2a+n1vhT+v2Az1PATtuG2NNNfHpWOXZWwtL/oE2BCdPjvnef/bBSb3g7nnegsq1gAI/ax/ARa7KQ/5hwHIvXe/Y77yKljl2hqJtFT+shTluMnlhxcys6hNklOySMNOIZOoBAaNCBYeRQxRPft2eIhaeCeA32O6ATwPkUcANwnTbi4xDvgkX/ggiLUk3Ilw+uDhChLAUmrYSa4Ykh1NsP0STlYUaahpYqAL3Knacivc+iIeoCOu0D/GGOeEmnbEQ4tQFvN1MDpRr2LfbTZN3HNaer14hhWzMQ/gx4Uzpshfi3hpziZapNDtTUTiYJ1KA9UNBFaf8KBpbX5hDozjQsCLqWDKoB7MiZjvEdWSD47oXlqlm8xlYHhRS51lyLLn6btiKEGEXzi5W/s49B1c02Odg1FB3WxaF3T4xhLERZp5O2b9EzIPleKgxCZy21bWR6h5XTQ4geowM/NU4MfU8tWOU4BSo9csUabd8N7eDDGK9o+KJ95eSre2vJSfiS7eMj/qpJgYnf7vwDunpgDzhu93Jzk3dLYGSN+KE35fovBJ18DgdHBEK9a0xtSDqeNpJTHFCfmEPnFXxHpO4aifh92CR71CGrweuZBpuHyphNKTO/YqbMnFK5ViJk12SKw+qlx38IRZgwwS5JMNnBtpSU5S+sqlw/McP1YnOtEe/r67udcbFSRyzFTelgUmjaBgZPxOAziJ4jtcC7/RRCdhWKo87w/ZLunZ4Y+fY+/MTgq7qqcCbsbkrGfVrqD0yd//+ooDLXDepOXJnmG8VikXLMJWWsp8xxs/aJG5cTDm7+0sSD8KcrXLodDjxIQ0K4rlo4iEfI4rp9gnMfCQ7xjyCBDxTpa7quz8wN5/pr6gVnrBIIGUmCd+oUxWNACf+S6wcDpputVEIWt7ASdkcZfsgGM0f5qip7EuU/rpPag3Wyof4MEuJ12vK02m70bXN0Y/sXSptygCIkEKU5Vcukj7/wwuUfoz5B2AQJmSCzyzCsGx28+7WkxbE876tSl7BWxP/jMF/jW/GAWaNSMW2MuXOf/FByXdKuFGG8TizWb6j8ig4+LSTS6vhl4NYM7tSxAlGd2D6P1oTD29HL4P37Jbu5RjwsREe9Wkukz58VO98amC5GJnBJf+Hhy6QO3moxgQkZP0h1AJy4ofj8rHuYaRrGcMMkWq40ZI7POQHmE7Jupvvoo7BJXp1GAqPpSztPZZiSJ4dgXRGJedjtC7WUUBluxsgVzD5+YAZbqMJyRBftFIzA6WgwjBdQt27NbXQpwrpUVKedY/kB/P+LfHvnT2PyacqD2s7iDZ6wgtqpizp4Jbz+VGyBtRYU659BMswlpI1IAyygzJZWzvRjtG1kSyMqw26dI8+MgBOM7t2oTXc2PrORYHfqhIpvrP0MV2/P9CNMfnT2DVFiiI6kDWJsEXuLDd8SRvg1ME1gQp4+fb5CWTxvBwocIb7SA8LLaWm06zXVRcZYxPE7wTvam2MwQ0fUpa5eZjbv/ImGDwzAoi2mThi5IpUur05iBRLRElfxOjegrttK9Szjh85XFOYU9Hae0tULBgxE3FPkBRGcC5/1cxbiea0AbP4XmOQ4lIp0cniQFHvO9GM0Nrggkv1/PHsXq4Glb81PdYL5T4JGT8IcUPmlZOgAAznM/bFyut4/048y5eGUhpXJjKr54rIV6Ai3ATb0iPCm1gLnDW6huodA3rQrh1Nt93kU0weHdFkp8ugQyvwgnr55BTNBNF78/QTm4kz/MEO9+gcM+tXBYElnfnZLBL97gJBKaAizBEPg6cWYGcX0+f9YncRMkclTmg/RkLWKvGxpOyf6+EFVqcesUP6SIXQZPTyCxmcDcT488EOWWrAZAVG/eal3Uxz3JsOJ3Ux0Jftm3ijygyFO3PBudbEQw6OaCQyQUXd0jI4+YD3jurSINL4RnuMlGEXNlChf4kh2b6Yfqz3DLQMhSwQuxWJQj5tIk5GD/Wue8VM3aJ1OGeH7uEOAAfY2AFAEZ/psHNE13DbW3U845p1LkHWBn6Ga8pyeAQHNUC+ll8B7F2o8gcUmfNE8U4xp3YXkEnIOn0T+Dk18M7DwFPvUz11SIZSLI21LpKvFlbAIz1g9hE1mkZMgDEDpcvJRTgInhELOhgg+oSCJa4ozmu1hkIwF5zHGMOT2ahi4QYJlqN4+OT4OjNcBdHuxfP4z8O9nLcKvt6TaD2Ge2NHLz4zNOcn9BabJlWdemk3rcIX7WfexT+xzMAmh54jxf8yqANpgFT7g/BX8fTUQo+gEUWcmuQ4fTIEnoGTKtDMZEUwIJinbMunWIIWLG8mi0z4+DjMTGaEaeyOp0qCS1vkUzMn0DmGj6N3h2j0wEZv/cEp0rhu0dvyPYJ6h3vEy+o1cP5+fTKXxYXV2B3faPdBadtlb4EINgpHFmFvYiy3m+KeWsbjRMIO1uL+Hea3GDqdBdIRXHJzTuWS14o6kQtgwSgxRDyUDVhqBe/ay096vNm++lsqsCMZGXbQNUyTMyYmrvqUOMMC+8H9dmppZRF+mCmaRUAaePY5Rvwmz/1Wn8QljqvcCyfbB8/ZRQ6eZXv7ZNfzuSGBksecWZWd0VXzQqX2wcF+B+be0SJSaNIym9X5J7+E/wPy2xkhjMapobHEXRkfDdV8KDDDXzUdZtbDiOa85S3X2rVT7vAXsh64hBzwT7QWDOSDw3jAP1hyXx1rAC+F+/g2ugeL7GSGsXXlsnfcbSWlWdCVc4/COoMbq4RhJ38Jud0rVHQqu3pbRwVkxkghYkqUlDAo6GDNlK2B+FxZ27QS7b3wRKE8saw+pPTu6XL/UmG0rRvfKDv0WXOu/xBt5BD73F02o2/T7purWIvr430DxfwXccwHE+lyfsREKGMCh5NjOLOKbGW6ZomYcCw8pMkY7qgPDzEGMUOhTgWBYIPFjQzQ/jCYgVLwFAfU4Qk74nS17DEiPhPgx+Pt2zUWqRzldy7TPeH26Xyw/o7r9XSK+dUOzBKAdtf8Zl5gaOa7mXfAeR9rNYbDlAzC/qLHuP6To4nqRAsZmGMcQUb20SKQG9RNYIyoF3barYL4LpNLh8Fsdc8q1pNDUzXPFjmnURMjpWR6w2m6HK4cea6oLxLQz2Av55YnhRpXDvTUw6pZrN6zOBaY5GIzDLmCAJTCx988IMUkILidVE8efhPlRmJdqjkdgVG4xXO8Y0NkvdguVjhe95zIqj/MTTyVWu/UOJYWmCGqRc3hmenl2roFFnm4ooWZ23ahINNdXc7AfL1fVRJYnQKlnduOK8irVxGY31038PhaSvvkCZABPGl2b8jjVik5pu0arR7ckUcidNB3ICKqGuxXbtGsK5BSxP2HNRR8fGAB7FWqdVhLzzg6rSfk34hn9NnX4nsnx/wHPo4iJhQvMzQAAAABJRU5ErkJggg==".into()
    }
}
