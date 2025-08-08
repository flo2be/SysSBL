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
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAEumlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4KPHg6eG1wbWV0YSB4bWxuczp4PSdhZG9iZTpuczptZXRhLyc+CjxyZGY6UkRGIHhtbG5zOnJkZj0naHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyc+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpBdHRyaWI9J2h0dHA6Ly9ucy5hdHRyaWJ1dGlvbi5jb20vYWRzLzEuMC8nPgogIDxBdHRyaWI6QWRzPgogICA8cmRmOlNlcT4KICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0nUmVzb3VyY2UnPgogICAgIDxBdHRyaWI6Q3JlYXRlZD4yMDI1LTA4LTA4PC9BdHRyaWI6Q3JlYXRlZD4KICAgICA8QXR0cmliOkV4dElkPjY3NTlkNzRmLTViOGItNDJiMC1hNTNiLTMyN2FjODA0YmRiNjwvQXR0cmliOkV4dElkPgogICAgIDxBdHRyaWI6RmJJZD41MjUyNjU5MTQxNzk1ODA8L0F0dHJpYjpGYklkPgogICAgIDxBdHRyaWI6VG91Y2hUeXBlPjI8L0F0dHJpYjpUb3VjaFR5cGU+CiAgICA8L3JkZjpsaT4KICAgPC9yZGY6U2VxPgogIDwvQXR0cmliOkFkcz4KIDwvcmRmOkRlc2NyaXB0aW9uPgoKIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PScnCiAgeG1sbnM6ZGM9J2h0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvJz4KICA8ZGM6dGl0bGU+CiAgIDxyZGY6QWx0PgogICAgPHJkZjpsaSB4bWw6bGFuZz0neC1kZWZhdWx0Jz5VbnRpdGxlZCBkZXNpZ24gLSAxPC9yZGY6bGk+CiAgIDwvcmRmOkFsdD4KICA8L2RjOnRpdGxlPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlv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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAEumlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4KPHg6eG1wbWV0YSB4bWxuczp4PSdhZG9iZTpuczptZXRhLyc+CjxyZGY6UkRGIHhtbG5zOnJkZj0naHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyc+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpBdHRyaWI9J2h0dHA6Ly9ucy5hdHRyaWJ1dGlvbi5jb20vYWRzLzEuMC8nPgogIDxBdHRyaWI6QWRzPgogICA8cmRmOlNlcT4KICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0nUmVzb3VyY2UnPgogICAgIDxBdHRyaWI6Q3JlYXRlZD4yMDI1LTA4LTA4PC9BdHRyaWI6Q3JlYXRlZD4KICAgICA8QXR0cmliOkV4dElkPjY3NTlkNzRmLTViOGItNDJiMC1hNTNiLTMyN2FjODA0YmRiNjwvQXR0cmliOkV4dElkPgogICAgIDxBdHRyaWI6RmJJZD41MjUyNjU5MTQxNzk1ODA8L0F0dHJpYjpGYklkPgogICAgIDxBdHRyaWI6VG91Y2hUeXBlPjI8L0F0dHJpYjpUb3VjaFR5cGU+CiAgICA8L3JkZjpsaT4KICAgPC9yZGY6U2VxPgogIDwvQXR0cmliOkFkcz4KIDwvcmRmOkRlc2NyaXB0aW9uPgoKIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PScnCiAgeG1sbnM6ZGM9J2h0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvJz4KICA8ZGM6dGl0bGU+CiAgIDxyZGY6QWx0PgogICAgPHJkZjpsaSB4bWw6bGFuZz0neC1kZWZhdWx0Jz5VbnRpdGxlZCBkZXNpZ24gLSAxPC9yZGY6bGk+CiAgIDwvcmRmOkFsdD4KICA8L2RjOnRpdGxlPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlv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".into()
    }
}
