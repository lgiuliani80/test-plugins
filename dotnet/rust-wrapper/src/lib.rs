use std::{
    ffi::{c_char, c_int, c_void},
    path::PathBuf,
    sync::OnceLock,
};

use libloading::{Library, Symbol};

// ── Platform character type ───────────────────────────────────────────────────
// hostfxr's char_t is wchar_t (u16) on Windows and char (u8) on POSIX.

#[cfg(windows)]
type CharT = u16;
#[cfg(not(windows))]
type CharT = c_char;

// Owned, null-terminated string in the host-native character width.
#[cfg(windows)]
struct NativeStr(Vec<u16>);
#[cfg(not(windows))]
struct NativeStr(std::ffi::CString);

impl NativeStr {
    fn new(s: &str) -> Result<Self, String> {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let mut v: Vec<u16> = std::ffi::OsStr::new(s).encode_wide().collect();
            v.push(0);
            Ok(NativeStr(v))
        }
        #[cfg(not(windows))]
        {
            std::ffi::CString::new(s)
                .map(NativeStr)
                .map_err(|e| format!("CString '{s}': {e}"))
        }
    }

    fn as_ptr(&self) -> *const CharT {
        self.0.as_ptr()
    }
}

// ── hostfxr C API types ───────────────────────────────────────────────────────
// String parameters follow char_t, which is CharT above.

type HostfxrHandle = *mut c_void;

type FnInitializeForRuntimeConfig = unsafe extern "C" fn(
    runtime_config_path: *const CharT,
    parameters: *const c_void,
    host_context_handle: *mut HostfxrHandle,
) -> i32;

type FnGetRuntimeDelegate = unsafe extern "C" fn(
    host_context_handle: HostfxrHandle,
    delegate_type: i32,
    delegate: *mut *mut c_void,
) -> i32;

type FnClose = unsafe extern "C" fn(HostfxrHandle) -> i32;

// hdt_load_assembly_and_get_function_pointer = 5
const HDT_LOAD_ASSEMBLY_AND_GET_FUNCTION_POINTER: i32 = 5;

type FnLoadAssemblyAndGetFuncPtr = unsafe extern "C" fn(
    assembly_path: *const CharT,
    type_name: *const CharT,
    method_name: *const CharT,
    delegate_type_name: *const CharT,
    reserved: *const c_void,
    delegate: *mut *mut c_void,
) -> i32;

// Sentinel that tells the hosting layer the method carries [UnmanagedCallersOnly]
const UNMANAGEDCALLERSONLY_METHOD: *const CharT = (-1_isize) as *const CharT;

// ── SHA-1 function-pointer types ──────────────────────────────────────────────

type InitFn    = unsafe extern "C" fn() -> i32;
type UpdateFn  = unsafe extern "C" fn(*const u8, u32);
type GetFn     = unsafe extern "C" fn(*mut u8) -> i32;
type GetNameFn = unsafe extern "C" fn(*mut u8, i32) -> i32;

struct Callbacks {
    init:     InitFn,
    update:   UpdateFn,
    get:      GetFn,
    get_name: GetNameFn,
    // Keep libhostfxr alive for the process lifetime so no mapping is torn down.
    _hostfxr: Library,
}

// SAFETY: all fn-pointer fields are bare C function pointers.
unsafe impl Send for Callbacks {}
unsafe impl Sync for Callbacks {}

static CALLBACKS: OnceLock<Result<Callbacks, String>> = OnceLock::new();

// ── hostfxr / dotnet-root discovery ──────────────────────────────────────────

fn dotnet_root() -> Option<PathBuf> {
    // 1. Explicit env override
    if let Ok(v) = std::env::var("DOTNET_ROOT") {
        let p = PathBuf::from(v);
        if p.join("host/fxr").exists() {
            return Some(p);
        }
    }
    // 2. Well-known install paths (platform-specific)
    #[cfg(windows)]
    {
        for var in &["ProgramFiles", "ProgramFiles(x86)"] {
            if let Ok(pf) = std::env::var(var) {
                let p = PathBuf::from(pf).join("dotnet");
                if p.join("host/fxr").exists() {
                    return Some(p);
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        for candidate in &["/usr/share/dotnet", "/usr/local/share/dotnet", "/opt/dotnet"] {
            let p = PathBuf::from(candidate);
            if p.join("host/fxr").exists() {
                return Some(p);
            }
        }
    }
    // 3. Resolve the `dotnet` binary on PATH
    #[cfg(windows)]
    let finder = ("where", "dotnet");
    #[cfg(not(windows))]
    let finder = ("which", "dotnet");
    if let Ok(out) = std::process::Command::new(finder.0).arg(finder.1).output() {
        if let Ok(s) = std::str::from_utf8(&out.stdout) {
            // `where` may return multiple lines; take the first
            let first = s.lines().next().unwrap_or("").trim();
            if let Ok(resolved) = std::fs::canonicalize(first) {
                if let Some(parent) = resolved.parent() {
                    if parent.join("host/fxr").exists() {
                        return Some(parent.to_owned());
                    }
                }
            }
        }
    }
    None
}

/// Walk `<dotnet_root>/host/fxr/` and return the path to the highest-versioned
/// hostfxr library found there.
fn find_hostfxr(dotnet_root: &std::path::Path) -> Option<PathBuf> {
    let fxr_dir = dotnet_root.join("host/fxr");
    let mut entries: Vec<_> = std::fs::read_dir(&fxr_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .collect();
    entries.sort_by_key(|e| e.file_name());
    #[cfg(windows)]
    let lib_name = "hostfxr.dll";
    #[cfg(not(windows))]
    let lib_name = "libhostfxr.so";
    let lib = entries.last()?.path().join(lib_name);
    lib.exists().then_some(lib)
}

// ── assembly directory (where sha1dotnet.dll lives) ───────────────────────────

fn assembly_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SHA1DOTNET_DIR") {
        return PathBuf::from(dir);
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(ToOwned::to_owned))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn ns(s: &str) -> Result<NativeStr, String> {
    NativeStr::new(s)
}

// ── one-time .NET runtime initialisation ─────────────────────────────────────

fn load_dotnet() -> Result<Callbacks, String> {
    let root = dotnet_root()
        .ok_or_else(|| "cannot find .NET root (set DOTNET_ROOT)".to_string())?;
    let hostfxr_path = find_hostfxr(&root)
        .ok_or_else(|| format!("libhostfxr.so not found under {}", root.display()))?;

    // SAFETY: opening a well-known system library
    let lib = unsafe { Library::new(&hostfxr_path) }
        .map_err(|e| format!("dlopen {}: {e}", hostfxr_path.display()))?;

    let dir = assembly_dir();
    let runtimeconfig = ns(
        dir.join("sha1dotnet.runtimeconfig.json")
            .to_str()
            .ok_or("non-UTF-8 path")?,
    )?;
    let assembly_path = ns(
        dir.join("sha1dotnet.dll")
            .to_str()
            .ok_or("non-UTF-8 path")?,
    )?;

    // ── load and call hostfxr_initialize_for_runtime_config ──────────────────
    let mut handle: HostfxrHandle = std::ptr::null_mut();
    {
        let initialize: Symbol<FnInitializeForRuntimeConfig> = unsafe {
            lib.get(b"hostfxr_initialize_for_runtime_config\0")
        }
        .map_err(|e| format!("hostfxr_initialize_for_runtime_config symbol: {e}"))?;

        let rc = unsafe { initialize(runtimeconfig.as_ptr(), std::ptr::null(), &mut handle) };
        if rc < 0 {
            return Err(format!("hostfxr_initialize_for_runtime_config: 0x{rc:08x}"));
        }
    }

    // ── get the load_assembly_and_get_function_pointer delegate ──────────────
    let mut delegate_ptr: *mut c_void = std::ptr::null_mut();
    {
        let get_delegate: Symbol<FnGetRuntimeDelegate> = unsafe {
            lib.get(b"hostfxr_get_runtime_delegate\0")
        }
        .map_err(|e| format!("hostfxr_get_runtime_delegate symbol: {e}"))?;

        let rc = unsafe {
            get_delegate(
                handle,
                HDT_LOAD_ASSEMBLY_AND_GET_FUNCTION_POINTER,
                &mut delegate_ptr,
            )
        };
        if rc != 0 {
            // best-effort close before returning
            if let Ok(close) = unsafe { lib.get::<FnClose>(b"hostfxr_close\0") } {
                unsafe { close(handle) };
            }
            return Err(format!("hostfxr_get_runtime_delegate: 0x{rc:08x}"));
        }
    }

    // Close the initialisation context; the CLR itself stays loaded
    {
        let close: Symbol<FnClose> = unsafe { lib.get(b"hostfxr_close\0") }
            .map_err(|e| format!("hostfxr_close symbol: {e}"))?;
        unsafe { close(handle) };
    }

    // SAFETY: delegate_ptr is a valid fn pointer returned by the CLR
    let load_fn: FnLoadAssemblyAndGetFuncPtr =
        unsafe { std::mem::transmute(delegate_ptr) };

    // ── helper: resolve one [UnmanagedCallersOnly] method ────────────────────
    let type_name = ns("NativeExports, sha1dotnet")?;

    macro_rules! get_method {
        ($method:literal, $ty:ty) => {{
            let method_name = ns($method)?;
            let mut fp: *mut c_void = std::ptr::null_mut();
            let rc = unsafe {
                load_fn(
                    assembly_path.as_ptr(),
                    type_name.as_ptr(),
                    method_name.as_ptr(),
                    UNMANAGEDCALLERSONLY_METHOD,
                    std::ptr::null(),
                    &mut fp,
                )
            };
            if rc != 0 {
                return Err(format!(
                    "load_assembly_and_get_function_pointer '{}': 0x{rc:08x}",
                    $method
                ));
            }
            // SAFETY: the CLR guarantees fp matches the declared signature
            unsafe { std::mem::transmute::<*mut c_void, $ty>(fp) }
        }};
    }

    Ok(Callbacks {
        init:     get_method!("Init",          InitFn),
        update:   get_method!("Update",        UpdateFn),
        get:      get_method!("Get",           GetFn),
        get_name: get_method!("GetPluginName", GetNameFn),
        _hostfxr: lib,
    })
}

fn callbacks() -> Result<&'static Callbacks, &'static str> {
    CALLBACKS
        .get_or_init(load_dotnet)
        .as_ref()
        .map_err(String::as_str)
}

// ── C plugin interface ────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn sha1_init() -> c_int {
    match callbacks() {
        Ok(cb) => (cb.init)() as c_int,
        Err(e) => {
            eprintln!("sha1dotnet-wrapper: {e}");
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sha1_update(data: *const u8, size: u32) {
    if let Ok(cb) = callbacks() {
        (cb.update)(data, size);
    }
}

#[no_mangle]
pub unsafe extern "C" fn sha1_get(buffer: *mut u8) -> c_int {
    match callbacks() {
        Ok(cb) => (cb.get)(buffer) as c_int,
        Err(e) => {
            eprintln!("sha1dotnet-wrapper: {e}");
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sha1_get_plugin_name(name: *mut c_char, max_length: c_int) -> c_int {
    match callbacks() {
        Ok(cb) => (cb.get_name)(name as *mut u8, max_length) as c_int,
        Err(e) => {
            eprintln!("sha1dotnet-wrapper: {e}");
            -1
        }
    }
}