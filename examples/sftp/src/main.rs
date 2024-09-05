use std::{
    convert::Infallible, env, ffi::OsStr, fs::{self, File}, io::{self, BufWriter, Read, Seek, SeekFrom, Write}, net::TcpStream, ops::Deref, os::windows::fs::OpenOptionsExt, path::{Path, StripPrefixError}, str::FromStr, sync::mpsc
};

use clap::{arg, command, Parser};
use rkyv::{Archive, Deserialize, Serialize};
use snafu::Snafu;
use ssh2::{Session, Sftp};
use typed_path::{NativePath, PathBuf, UnixPath, UnixPathBuf, Utf8NativePath, Utf8UnixPathBuf, Utf8WindowsPathBuf, WindowsEncoding, WindowsPath, WindowsPathBuf};
use widestring::{u16str, U16String};
use wincs::{
    ext::{ConvertOptions, FileExt}, filter::{info, ticket, SyncFilter}, placeholder_file::{Metadata, PlaceholderFile}, request::Request, CloudErrorKind, PopulationType, Registration, SecurityId, SyncRootId, SyncRootIdBuilder, WinCSError, WindowsError
};

// max should be 65536, this is done both in term-scp and sshfs because it's the
// max packet size for a tcp connection
const DOWNLOAD_CHUNK_SIZE_BYTES: usize = 4096;
// doesn't have to be 4KiB aligned
const UPLOAD_CHUNK_SIZE_BYTES: usize = 4096;

const PROVIDER_NAME: &str = "wincs";
const DISPLAY_NAME: &str = "Sftp";

#[derive(Debug, Archive, Serialize, Deserialize)]
pub struct FileBlob {
    relative_path: String,
}

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    username: String,

    #[arg(short, long)]
    password: String,

    #[arg(long)]
    host: String,

    #[arg(short, long)]
    mount_path: LocalPath,

    #[arg(short, long)]
    remote_path: RemotePath,
}

fn main() -> Result<(), SftpError> {
    let args = Args::parse();

    let tcp = TcpStream::connect(&args.host).unwrap();
    let mut session = Session::new().unwrap();
    session.set_blocking(true);
    session.set_tcp_stream(tcp);
    session.handshake().unwrap();
    session
        .userauth_password(
            &args.username,
            &args.password,
        )
        .unwrap();

    let sftp = session.sftp().unwrap();

    let sync_root_id = SyncRootIdBuilder::new(U16String::from_str(PROVIDER_NAME))
        .user_security_id(SecurityId::current_user().unwrap())
        .build();

    let client_path = &args.mount_path;

    let should_unregister = match sync_root_id.is_registered() {
        Ok(false) => {
            register_filter(&sync_root_id, &client_path)?;
            true
        },
        Ok(true) => true,
        Err(e) => Err(e)?
    };

    match main_loop(sftp, args) {
        Ok(_) => {},
        Err(e) => {
            println!("main loop error: {:?}", e);
        },
    }

    if should_unregister {
        sync_root_id.unregister()?;
    }

    Ok(())
}

fn register_filter(sync_root_id: &SyncRootId, client_path: &LocalPath) -> Result<(), SftpError> {
    let u16_display_name = U16String::from_str(DISPLAY_NAME);
    Registration::from_sync_root_id(&sync_root_id)
        .display_name(&u16_display_name)
        .hydration_type(wincs::HydrationType::Full)
        .population_type(PopulationType::Full)
        .icon(
            U16String::from_str("%SystemRoot%\\system32\\charmap.exe"),
            0,
        )
        .version(u16str!("1.0.0"))
        .recycle_bin_uri(u16str!("http://cloudmirror.example.com/recyclebin"))
        .register(client_path)?;
    Ok(())
}

fn main_loop(sftp: Sftp, args: Args) -> Result<(), SftpError> {
    convert_to_placeholder(&args.mount_path)?;

    let connection = wincs::Session::new()
        .connect(&args.mount_path, Filter { sftp, args: args.clone() })?;

    wait_for_ctrlc();

    connection.disconnect()?;
    Ok(())
}

fn convert_to_placeholder(path: &LocalPath) -> Result<(), SftpError> {
    println!("convert_to_placeholder {:?}", path);
    for entry in path.read_dir().unwrap() {
        let entry = entry?;
        let is_dir = entry.path().is_dir();

        let mut open_options = File::options();
        open_options.read(true);
        if is_dir {
            // FILE_FLAG_BACKUP_SEMANTICS, needed to obtain handle to directory
            open_options.custom_flags(0x02000000);
        }

        let convert_options = if is_dir {
            ConvertOptions::default().has_children()
        } else {
            ConvertOptions::default()
        };

        let file = open_options.open(entry.path())?;
        file.to_placeholder(convert_options)?;

        if is_dir {
            convert_to_placeholder(&LocalPath(entry.path()))?;
        }
    }
    Ok(())
}

pub struct Filter {
    sftp: Sftp,
    args: Args,
}

impl Filter {
    pub fn create_file(&self, src: &Path, dest: &Path) -> Result<(), SftpError> {
        let mut client_file = File::open(src)?;
        // TODO: This will overwrite the file if it exists on the server
        let mut server_file = self.sftp.create(dest)?;

        let mut buffer = [0; UPLOAD_CHUNK_SIZE_BYTES];
        let mut bytes_written = 0;

        // TODO: I could do the little offset trick and moving the old bytes to the
        // beginning of the buffer, I just don't know if it's worth it
        loop {
            client_file.seek(SeekFrom::Start(bytes_written))?;
            match client_file.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => {
                    bytes_written += server_file.write(&buffer[0..bytes_read])? as u64;
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(SftpError::Io { source: err }),
            }
        }

        Ok(())
    }

    // TODO: src is full, dest is relative
    pub fn create_dir_all(&self, src: &Path, dest: &Path) -> Result<(), SftpError> {
        // TODO: what does the "o" mean in 0o775
        self.sftp.mkdir(dest, 0o775)?;

        for entry in fs::read_dir(src)? {
            let src = entry?.path();
            let dest = dest.join(src.file_name().unwrap());
            match src.is_dir() {
                true => self.create_dir_all(&src, &dest)?,
                false => self.create_file(&src, &dest)?,
            }
        }

        Ok(())
    }

    pub fn remove_dir_all(&self, dest: &Path) -> Result<(), ssh2::Error> {
        for entry in self.sftp.readdir(dest)? {
            match entry.0.is_dir() {
                true => self.remove_dir_all(&entry.0)?,
                false => self.sftp.unlink(&entry.0)?,
            }
        }

        self.sftp.rmdir(dest)
    }
}

// TODO: handle unwraps
// TODO: everything is just forwarded to external functions... This should be
// changed in the wrapper api
impl SyncFilter for Filter {
    type Error = SftpError;
    // TODO: handle unwraps
    fn fetch_data(&self, request: Request, ticket: ticket::FetchData, info: info::FetchData) -> Result<(), SftpError> {
        println!("fetch_data {:?}", request.file_blob());
        // TODO: handle unwrap
        let path = Path::new(unsafe { OsStr::from_encoded_bytes_unchecked(request.file_blob()) });

        let range = info.required_file_range();
        let end = range.end;
        let mut position = range.start;

        // TODO: allow callback to return Result in SyncFilter
        let res = || -> Result<(), _> {
            let mut server_file = self
                .sftp
                .open(path)
                .map_err(|_| CloudErrorKind::InvalidRequest)?;
            let mut client_file = BufWriter::with_capacity(4096, request.placeholder());

            server_file
                .seek(SeekFrom::Start(position))
                .map_err(|_| CloudErrorKind::InvalidRequest)?;
            client_file
                .seek(SeekFrom::Start(position))
                .map_err(|_| CloudErrorKind::InvalidRequest)?;

            let mut buffer = [0; DOWNLOAD_CHUNK_SIZE_BYTES];

            // TODO: move to a func and remove unwraps & allow to split up the entire read
            // into segments done on separate threads
            // transfer the data in chunks
            loop {
                client_file.get_ref().set_progress(end, position).unwrap();

                // TODO: read directly to the BufWriters buffer
                // TODO: ignore if the error was just interrupted
                let bytes_read = server_file
                    .read(&mut buffer[0..DOWNLOAD_CHUNK_SIZE_BYTES])
                    .map_err(|_| CloudErrorKind::InvalidRequest)?;
                let bytes_written = client_file
                    .write(&buffer[0..bytes_read])
                    .map_err(|_| CloudErrorKind::InvalidRequest)?;
                position += bytes_written as u64;

                if position >= end {
                    break;
                }
            }

            client_file
                .flush()
                .map_err(|_| CloudErrorKind::InvalidRequest)?;

            Ok(())
        }();

        if let Err(e) = res {
            ticket.fail(e)?;
        }
        Ok(())
    }

    fn deleted(&self, _request: Request, _info: info::Deleted) -> Result<(), SftpError> {
        println!("deleted");
        Ok(())
    }

    // TODO: I probably also have to delete the file from the disk
    fn delete(&self, request: Request, ticket: ticket::Delete, info: info::Delete) -> Result<(), SftpError>{
        println!("delete {:?}", request.path());
        let path = Path::new(unsafe { OsStr::from_encoded_bytes_unchecked(request.file_blob()) });
        let res = || -> Result<(), _> {
            match info.is_directory() {
                true => self
                    .remove_dir_all(path)
                    .map_err(|_| CloudErrorKind::InvalidRequest)?,
                false => self
                    .sftp
                    .unlink(path)
                    .map_err(|_| CloudErrorKind::InvalidRequest)?,
            }
            ticket.pass().unwrap();
            Ok(())
        }();

        if let Err(e) = res {
            ticket.fail(e).unwrap();
        }
        Ok(())
    }

    // TODO: Do I have to move the file and set the file progress? or does the OS
    // handle that? (I think I do)
    fn rename(&self, request: Request, ticket: ticket::Rename, info: info::Rename) -> Result<(), SftpError>{
        let res = || -> Result<(), _> {
            match info.target_in_scope() {
                true => {
                    // TODO: path should auto include the drive letter
                    let src = request.path();
                    // TODO: should be relative
                    let dest = info.target_path();

                    match info.source_in_scope() {
                        // TODO: use fs::copy or fs::rename, whatever it is to move the local files,
                        // then use ConvertToPlaceholder. I'm not sure if I have to do this recursively
                        // for each file or only the top-level folder TODO: which
                        // rename flags do I use? how do I know if I should be overwriting?
                        true => self
                            .sftp
                            .rename(&src, &dest, None)
                            .map_err(|_| CloudErrorKind::InvalidRequest)?,
                        false => match info.is_directory() {
                            true => self
                                .create_dir_all(&src, &dest)
                                .map_err(|_| CloudErrorKind::InvalidRequest)?,
                            false => self
                                .create_file(&src, &dest)
                                .map_err(|_| CloudErrorKind::InvalidRequest)?,
                        },
                    }
                }
                // TODO: do I need to delete it locally?
                false => self
                    .sftp
                    .unlink(Path::new(unsafe {
                        OsStr::from_encoded_bytes_unchecked(request.file_blob())
                    }))
                    .map_err(|_| CloudErrorKind::InvalidRequest)?,
            }
            ticket.pass().unwrap();
            Ok(())
        }();

        if let Err(e) = res {
            ticket.fail(e).unwrap();
        }
        Ok(())
    }

    fn fetch_placeholders(
        &self,
        request: Request,
        ticket: ticket::FetchPlaceholders,
        info: info::FetchPlaceholders,
    ) -> Result<(), SftpError>{
        println!(
            "fetch_placeholders {:?} {:?}",
            request.path(),
            info.pattern()
        );
        let local_path = LocalPath(PathBuf::<WindowsEncoding>::try_from(request.path())?);
        let local_root = &self.args.mount_path;
        let remote_root = &self.args.remote_path;
        let remote_path = local_path.to_remote(local_root, remote_root)?;
        println!(
            " ... {:?} -> {:?}",
            local_path,
            remote_path
        );

        let dirs = self.sftp.readdir(&remote_path)?;
        let mut placeholders = dirs
            .into_iter()
            .map(|(path, stat)| (RemotePath(path), stat))
            .filter(|(path, _)| match path.to_local(local_root, remote_root) {
                Ok(local_path) => !local_path.exists(),
                Err(e) => {
                    println!("Failed to map remote path: {:?}", e);
                    false
                }
            })
            .map(|(path, stat)| {
                println!("path: {:?}, stat {:?}", path, stat);
                println!("is file: {}, is dir: {}", stat.is_file(), stat.is_dir());

                PlaceholderFile::new(path.to_local(local_root, remote_root).unwrap())
                    .metadata(
                        if stat.is_dir() {
                            Metadata::directory()
                        } else {
                            Metadata::file()
                        }
                        .size(stat.size.unwrap_or_default())
                        // .creation_time() // either the access time or write time, whichever is less
                        .last_access_time(stat.atime.unwrap_or_default())
                        .last_write_time(stat.mtime.unwrap_or_default())
                        .change_time(stat.mtime.unwrap_or_default()),
                    )
                    .overwrite()
                    // .mark_sync() // need this?
                    .blob(path.0.into_os_string().into_encoded_bytes())
            })
            .collect::<Vec<_>>();

        ticket.pass_with_placeholder(&mut placeholders).unwrap();
        Ok(())
    }

    fn closed(&self, request: Request, info: info::Closed) -> Result<(), SftpError> {
        println!("closed {:?}, deleted {}", request.path(), info.deleted());
        Ok(())
    }

    fn cancel_fetch_data(&self, _request: Request, _info: info::CancelFetchData) -> Result<(), SftpError> {
        println!("cancel_fetch_data");
        Ok(())
    }

    fn validate_data(
        &self,
        _request: Request,
        ticket: ticket::ValidateData,
        _info: info::ValidateData,
    ) -> Result<(), SftpError>{
        println!("validate_data");
        #[allow(unused_must_use)]
        {
            ticket.fail(CloudErrorKind::NotSupported);
            Err(SftpError::NotImplemented { name: "validate_data" })
        }
    }

    fn cancel_fetch_placeholders(&self, _request: Request, _info: info::CancelFetchPlaceholders) -> Result<(), SftpError>{
        println!("cancel_fetch_placeholders");
        Ok(())
    }

    fn opened(&self, request: Request, _info: info::Opened) -> Result<(), SftpError> {
        println!("opened: {:?}", request.path());
        Ok(())
    }

    fn dehydrate(&self, _request: Request, ticket: ticket::Dehydrate, _info: info::Dehydrate) -> Result<(), SftpError>{
        println!("dehydrate");
        #[allow(unused_must_use)]
        {
            ticket.fail(CloudErrorKind::NotSupported);
            Err(SftpError::NotImplemented { name: "dehydrate" })
        }
    }

    fn dehydrated(&self, _request: Request, _info: info::Dehydrated) -> Result<(), SftpError>{
        println!("dehydrated");
        Ok(())
    }

    fn renamed(&self, _request: Request, _info: info::Renamed) -> Result<(), SftpError>{
        println!("renamed");
        Ok(())
    }

    // TODO: acknowledgement callbacks
}

#[derive(Debug, Clone)]
struct RemotePath(Utf8UnixPathBuf);

#[derive(Debug, Clone)]
struct LocalPath(Utf8WindowsPathBuf);

impl FromStr for RemotePath {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(RemotePath(Utf8UnixPathBuf::from_str(s)?))
    }
}

impl Deref for RemotePath {
    type Target = UnixPath;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<UnixPath> for RemotePath {
    fn as_ref(&self) -> &UnixPath {
        &self.0
    }
}

impl AsRef<Path> for RemotePath {
    fn as_ref(&self) -> &Path {

        &Utf8NativePath::from_bytes_path(&self.0)
    }
}

impl RemotePath {
    fn to_local(&self, sync_root: &LocalPath, remote_root: &RemotePath) -> Result<RemotePath, StripPrefixError> {
        let relative = self.strip_prefix(remote_root)?;
        Ok(RemotePath(sync_root.join(relative)))
    }
}

impl FromStr for LocalPath {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(LocalPath(WindowsPathBuf::from_str(s)?))
    }
}

impl Deref for LocalPath {
    type Target = WindowsPath;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<WindowsPath> for LocalPath {
    fn as_ref(&self) -> &WindowsPath {
        &self.0
    }
}

impl LocalPath {
    fn to_remote(&self, sync_root: &LocalPath, remote_root: &RemotePath) -> Result<RemotePath, StripPrefixError> {
        let relative = self.strip_prefix(sync_root)?;
        Ok(RemotePath(remote_root.join(relative)))
    }
}

#[derive(Snafu, Debug)]
pub enum SftpError {
    #[snafu(transparent)]
    WinCSError { source: WinCSError },

    #[snafu(transparent)]
    Windows { source: WindowsError },

    #[snafu(transparent)]
    Io { source: io::Error },

    #[snafu(transparent)]
    Sftp { source: ssh2::Error },

    #[snafu(transparent)]
    PathStripPrefixError { source: StripPrefixError },

    #[snafu(display("couldn't convert path: {path}"))]
    CannotConvertTypedPath { path: std::path::PathBuf },

    #[snafu(display("not implemented: {name}"))]
    NotImplemented { name: &'static str },
}

fn wait_for_ctrlc() {
    let (tx, rx) = mpsc::channel();

    ctrlc::set_handler(move || {
        tx.send(()).unwrap();
    })
    .expect("Error setting Ctrl-C handler");

    rx.recv().unwrap();
}

impl Into<CloudErrorKind> for SftpError {
    fn into(self) -> CloudErrorKind {
        match self {
            Self::WinCSError { source: WinCSError::CloudError(ce) } => ce,
            // Fall back to NotSupported for other types
            _ => CloudErrorKind::NotSupported,
        }
    }
}