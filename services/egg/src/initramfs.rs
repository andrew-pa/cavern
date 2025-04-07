use tar_no_std::TarArchiveRef;
use user_core::rpc::Service;

pub struct InitramfsService {
    archive: TarArchiveRef<'static>,
}

impl InitramfsService {
    pub fn new(archive: TarArchiveRef<'static>) -> Self {
        Self { archive }
    }
}

impl Service for InitramfsService {
    #[allow(clippy::manual_async_fn)]
    fn handle_message(
        &self,
        msg: kernel_api::Message,
    ) -> impl Future<Output = ()> + Send + 'static {
        async { todo!() }
    }
}
