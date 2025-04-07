use tar_no_std::TarArchiveRef;
use user_core::rpc::Service;

pub struct InitramfsService<'a> {
    archive: &'a TarArchiveRef<'static>,
}

impl<'a> InitramfsService<'a> {
    pub fn new(archive: &'a TarArchiveRef<'static>) -> Self {
        Self { archive }
    }
}

impl Service for InitramfsService<'_> {
    #[allow(clippy::manual_async_fn)]
    fn handle_message(
        &self,
        msg: kernel_api::Message,
    ) -> impl Future<Output = ()> + Send + 'static {
        async { todo!() }
    }
}
