use crate::error::PortmapError;
use crate::types::{PMAP_PROG, PROGRAM, VERSION, mapping, pmaplist};
use onc_rpc_client::RpcClient;
use onc_rpc_client::RpcError;
use onc_rpc_client::transport::io::{AsyncRead, AsyncWrite};
use onc_xdr::{Pack, Unpack, Void};

/// Client for the portmapper service
#[derive(Debug)]
pub struct PortmapperClient<IO> {
    rpc: RpcClient<IO>,
}

impl<IO> PortmapperClient<IO>
where
    IO: AsyncRead + AsyncWrite + Send,
{
    /// Create a new portmapper client.
    ///
    /// The portmapper accepts AUTH_NONE for the query procedures, so no
    /// credential is set up here.
    pub fn new(io: IO) -> Self {
        Self { rpc: RpcClient::new(io) }
    }

    /// A null procedure that does nothing. Can be used to check if the portmapper is responsive.
    pub async fn null(&mut self) -> Result<(), RpcError> {
        let _ = self.call::<Void, Void>(PMAP_PROG::PMAPPROC_NULL, Void).await?;
        Ok(())
    }

    /// Look up the port registered for `prog` with `vers` over transport `prot`
    #[expect(clippy::similar_names, reason = "prog and prot are standard names used in portmapper")]
    pub async fn getport(&mut self, prog: u32, vers: u32, prot: u32) -> Result<u16, PortmapError> {
        let args = mapping { prog, vers, prot, port: 0 };

        let port = self.call::<mapping, u32>(PMAP_PROG::PMAPPROC_GETPORT, args).await?;

        let port_u16: Result<u16, _> = port.try_into();
        match port_u16 {
            Ok(0) => Err(PortmapError::ProgramUnavailable),
            Ok(port) => Ok(port),
            Err(_) => Err(PortmapError::InvalidPortValue(port)),
        }
    }

    /// Retrieve a list of all registered programs
    pub async fn dump(&mut self) -> Result<Vec<mapping>, RpcError> {
        let mappings = self.call::<Void, pmaplist>(PMAP_PROG::PMAPPROC_DUMP, Void).await?;
        Ok(mappings.into_inner())
    }

    /// Issue one portmapper procedure call against program 100000, version 2.
    async fn call<C, R>(&mut self, proc: PMAP_PROG, args: C) -> Result<R, RpcError>
    where
        R: Unpack,
        C: Pack + Send + Sync,
    {
        self.rpc.call::<C, R>(PROGRAM, VERSION, proc as u32, &args).await
    }
}
