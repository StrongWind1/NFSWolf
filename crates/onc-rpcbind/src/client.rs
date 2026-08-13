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

    /// PMAPPROC_NULL (proc 0, RFC 1057 appendix A): no-op connectivity check.
    pub async fn null(&mut self) -> Result<(), RpcError> {
        let _ = self.call::<Void, Void>(PMAP_PROG::PMAPPROC_NULL, Void).await?;
        Ok(())
    }

    /// PMAPPROC_SET (proc 1, RFC 1057 appendix A): register a mapping.
    #[expect(clippy::similar_names, reason = "prog and prot are standard names used in portmapper")]
    pub async fn set(&mut self, prog: u32, vers: u32, prot: u32, port: u32) -> Result<bool, RpcError> {
        let args = mapping { prog, vers, prot, port };
        self.call::<mapping, bool>(PMAP_PROG::PMAPPROC_SET, args).await
    }

    /// PMAPPROC_UNSET (proc 2, RFC 1057 appendix A): unregister a mapping.
    #[expect(clippy::similar_names, reason = "prog and prot are standard names used in portmapper")]
    pub async fn unset(&mut self, prog: u32, vers: u32, prot: u32, port: u32) -> Result<bool, RpcError> {
        let args = mapping { prog, vers, prot, port };
        self.call::<mapping, bool>(PMAP_PROG::PMAPPROC_UNSET, args).await
    }

    /// PMAPPROC_GETPORT (proc 3, RFC 1057 appendix A): look up the port
    /// registered for `prog` with `vers` over transport `prot`.
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

    /// PMAPPROC_DUMP (proc 4, RFC 1057 appendix A): retrieve all registered mappings.
    pub async fn dump(&mut self) -> Result<Vec<mapping>, RpcError> {
        let mappings = self.call::<Void, pmaplist>(PMAP_PROG::PMAPPROC_DUMP, Void).await?;
        Ok(mappings.into_inner())
    }

    /// PMAPPROC_CALLIT (proc 5, RFC 1057 appendix A): indirect call
    /// through the portmapper.
    ///
    /// Forwards `args` to `(prog, vers, proc)` on the local host over
    /// UDP and returns the result plus the port the program is listening
    /// on.  Attack surface: UDP amplification (small request, large
    /// response with spoofed source) and relay to non-standard ports.
    #[expect(clippy::similar_names, reason = "prog and proc are the RFC field names")]
    pub async fn callit(&mut self, prog: u32, vers: u32, proc: u32, args: &[u8]) -> Result<crate::types::call_result<'static>, RpcError> {
        let call = crate::types::call_args { prog, vers, proc, args: onc_xdr::Opaque::borrowed(args) };
        self.call::<crate::types::call_args<'_>, crate::types::call_result<'static>>(PMAP_PROG::PMAPPROC_CALLIT, call).await
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
