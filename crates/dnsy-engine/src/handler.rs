//! The [`Handler`] contract shared by every transport.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Instant;

use dnsy_core::{Principal, Transport};
use dnsy_proto::{Message, Rcode};

/// Facts about a request that the transport knows and the wire message does not.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub client: SocketAddr,
    pub transport: Transport,
    /// The authenticated principal (`DoH` token, `DoT` client certificate), if any.
    pub principal: Option<Principal>,
    pub received_at: Instant,
}

/// Answers one decoded query. Implementations never panic on hostile queries and always return
/// a response to the query they were given; transports apply size limits and framing.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, ctx: RequestContext, query: Message) -> impl Future<Output = Message> + Send;

    /// Like [`Handler::handle`], but `None` means the request must be dropped without a reply
    /// (ACL `drop`, UDP rate limiting). Transports call this; the default always answers.
    fn respond(
        &self,
        ctx: RequestContext,
        query: Message,
    ) -> impl Future<Output = Option<Message>> + Send {
        async move { Some(self.handle(ctx, query).await) }
    }
}

/// Stub pipeline: answers every query with REFUSED.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefusedHandler;

impl Handler for RefusedHandler {
    fn handle(&self, _ctx: RequestContext, query: Message) -> impl Future<Output = Message> + Send {
        let mut response = Message::response_to(&query);
        response.header.rcode = Rcode::Refused;
        std::future::ready(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnsy_proto::{Class, Name, Question, RecordType};

    #[tokio::test]
    async fn refused_handler_echoes_id_and_question() {
        let mut query = Message::response_to(&Message::decode(&[0; 12]).unwrap());
        query.header.qr = false;
        query.header.id = 0x1234;
        query.questions.push(Question {
            name: Name::from_ascii("example.com.").unwrap(),
            qtype: RecordType::A,
            qclass: Class::In,
        });
        let ctx = RequestContext {
            client: ([127, 0, 0, 1], 5353).into(),
            transport: Transport::Udp,
            principal: None,
            received_at: Instant::now(),
        };
        let response = RefusedHandler.handle(ctx, query.clone()).await;
        assert!(response.header.qr);
        assert_eq!(response.header.id, 0x1234);
        assert_eq!(response.header.rcode, Rcode::Refused);
        assert_eq!(response.questions, query.questions);
    }
}
