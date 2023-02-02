use crate::packet::{Packet, PacketBuffer};
use crate::record::RecordType;
use crate::result::{Error, Result, ResultCode};

use std::fmt::{self, Formatter};
use std::net::Ipv4Addr;
use std::net::UdpSocket;

pub struct Server {
    local_addr: String,
    local_port: u16,
}

impl Server {
    pub fn new(addr: String, port: u16) -> Self {
        Self {
            local_addr: addr,
            local_port: port,
        }
    }

    pub fn lookup(
        &self,
        qname: &str,
        qtype: RecordType,
        server: (Ipv4Addr, u16),
    ) -> Result<Packet> {
        // Forge a query packet
        let mut send_packet: Packet = Default::default();
        send_packet.header.recursion_desired = true;
        send_packet.add_question(qname, qtype)?;

        // Write that packet to a buffer to send
        let mut send_buffer = PacketBuffer::new();
        send_packet.write(&mut send_buffer)?;

        let socket = UdpSocket::bind((self.local_addr.to_owned(), self.local_port))
            .map_err(|_| Error::UDPBindFailed)?;
        socket
            .send_to(&send_buffer.bytes[0..send_buffer.pos()], server)
            .map_err(|e| {
                eprintln!("{e}");
                Error::UDPSendFailed
            })?;

        let mut recv_buffer = PacketBuffer::new();
        socket
            .recv_from(&mut recv_buffer.bytes)
            .map_err(|_| Error::UDPRecvFailed)?;

        let recv_packet = Packet::try_from(recv_buffer)?;

        Ok(recv_packet)
    }

    pub fn handle_query(&self, socket: &UdpSocket) -> Result<()> {
        // With a socket ready, we can go ahead and read a packet. This will
        // block until one is received.
        let mut req_buffer = PacketBuffer::new();

        // The `recv_from` function will write the data into the provided buffer,
        // and return the length of the data read as well as the source address.
        // We're not interested in the length, but we need to keep track of the
        // source in order to send our reply later on.
        let (_, src) = socket
            .recv_from(&mut req_buffer.bytes)
            .map_err(|_| Error::UDPRecvFailed)?;

        // Next, `DnsPacket::from_buffer` is used to parse the raw bytes into
        // a `DnsPacket`.
        let mut request = Packet::try_from(req_buffer)?;

        // Create and initialize the response packet
        let mut packet: Packet = Default::default();
        packet.header.id = request.header.id;
        packet.header.recursion_desired = true;
        packet.header.recursion_available = true;
        packet.header.is_response = true;

        // In the normal case, exactly one question is present
        if let Some(question) = request.questions.pop() {
            println!("Received query: {}", question);

            // Since all is set up and as expected, the query can be forwarded to the
            // target server. There's always the possibility that the query will
            // fail, in which case the `SERVFAIL` response code is set to indicate
            // as much to the client. If rather everything goes as planned, the
            // question and response records as copied into our response packet.
            if let Ok(result) = self.recursive_lookup(&question.name, question.question_type) {
                println!("Result: {}", result);

                packet.questions.push(question);
                packet.header.question_count += 1;
                packet.header.response_code = result.header.response_code;

                for rec in result.answers {
                    packet.answers.push(rec);
                    packet.header.answer_count += 1;
                }
                for rec in result.authorities {
                    packet.authorities.push(rec);
                    packet.header.authority_count += 1;
                }
                for rec in result.additionals {
                    packet.additionals.push(rec);
                    packet.header.additional_count += 1;
                }
            } else {
                packet.header.response_code = ResultCode::ServFail;
            }
        }
        // Being mindful of how unreliable input data from arbitrary senders can be, we
        // need make sure that a question is actually present. If not, we return `FORMERR`
        // to indicate that the sender made something wrong.
        else {
            packet.header.response_code = ResultCode::FormErr;
        }

        // The only thing remaining is to encode our response and send it off!
        let mut res_buffer = PacketBuffer::new();
        packet.write(&mut res_buffer)?;

        let len = res_buffer.pos();
        let data = res_buffer.get_range(0, len)?;

        socket
            .send_to(data, src)
            .map_err(|_| Error::UDPSendFailed)?;

        Ok(())
    }

    pub fn recursive_lookup(&self, qname: &str, qtype: RecordType) -> Result<Packet> {
        // For now we're always starting with *a.root-servers.net*.
        let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

        // Since it might take an arbitrary number of steps, we enter an unbounded loop.
        loop {
            println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

            // The next step is to send the query to the active server.
            let ns_copy = ns;

            let server = (ns_copy, 53);
            let response = self.lookup(qname, qtype, server)?;

            // If there are entries in the answer section, and no errors, we are done!
            if !response.answers.is_empty() && response.header.response_code == ResultCode::NoError
            {
                return Ok(response);
            }

            // We might also get a `NXDOMAIN` reply, which is the authoritative name servers
            // way of telling us that the name doesn't exist.
            if response.header.response_code == ResultCode::NXDomain {
                return Ok(response);
            }

            // Otherwise, we'll try to find a new nameserver based on NS and a corresponding A
            // record in the additional section. If this succeeds, we can switch name server
            // and retry the loop.
            if let Some(new_ns) = response.get_resolved_ns(qname) {
                ns = new_ns;

                continue;
            }

            // If not, we'll have to resolve the ip of a NS record. If no NS records exist,
            // we'll go with what the last server told us.
            let new_ns_name = match response.get_unresolved_ns(qname) {
                Some(x) => x,
                None => return Ok(response),
            };

            // Here we go down the rabbit hole by starting _another_ lookup sequence in the
            // midst of our current one. Hopefully, this will give us the IP of an appropriate
            // name server.
            let recursive_response = self.recursive_lookup(&new_ns_name, RecordType::A)?;

            // Finally, we pick a random ip from the result, and restart the loop. If no such
            // record is available, we again return the last result we got.
            if let Some(new_ns) = recursive_response.get_random_a() {
                ns = new_ns;
            } else {
                return Ok(response);
            }
        }
    }
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "({}:{})", self.local_addr, self.local_port)
    }
}
